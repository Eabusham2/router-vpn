package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#62d5ff"/><stop offset="1" stop-color="#7b68ff"/></linearGradient></defs><rect width="64" height="64" rx="16" fill="#0d1220"/><path d="M32 8 52 16v14c0 13-8.4 22.1-20 27C20.4 52.1 12 43 12 30V16l20-8Z" fill="url(#g)"/><path d="M24 32.5 29.5 38 41 25" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>`

func extraRoutes(h *http.ServeMux, a *app) {
	initSessionTracker(a)
	h.HandleFunc("/favicon.svg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "image/svg+xml")
		w.Header().Set("cache-control", "public, max-age=86400")
		_, _ = io.WriteString(w, faviconSVG)
	})
	// The browser root is diagnostics plumbing only. The retired installable
	// browser client intentionally has no web manifest or service-worker route.
	h.HandleFunc("/api/logical-modes", a.listLogicalModes)
	h.HandleFunc("/api/connect-logical", a.connectLogicalTracked)
	h.HandleFunc("/api/session", a.sessionStatus)
	h.HandleFunc("/api/session/events", a.sessionEvents)
	h.HandleFunc("/api/profile/latency", a.profileLatency)
	h.HandleFunc("/api/profile/lowest-saved-latency", a.selectSavedLowestLatency)
	h.HandleFunc("/api/public-ip", a.publicIP)
	h.HandleFunc("/api/dns/retest", a.retestDNS)
	registerMTURetestRoute(h, a)
	h.HandleFunc("/api/emergency-stop", a.emergencyStopTracked)
	// Linux keeps its native WG/AWG split-entry chain. Windows and macOS route
	// to their real native desktop multihop launchers instead of accidentally
	// exposing the Linux-only handler and returning a false unsupported result.
	registerDesktopMultihopRoutes(h, a)
	registerNativeUpdateRoutes(h, a)
}

type latencyRequest struct {
	ID      string `json:"id"`
	Samples int    `json:"samples"`
}

type latencyResponse struct {
	Saved       bool      `json:"saved"`
	Complete    bool      `json:"complete"`
	ID          string    `json:"id"`
	Port        int       `json:"port"`
	Samples     int       `json:"samples"`
	Failed      int       `json:"failed"`
	MinMs       float64   `json:"min_ms"`
	MedianMs    float64   `json:"median_ms"`
	TrimmedMs   float64   `json:"trimmed_mean_ms"`
	AverageMs   float64   `json:"average_ms"`
	P90Ms       float64   `json:"p90_ms"`
	MaxMs       float64   `json:"max_ms"`
	MeasuredAt  time.Time `json:"measured_at"`
	Description string    `json:"description"`
}

func (a *app) profileLatency(w http.ResponseWriter, r *http.Request) {
	a.profileLatencyWithNetwork(w, r, physicalNetworkIdentityContext)
}

func (a *app) profileLatencyWithNetwork(w http.ResponseWriter, r *http.Request, networkIdentity func(context.Context) (string, error)) {
	a.profileLatencyWithClock(w, r, networkIdentity, startClientMeasurementInterval)
}

func (a *app) profileLatencyWithClock(w http.ResponseWriter, r *http.Request, networkIdentity func(context.Context) (string, error), startClock clientMeasurementClock) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q latencyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	q.Samples = max(50, q.Samples)
	if q.Samples > 200 {
		q.Samples = 200
	}

	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if ctx.Err() != nil {
		http.Error(w, "durable node latency request was cancelled", http.StatusRequestTimeout)
		return
	}
	rejectObservation := func(err error) {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			http.Error(w, "durable node latency request was cancelled", http.StatusRequestTimeout)
		} else {
			http.Error(w, err.Error(), http.StatusConflict)
		}
	}
	networkAtStart, networkErr := networkIdentity(ctx)
	if ctx.Err() != nil {
		rejectObservation(ctx.Err())
		return
	}
	if networkErr != nil || networkAtStart == "" {
		http.Error(w, "physical network metadata unavailable", http.StatusConflict)
		return
	}
	networkCurrent := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		observed, err := networkIdentity(ctx)
		if err != nil || observed != networkAtStart {
			return errors.Join(err, errors.New("physical network metadata changed during direct benchmark"))
		}
		return ctx.Err()
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		rejectObservation(err)
		return
	}
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "disconnect before direct node benchmark", http.StatusConflict)
		return
	}
	p, ok := a.profileByIDLocked(q.ID)
	p = cloneRouterProfile(p)
	pathAtStart := activeTelemetryPathToken(a.state)
	selectionAtStart := a.profiles.SelectedID
	a.mu.Unlock()
	tracker := sessionTrackerFor(a)
	if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
		rejectObservation(err)
		return
	}
	sessionAtStart := ""
	if tracker.session != nil {
		sessionAtStart = tracker.session.ID
	}
	registered, retained := sessionTrackers.Load(a)
	tracker.mu.Unlock()
	if !retained || registered != tracker || tracker.a != a {
		rejectObservation(errors.New("VPN session tracker changed during direct benchmark"))
		return
	}
	if !ok {
		http.Error(w, "unknown router profile", http.StatusNotFound)
		return
	}
	if p.External != nil || (strings.TrimSpace(p.NodeKind) != "" && !strings.EqualFold(p.NodeKind, "router-vpn")) || p.MultihopEnabled {
		http.Error(w, "use the routed comparison for external or multihop nodes", http.StatusBadRequest)
		return
	}
	if p.Endpoint == "" {
		http.Error(w, "router profile has no endpoint", http.StatusBadRequest)
		return
	}
	profileAtStart := fastestProfileSnapshotToken([]common.RouterProfile{p})

	port, err := pickTCPProbePortContext(r.Context(), p.Endpoint)
	if err != nil {
		if r.Context().Err() != nil {
			http.Error(w, "durable node latency request was cancelled", http.StatusRequestTimeout)
		} else {
			http.Error(w, "node is not reachable on a known TCP listener: "+err.Error(), http.StatusBadGateway)
		}
		return
	}

	values := make([]float64, 0, q.Samples)
	failed := 0
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	for i := 0; i < q.Samples; i++ {
		if err := networkCurrent(); err != nil {
			rejectObservation(err)
			return
		}
		interval, clockErr := startClock()
		if clockErr != nil {
			http.Error(w, "durable node latency clock failed: "+clockErr.Error(), http.StatusBadGateway)
			return
		}
		c, dialErr := dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(p.Endpoint, fmt.Sprintf("%d", port)))
		if dialErr != nil {
			if r.Context().Err() != nil {
				http.Error(w, "durable node latency request was cancelled", http.StatusRequestTimeout)
				return
			}
			failed++
			continue
		}
		_ = c.Close()
		elapsed, clockErr := clientMeasurementMilliseconds(r.Context(), interval)
		if clockErr != nil {
			if r.Context().Err() != nil {
				http.Error(w, "durable node latency request was cancelled", http.StatusRequestTimeout)
			} else {
				http.Error(w, "durable node latency clock failed: "+clockErr.Error(), http.StatusBadGateway)
			}
			return
		}
		values = append(values, elapsed)
		if i%10 == 9 {
			select {
			case <-r.Context().Done():
				http.Error(w, "durable node latency request was cancelled", http.StatusRequestTimeout)
				return
			case <-time.After(15 * time.Millisecond):
			}
		}
	}
	if r.Context().Err() != nil {
		http.Error(w, "durable node latency request was cancelled", http.StatusRequestTimeout)
		return
	}
	if len(values) < 5 {
		http.Error(w, "too few successful latency samples", http.StatusBadGateway)
		return
	}
	sort.Float64s(values)
	minV := values[0]
	maxV := values[len(values)-1]
	avgV := averageMeasuredMilliseconds(values)
	medianV := percentile(values, 0.50)
	p90V := percentile(values, 0.90)
	trim := len(values) / 10
	trimmed := values
	if len(values)-2*trim >= 3 && trim > 0 {
		trimmed = values[trim : len(values)-trim]
	}
	trimmedV := averageMeasuredMilliseconds(trimmed)
	now := time.Now().UTC()
	resp := latencyResponse{
		ID:          p.ID,
		Port:        port,
		Samples:     len(values),
		Failed:      failed,
		MinMs:       roundMeasuredMilliseconds(minV),
		MedianMs:    roundMeasuredMilliseconds(medianV),
		TrimmedMs:   roundMeasuredMilliseconds(trimmedV),
		AverageMs:   roundMeasuredMilliseconds(avgV),
		P90Ms:       roundMeasuredMilliseconds(p90V),
		MaxMs:       roundMeasuredMilliseconds(maxV),
		MeasuredAt:  now,
		Description: "Disconnected direct TCP handshake latency; network metadata captured; median and 10% trimmed mean resist outliers",
		Complete:    failed == 0 && len(values) == q.Samples,
	}

	if err := networkCurrent(); err != nil {
		rejectObservation(err)
		return
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		if r.Context().Err() != nil {
			http.Error(w, "durable node latency request was cancelled before persistence", http.StatusRequestTimeout)
		} else {
			http.Error(w, guardErr.Error(), http.StatusConflict)
		}
		return
	}
	defer release()
	if err := networkCurrent(); err != nil {
		rejectObservation(err)
		return
	}
	if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
		rejectObservation(err)
		return
	}
	defer tracker.mu.Unlock()
	currentSessionID := ""
	if tracker.session != nil {
		currentSessionID = tracker.session.ID
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		rejectObservation(err)
		return
	}
	registered, retained = sessionTrackers.Load(a)
	if !retained || registered != tracker || tracker.a != a || currentSessionID != sessionAtStart || a.profiles.SelectedID != selectionAtStart || activeTelemetryPathToken(a.state) != pathAtStart || profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "VPN or selection changed during direct benchmark", http.StatusConflict)
		return
	}
	// Cancellation while waiting for this save lock must not publish a result.
	if r.Context().Err() != nil {
		a.mu.Unlock()
		http.Error(w, "durable node latency request was cancelled before persistence", http.StatusRequestTimeout)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	current, currentOK := a.profileByIDLocked(p.ID)
	if !currentOK || fastestProfileSnapshotToken([]common.RouterProfile{current}) != profileAtStart {
		a.mu.Unlock()
		http.Error(w, "router profile identity changed while durable latency measurement was running", http.StatusConflict)
		return
	}
	if !resp.Complete {
		// Real partial statistics are useful diagnostics, but cannot replace the
		// last complete durable benchmark or acquire eligibility by losing Failed.
		a.mu.Unlock()
		resp.Description += "; incomplete result, prior saved statistics preserved"
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == p.ID {
			x := &a.profiles.Profiles[i]
			x.LatencySamples = resp.Samples
			x.LatencyMinMs = resp.MinMs
			x.LatencyMedianMs = resp.MedianMs
			x.LatencyTrimmedMeanMs = resp.TrimmedMs
			x.LatencyAverageMs = resp.AverageMs
			x.LatencyP90Ms = resp.P90Ms
			x.LatencyMaxMs = resp.MaxMs
			x.LatencyLastTest = now.Format(time.RFC3339)
			x.LatencyReceipt = &common.NodeLatencyReceipt{Schema: 1, Measurement: savedNodeLatencyMeasurement, Attempts: q.Samples, Failed: failed, SourceToken: liveMeasurementProfileToken(p), NetworkMetadata: networkAtStart}
			break
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	}
	a.mu.Unlock()
	if persistErr != nil {
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}
	resp.Saved = true
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func pickTCPProbePort(endpoint string) (int, error) {
	return pickTCPProbePortContext(context.Background(), endpoint)
}

func pickTCPProbePortContext(ctx context.Context, endpoint string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ports := []int{443, 8388, 10443, 11443, 12443, 13443, 14443, 15443}
	var last error
	dialer := &net.Dialer{Timeout: 1200 * time.Millisecond}
	for _, port := range ports {
		c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(endpoint, fmt.Sprintf("%d", port)))
		if err == nil {
			_ = c.Close()
			return port, nil
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		last = err
	}
	if last == nil {
		last = errors.New("no probe ports")
	}
	return 0, last
}

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var total float64
	for _, v := range values {
		total += v
	}
	return total / float64(len(values))
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := p * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

func captureAsyncMeasurementSession(a *app) (connectionSession, error) {
	s := sessionTrackerFor(a).snapshot(0)
	if strings.TrimSpace(s.ID) == "" || !s.Connected || strings.TrimSpace(s.Phase) != "connected" || s.PathProof != "passed" {
		return connectionSession{}, errors.New("current Router VPN session has not proved a stable connected path")
	}
	return s, nil
}

func captureAsyncMeasurementSessionContext(ctx context.Context, a *app) (connectionSession, error) {
	_, session, err := measurementSessionContext(ctx, a, nil)
	if err != nil {
		return connectionSession{}, err
	}
	if strings.TrimSpace(session.ID) == "" || !session.Connected || strings.TrimSpace(session.Phase) != "connected" || session.PathProof != "passed" {
		return connectionSession{}, errors.New("current Router VPN session has not proved a stable connected path")
	}
	return session, ctx.Err()
}

func sameAsyncMeasurementSession(before, after connectionSession) bool {
	return before.ID != "" && after.ID == before.ID && after.Connected && after.Phase == "connected" && after.PathProof == "passed" &&
		after.RouterID == before.RouterID && after.ActualMode == before.ActualMode && after.ActualBase == before.ActualBase
}

func asyncMeasurementProfileToken(p common.RouterProfile) string {
	return liveMeasurementProfileToken(p)
}

func (a *app) activeAsyncMeasurementProfile() (common.RouterProfile, state, error) {
	return a.activeAsyncMeasurementProfileContext(context.Background())
}

func (a *app) activeAsyncMeasurementProfileContext(ctx context.Context) (common.RouterProfile, state, error) {
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return common.RouterProfile{}, state{}, err
	}
	defer a.mu.Unlock()
	st := a.state
	if !st.Connected || strings.TrimSpace(st.Phase) != "connected" {
		return common.RouterProfile{}, st, errors.New("connect the VPN first; live proof requires a stable connected path")
	}
	target := strings.TrimSpace(st.RouterID)
	if target == "" {
		return common.RouterProfile{}, st, errors.New("active VPN node identity is unavailable; refusing to substitute the mutable selected node")
	}
	p, ok := a.profileByIDLocked(target)
	if !ok {
		return common.RouterProfile{}, st, errors.New("active VPN node disappeared before live proof")
	}
	return cloneRouterProfile(p), st, ctx.Err()
}

func validateAsyncMeasurementProfile(a *app, p common.RouterProfile, st state, session connectionSession, token string) error {
	return validateAsyncMeasurementProfileContext(context.Background(), a, p, st, session, token)
}

func validateAsyncMeasurementProfileContext(ctx context.Context, a *app, p common.RouterProfile, st state, session connectionSession, token string) error {
	_, currentSession, err := measurementSessionContext(ctx, a, nil)
	if err != nil {
		return err
	}
	if !sameAsyncMeasurementSession(session, currentSession) {
		return errors.New("VPN session/path changed while live proof was running")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if !a.state.Connected || mtuStateSnapshotToken(a.state) != mtuStateSnapshotToken(st) || strings.TrimSpace(a.state.RouterID) != p.ID {
		return errors.New("active VPN node/mode/base/path changed while live proof was running")
	}
	current, ok := a.profileByIDLocked(p.ID)
	if !ok || asyncMeasurementProfileToken(current) != token {
		return errors.New("active VPN profile or policy changed while live proof was running")
	}
	return ctx.Err()
}

func (a *app) publicIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	targetProfile, stateAtStart, err := a.activeAsyncMeasurementProfileContext(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	target := targetProfile.ID
	targetAtStart := asyncMeasurementProfileToken(targetProfile)
	sessionAtStart, sessionErr := captureAsyncMeasurementSessionContext(r.Context(), a)
	if sessionErr != nil {
		http.Error(w, sessionErr.Error(), http.StatusConflict)
		return
	}
	if sessionAtStart.RouterID != "" && sessionAtStart.RouterID != target {
		http.Error(w, "session tracker node does not match the running VPN node", http.StatusConflict)
		return
	}
	measurementCtx, stopMeasurement, validatePath, err := asyncMeasurementPathContext(r.Context(), a, targetProfile, stateAtStart, sessionAtStart, targetAtStart)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "public-exit lookup") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stopMeasurement()
	client, err := newAsyncMeasurementHTTPClient(stateAtStart, 5*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer client.CloseIdleConnections()
	result, lookupErr := probePublicExitIPContext(measurementCtx, client)
	if asyncMeasurementRequestError(w, r.Context(), measurementCtx, "public-exit lookup") {
		return
	}
	if err := validatePath(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if lookupErr != nil {
		http.Error(w, lookupErr.Error(), http.StatusBadGateway)
		return
	}
	if err := validateAsyncMeasurementProfileContext(measurementCtx, a, targetProfile, stateAtStart, sessionAtStart, targetAtStart); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	releaseAdoption, err := a.beginAsyncMeasurementAdoption(measurementCtx)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), measurementCtx, "public-exit lookup") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	currentProfile, currentOK := a.profileByIDLocked(target)
	if !a.state.Connected || mtuStateSnapshotToken(a.state) != mtuStateSnapshotToken(stateAtStart) || strings.TrimSpace(a.state.RouterID) != target || !currentOK || asyncMeasurementProfileToken(currentProfile) != targetAtStart {
		releaseAdoption()
		http.Error(w, "active VPN path or policy changed before public-exit persistence", http.StatusConflict)
		return
	}
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == target {
			a.profiles.Profiles[i].PublicIP = result
			break
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	}
	releaseAdoption()
	if persistErr != nil {
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"public_ip": result, "router_id": target, "multihop": stateAtStart.Mode == "multihop"})
}

type dnsBenchmarkPayload struct {
	Winner  common.DNSBenchmarkResult   `json:"winner"`
	Results []common.DNSBenchmarkResult `json:"results"`
}

func (a *app) retestDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, stateAtStart, err := a.activeAsyncMeasurementProfileContext(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil {
		http.Error(w, "DNS Retest requires the active Router VPN home node", http.StatusConflict)
		return
	}
	if strings.TrimSpace(p.RouterAPI) == "" || strings.TrimSpace(p.APIToken) == "" {
		http.Error(w, "active Router VPN node has no private DNS benchmark API/token", http.StatusConflict)
		return
	}
	profileAtStart := asyncMeasurementProfileToken(p)
	sessionAtStart, sessionErr := captureAsyncMeasurementSessionContext(r.Context(), a)
	if sessionErr != nil {
		http.Error(w, sessionErr.Error(), http.StatusConflict)
		return
	}
	if sessionAtStart.RouterID != "" && sessionAtStart.RouterID != p.ID {
		http.Error(w, "session tracker node does not match the active DNS benchmark node", http.StatusConflict)
		return
	}

	measurementCtx, stopMeasurement, validatePath, err := asyncMeasurementPathContext(r.Context(), a, p, stateAtStart, sessionAtStart, profileAtStart)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "DNS Retest") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stopMeasurement()
	if stateAtStart.Mode == "multihop" {
		// Equal private API addresses are not node identity. Prove the exit lane
		// before authorizing a benchmark through it; never fall back to direct.
		if err := proveMultihopLaneNodeContext(measurementCtx, p, multihopProofProxy); err != nil {
			if !asyncMeasurementRequestError(w, r.Context(), measurementCtx, "DNS Retest") {
				http.Error(w, "DNS Retest exit-lane proof failed: "+err.Error(), http.StatusConflict)
			}
			return
		}
	}
	req, err := privateDNSBenchmarkRequestContext(measurementCtx, p.RouterAPI, p.APIToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client, err := newAsyncMeasurementHTTPClient(stateAtStart, 45*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), measurementCtx, "DNS Retest") {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
		return
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	_ = resp.Body.Close()
	if asyncMeasurementRequestError(w, r.Context(), measurementCtx, "DNS Retest") {
		return
	}
	if readErr != nil || len(body) > 1<<20 {
		http.Error(w, "DNS benchmark response exceeded its bounded result size", http.StatusBadGateway)
		return
	}
	if resp.StatusCode/100 != 2 {
		http.Error(w, strings.TrimSpace(string(body)), resp.StatusCode)
		return
	}
	var payload dnsBenchmarkPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid DNS benchmark response", http.StatusBadGateway)
		return
	}
	if asyncMeasurementRequestError(w, r.Context(), measurementCtx, "DNS Retest") {
		return
	}
	if err := validatePath(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err := validateAsyncMeasurementProfileContext(measurementCtx, a, p, stateAtStart, sessionAtStart, profileAtStart); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	if r.Context().Err() != nil {
		http.Error(w, "DNS Retest was cancelled before persistence", http.StatusRequestTimeout)
		return
	}
	releaseAdoption, err := a.beginAsyncMeasurementAdoption(measurementCtx)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), measurementCtx, "DNS Retest") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	current, currentOK := a.profileByIDLocked(p.ID)
	if !a.state.Connected || mtuStateSnapshotToken(a.state) != mtuStateSnapshotToken(stateAtStart) || strings.TrimSpace(a.state.RouterID) != p.ID || !currentOK || asyncMeasurementProfileToken(current) != profileAtStart {
		releaseAdoption()
		http.Error(w, "active node/path or DNS policy changed before DNS Retest persistence", http.StatusConflict)
		return
	}
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == p.ID {
			x := &a.profiles.Profiles[i]
			x.DNSResults = payload.Results
			if payload.Winner.Address != "" {
				x.FastestDNSHost = payload.Winner.Address
				x.FastestDNSName = payload.Winner.Name
				x.FastestDNSLatencyMs = payload.Winner.LatencyMs
			}
			break
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	}
	releaseAdoption()
	if persistErr != nil {
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (a *app) emergencyStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	receipt, err := a.capturePublicStopContext(r.Context(), "emergency-stop")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	release, err := a.beginCapturedPublicStopContext(r.Context(), receipt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer release()
	if err := finishViaEntryCancellationContext(r.Context(), a); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if err := a.stopModeWithDNSReceiptContext(r.Context(), false, receipt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true,"message":"local Router VPN transports stopped"}`)
}
