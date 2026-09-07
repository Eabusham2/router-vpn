package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type liveLatencyRequest struct {
	ID              string `json:"id"`
	EntryID         string `json:"entry_id"`
	ExitID          string `json:"exit_id"`
	Samples         int    `json:"samples"`
	Select          *bool  `json:"select,omitempty"`
	IncludeExternal bool   `json:"include_external,omitempty"`
}

type connectionSpeedRequest struct {
	Bytes int64 `json:"bytes,omitempty"`
}

type liveLatencyResult struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	NodeKind    string    `json:"node_kind"`
	Endpoint    string    `json:"endpoint"`
	Port        int       `json:"port"`
	Samples     int       `json:"samples"`
	Failed      int       `json:"failed"`
	MinMs       float64   `json:"min_ms"`
	MedianMs    float64   `json:"median_ms"`
	AverageMs   float64   `json:"average_ms"`
	P90Ms       float64   `json:"p90_ms"`
	MaxMs       float64   `json:"max_ms"`
	MeasuredAt  time.Time `json:"measured_at"`
	Description string    `json:"description"`
}

type connectionLatencyResult struct {
	Connected  bool      `json:"connected"`
	Mode       string    `json:"mode"`
	RouterID   string    `json:"router_id"`
	Name       string    `json:"name"`
	Samples    int       `json:"samples"`
	Failed     int       `json:"failed"`
	MinMs      float64   `json:"min_ms"`
	MedianMs   float64   `json:"median_ms"`
	AverageMs  float64   `json:"average_ms"`
	P90Ms      float64   `json:"p90_ms"`
	MaxMs      float64   `json:"max_ms"`
	MeasuredAt time.Time `json:"measured_at"`
	Proof      string    `json:"proof"`
}

type connectionSpeedResult struct {
	Connected       bool      `json:"connected"`
	Mode            string    `json:"mode"`
	LogicalMode     string    `json:"logical_mode"`
	RouterID        string    `json:"router_id"`
	Name            string    `json:"name"`
	Bytes           int64     `json:"bytes"`
	DownloadMbps    float64   `json:"download_mbps"`
	UploadMbps      float64   `json:"upload_mbps"`
	DownloadMs      float64   `json:"download_ms"`
	UploadMs        float64   `json:"upload_ms"`
	ServerReceiveMs float64   `json:"server_receive_ms,omitempty"`
	MeasuredAt      time.Time `json:"measured_at"`
	Proof           string    `json:"proof"`
}

func registerTelemetryRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/profile/live-latency", a.liveProfileLatency)
	h.HandleFunc("/api/profile/fastest", a.fastestProfile)
	h.HandleFunc("/api/connection/live-latency", a.connectionLiveLatency)
	h.HandleFunc("/api/connection/speed-test", a.connectionSpeedTest)
	h.HandleFunc("/api/multihop/live-latency", a.multihopLiveLatency)
}

func clampLiveSamples(value, fallback int) int {
	if value <= 0 {
		value = fallback
	}
	if value < 1 {
		value = 1
	}
	if value > 10 {
		value = 10
	}
	return value
}

func liveProbePort(endpoint string) (int, error) {
	return liveProbePortContext(context.Background(), endpoint)
}

func liveProbePortContext(ctx context.Context, endpoint string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ports := []int{443, 8388, 10443, 11443, 12443, 13443, 14443, 15443}
	var last error
	dialer := &net.Dialer{Timeout: 450 * time.Millisecond}
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
		last = errors.New("no live probe port")
	}
	return 0, last
}

func quickProfileLatency(p common.RouterProfile, samples int) (liveLatencyResult, error) {
	return quickProfileLatencyContext(context.Background(), p, samples)
}

func quickProfileLatencyContext(ctx context.Context, p common.RouterProfile, samples int) (liveLatencyResult, error) {
	if err := ctx.Err(); err != nil {
		return liveLatencyResult{}, err
	}
	if strings.TrimSpace(p.Endpoint) == "" {
		return liveLatencyResult{}, errors.New("node has no endpoint")
	}
	port, err := liveProbePortContext(ctx, p.Endpoint)
	if err != nil {
		return liveLatencyResult{}, err
	}
	values := make([]float64, 0, samples)
	failed := 0
	dialer := &net.Dialer{Timeout: 850 * time.Millisecond}
	for i := 0; i < samples; i++ {
		started := time.Now()
		c, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(p.Endpoint, fmt.Sprintf("%d", port)))
		if dialErr != nil {
			if ctx.Err() != nil {
				return liveLatencyResult{}, ctx.Err()
			}
			failed++
			continue
		}
		_ = c.Close()
		values = append(values, float64(time.Since(started).Microseconds())/1000.0)
		if i+1 < samples {
			select {
			case <-ctx.Done():
				return liveLatencyResult{}, ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return liveLatencyResult{}, err
	}
	if len(values) == 0 {
		return liveLatencyResult{}, errors.New("all live latency samples failed")
	}
	sort.Float64s(values)
	return liveLatencyResult{
		ID: p.ID, Name: p.Name, NodeKind: p.NodeKind, Endpoint: p.Endpoint, Port: port,
		Samples: len(values), Failed: failed, MinMs: round3(values[0]), MedianMs: round3(percentile(values, 0.50)),
		AverageMs: round3(average(values)), P90Ms: round3(percentile(values, 0.90)), MaxMs: round3(values[len(values)-1]),
		MeasuredAt: time.Now().UTC(), Description: "lightweight TCP-handshake RTT for live UI; use the 50-sample node benchmark for durable ranking",
	}, nil
}

func (a *app) liveProfileLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q liveLatencyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	q.Samples = clampLiveSamples(q.Samples, 3)
	a.mu.Lock()
	p, ok := a.profileByIDLocked(strings.TrimSpace(q.ID))
	a.mu.Unlock()
	if !ok {
		http.Error(w, "unknown router profile", http.StatusNotFound)
		return
	}
	result, err := quickProfileLatencyContext(r.Context(), p, q.Samples)
	if err != nil {
		if r.Context().Err() != nil {
			http.Error(w, "live latency request was cancelled", http.StatusRequestTimeout)
		} else {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}

func fastestProfileSnapshotToken(profiles []common.RouterProfile) string {
	var b strings.Builder
	for _, p := range profiles {
		b.WriteString(p.ID)
		b.WriteByte(0)
		b.WriteString(p.NodeKind)
		b.WriteByte(0)
		b.WriteString(p.Endpoint)
		b.WriteByte(0)
		b.WriteString(p.RouterAPI)
		b.WriteByte(0)
		b.WriteString(p.NodeProofID)
		b.WriteByte('\n')
	}
	return b.String()
}

func (a *app) fastestProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q liveLatencyRequest
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
	}
	q.Samples = clampLiveSamples(q.Samples, 5)
	selectWinner := true
	if q.Select != nil {
		selectWinner = *q.Select
	}
	a.mu.Lock()
	if selectWinner && (a.state.Connected || profileSettingsBusy(a.state.Connected, a.state.Phase)) {
		a.mu.Unlock()
		http.Error(w, "disconnect before switching to the fastest node", http.StatusConflict)
		return
	}
	selectionAtStart := a.profiles.SelectedID
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	profilesAtStart := fastestProfileSnapshotToken(profiles)
	a.mu.Unlock()
	sessionAtStart := sessionTrackerFor(a).snapshot(0).ID
	results := make([]liveLatencyResult, 0, len(profiles))
	for _, p := range profiles {
		kind := strings.ToLower(strings.TrimSpace(p.NodeKind))
		if kind == "" {
			kind = "router-vpn"
		}
		if kind == "external" && !q.IncludeExternal {
			continue
		}
		value, err := quickProfileLatencyContext(r.Context(), p, q.Samples)
		if err == nil {
			results = append(results, value)
		} else if r.Context().Err() != nil {
			http.Error(w, "fastest-node measurement was cancelled before selection", http.StatusRequestTimeout)
			return
		}
	}
	if err := r.Context().Err(); err != nil {
		http.Error(w, "fastest-node measurement was cancelled before selection", http.StatusRequestTimeout)
		return
	}
	if len(results) == 0 {
		http.Error(w, "no node returned a live latency result", http.StatusBadGateway)
		return
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].MedianMs < results[j].MedianMs })
	winner := results[0]

	// Fastest is an intentionally lightweight live RTT probe. Its 1-10 samples
	// must never overwrite Latency* fields, which are reserved for the durable
	// >=50-sample /api/profile/latency benchmark (including its real trimmed mean).
	// Only an explicit winner selection is durable here.
	a.mu.Lock()
	selectedID := a.profiles.SelectedID
	var persistErr error
	if selectWinner {
		if r.Context().Err() != nil {
			a.mu.Unlock()
			http.Error(w, "fastest-node measurement was cancelled before selection", http.StatusRequestTimeout)
			return
		}
		if a.state.Connected || profileSettingsBusy(a.state.Connected, a.state.Phase) {
			a.mu.Unlock()
			http.Error(w, "VPN state changed while fastest-node measurement was running", http.StatusConflict)
			return
		}
		if sessionTrackerFor(a).snapshot(0).ID != sessionAtStart {
			a.mu.Unlock()
			http.Error(w, "VPN session changed while fastest-node measurement was running", http.StatusConflict)
			return
		}
		if a.profiles.SelectedID != selectionAtStart {
			a.mu.Unlock()
			http.Error(w, "selected node changed while fastest-node measurement was running", http.StatusConflict)
			return
		}
		if fastestProfileSnapshotToken(a.profiles.Profiles) != profilesAtStart {
			a.mu.Unlock()
			http.Error(w, "linked node catalog changed while fastest-node measurement was running", http.StatusConflict)
			return
		}
		previousStore := cloneRouterProfileStore(a.profiles)
		previousRouterID := a.state.RouterID
		a.profiles.SelectedID = winner.ID
		a.state.RouterID = winner.ID
		selectedID = winner.ID
		persistErr = a.persistProfilesLocked()
		if persistErr != nil {
			a.rollbackProfilesLocked(previousStore)
			a.state.RouterID = previousRouterID
			selectedID = previousStore.SelectedID
		}
	}
	a.mu.Unlock()
	if persistErr != nil {
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"winner": winner, "results": results, "selected_id": selectedID, "selected": selectWinner, "note": "fastest-node chooses the lowest lightweight live median RTT and does not overwrite the durable 50-sample node benchmark"})
}

func activeLatencyTarget(a *app) (common.RouterProfile, state, error) {
	a.mu.Lock()
	st := a.state
	if !st.Connected || strings.TrimSpace(st.Phase) != "connected" {
		a.mu.Unlock()
		return common.RouterProfile{}, st, errors.New("VPN is not connected on a stable path")
	}
	target := strings.TrimSpace(st.RouterID)
	if target == "" {
		a.mu.Unlock()
		return common.RouterProfile{}, st, errors.New("active VPN node identity is unavailable; refusing to substitute the mutable selected node")
	}
	p, ok := a.profileByIDLocked(target)
	a.mu.Unlock()
	if !ok {
		return common.RouterProfile{}, st, errors.New("active node is missing")
	}
	if strings.TrimSpace(p.RouterAPI) == "" {
		return common.RouterProfile{}, st, errors.New("active node has no private Router API")
	}
	session := sessionTrackerFor(a).snapshot(0)
	if session.ID == "" || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" {
		return common.RouterProfile{}, st, errors.New("active VPN session has not proved the current path")
	}
	if session.RouterID != p.ID {
		return common.RouterProfile{}, st, errors.New("active VPN session identity does not match the running node")
	}
	return p, st, nil
}

func activeTelemetryPathToken(st state) string {
	return fmt.Sprintf("%t\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", st.Connected, st.Phase, st.Mode, st.LogicalMode, st.RuntimeMode, st.Base, st.RouterID)
}

func validateActiveTelemetryPath(a *app, p common.RouterProfile, st state, sessionID string) error {
	currentSession := sessionTrackerFor(a).snapshot(0)
	if !st.Connected || strings.TrimSpace(st.Phase) != "connected" || sessionID == "" || currentSession.ID != sessionID || !currentSession.Connected || currentSession.Phase != "connected" || currentSession.PathProof != "passed" {
		return errors.New("VPN session changed while live path telemetry was running; stale result was discarded")
	}
	a.mu.Lock()
	currentState := a.state
	currentProfile, ok := a.profileByIDLocked(strings.TrimSpace(currentState.RouterID))
	a.mu.Unlock()
	if !ok || currentProfile.ID != p.ID || activeTelemetryPathToken(currentState) != activeTelemetryPathToken(st) {
		return errors.New("active VPN node/mode/base/path changed while live path telemetry was running; stale result was discarded")
	}
	if strings.TrimSpace(p.ID) == "" || currentSession.RouterID != p.ID {
		return errors.New("active VPN session node changed while live path telemetry was running; stale result was discarded")
	}
	if asyncMeasurementProfileToken(currentProfile) != asyncMeasurementProfileToken(p) || currentProfile.APIToken != p.APIToken {
		return errors.New("active VPN profile or policy changed while live path telemetry was running; stale result was discarded")
	}
	return nil
}

func privatePathLatency(p common.RouterProfile, st state, samples int) (connectionLatencyResult, error) {
	return privatePathLatencyContext(context.Background(), p, st, samples)
}

func privatePathLatencyContext(ctx context.Context, p common.RouterProfile, st state, samples int) (connectionLatencyResult, error) {
	if err := ctx.Err(); err != nil {
		return connectionLatencyResult{}, err
	}
	if p.External != nil || strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") {
		return connectionLatencyResult{}, errors.New("private Router VPN node latency is unavailable for an external-only node")
	}
	base, err := validatedPrivateRouterAPI(p.RouterAPI)
	if err != nil {
		return connectionLatencyResult{}, err
	}
	// Validate the paired identity before constructing any authenticated request.
	if _, err := expectedNodeProofID(p); err != nil {
		return connectionLatencyResult{}, err
	}
	samples = clampLiveSamples(samples, 2)
	values := make([]float64, 0, samples)
	failed := 0
	client, err := newAsyncMeasurementHTTPClient(st, 1800*time.Millisecond)
	if err != nil {
		return connectionLatencyResult{}, err
	}
	defer client.CloseIdleConnections()
	url := base + "/health"
	for i := 0; i < samples; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return connectionLatencyResult{}, err
		}
		if strings.TrimSpace(p.APIToken) != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIToken)
		}
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Accept-Encoding", "identity")
		started := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return connectionLatencyResult{}, ctx.Err()
			}
			failed++
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
		_ = resp.Body.Close()
		elapsedMs := float64(time.Since(started).Microseconds()) / 1000.0
		if err := ctx.Err(); err != nil {
			return connectionLatencyResult{}, err
		}
		if readErr != nil || len(body) > 16<<10 || resp.StatusCode/100 != 2 {
			failed++
			continue
		}
		// A reachable private address can belong to a different Router VPN node.
		// Never salvage an earlier sample after an identity mismatch in this set.
		if err := validateSelectedNodeProof(p, body); err != nil {
			return connectionLatencyResult{}, fmt.Errorf("private latency node proof failed: %w", err)
		}
		values = append(values, elapsedMs)
		if i+1 < samples {
			select {
			case <-ctx.Done():
				return connectionLatencyResult{}, ctx.Err()
			case <-time.After(35 * time.Millisecond):
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return connectionLatencyResult{}, err
	}
	if len(values) == 0 {
		return connectionLatencyResult{}, errors.New("current private tunnel path did not answer with a proved node identity")
	}
	sort.Float64s(values)
	return connectionLatencyResult{Connected: true, Mode: st.Mode, RouterID: p.ID, Name: p.Name, Samples: len(values), Failed: failed, MinMs: round3(values[0]), MedianMs: round3(percentile(values, .50)), AverageMs: round3(average(values)), P90Ms: round3(percentile(values, .90)), MaxMs: round3(values[len(values)-1]), MeasuredAt: time.Now().UTC(), Proof: "HTTP RTT to the active node private Router API through the current tunnel; paired node identity proved for every sample"}, nil
}

func (a *app) connectionLiveLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	samples := 2
	if r.Method == http.MethodPost {
		var q liveLatencyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err == nil {
			samples = clampLiveSamples(q.Samples, 2)
		}
	}
	p, st, err := activeLatencyTarget(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	sessionAtStart := sessionTrackerFor(a).snapshot(0).ID
	measured, stop, validate, err := connectionTelemetryPathContext(r.Context(), a, p, st, sessionAtStart)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "connection latency") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stop()
	value, measureErr := privatePathLatencyContext(measured, p, st, samples)
	if asyncMeasurementRequestError(w, r.Context(), measured, "connection latency") {
		return
	}
	if err := validate(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if measureErr != nil {
		http.Error(w, measureErr.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func clampSpeedBytes(value int64) int64 {
	if value == 0 {
		return 8 << 20
	}
	if value < 1<<20 {
		return 1 << 20
	}
	if value > 16<<20 {
		return 16 << 20
	}
	return value
}

func privateBenchmarkRequest(method, url, token string, body io.Reader) (*http.Request, error) {
	if err := validatePrivateBenchmarkTarget(method, url); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return req, nil
}

func (a *app) connectionSpeedTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q connectionSpeedRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	q.Bytes = clampSpeedBytes(q.Bytes)
	p, st, err := activeLatencyTarget(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	sessionAtStart := sessionTrackerFor(a).snapshot(0).ID
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil {
		http.Error(w, "private Router VPN throughput benchmark is unavailable for an external-only exit", http.StatusConflict)
		return
	}
	if strings.TrimSpace(p.APIToken) == "" {
		http.Error(w, "active node has no private benchmark token", http.StatusConflict)
		return
	}

	measured, stop, validate, err := connectionTelemetryPathContext(r.Context(), a, p, st, sessionAtStart)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "connection speed test") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stop()
	// Share the bounded download/upload implementation and acknowledgement
	// validation with per-node speed tests; do not maintain a second HTTP path.
	var value routedSpeedResult
	if st.Mode == "multihop" {
		value, err = measureRoutedProfileSpeedViaProxyContext(measured, p, q.Bytes, multihopProofProxy)
	} else {
		value, err = measureRoutedProfileSpeedContext(measured, p, q.Bytes)
	}
	if asyncMeasurementRequestError(w, r.Context(), measured, "connection speed test") {
		return
	}
	if freshnessErr := validate(); freshnessErr != nil {
		http.Error(w, freshnessErr.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Preserve the flat response consumed by all three native desktop shells.
	result := connectionSpeedResult{
		Connected: true, Mode: st.Mode, LogicalMode: st.LogicalMode, RouterID: value.RouterID, Name: value.Name, Bytes: value.Bytes,
		DownloadMbps: value.DownloadMbps, UploadMbps: value.UploadMbps,
		DownloadMs: value.DownloadMs, UploadMs: value.UploadMs,
		ServerReceiveMs: value.ServerReceiveMs, MeasuredAt: value.MeasuredAt, Proof: value.Proof,
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}

func (a *app) multihopLiveLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q liveLatencyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	q.Samples = clampLiveSamples(q.Samples, 3)
	a.mu.Lock()
	entry, entryOK := a.profileByIDLocked(strings.TrimSpace(q.EntryID))
	exit, exitOK := a.profileByIDLocked(strings.TrimSpace(q.ExitID))
	st := a.state
	a.mu.Unlock()
	if !entryOK || !exitOK {
		http.Error(w, "unknown multihop entry or exit node", http.StatusNotFound)
		return
	}
	if entry.ID == exit.ID {
		http.Error(w, "multihop entry and exit must be different", http.StatusBadRequest)
		return
	}
	if asyncMeasurementRequestError(w, r.Context(), r.Context(), "multihop node latency request") {
		return
	}
	if st.Mode == "multihop" {
		a.connectedMultihopLiveLatency(w, r, entry, exit, st, q.Samples)
		return
	}
	entryValue, entryErr := quickProfileLatencyContext(r.Context(), entry, q.Samples)
	if r.Context().Err() != nil {
		http.Error(w, "multihop node latency request was cancelled", http.StatusRequestTimeout)
		return
	}
	exitValue, exitErr := quickProfileLatencyContext(r.Context(), exit, q.Samples)
	if r.Context().Err() != nil {
		http.Error(w, "multihop node latency request was cancelled", http.StatusRequestTimeout)
		return
	}
	payload := map[string]any{"entry_id": entry.ID, "exit_id": exit.ID, "measured_at": time.Now().UTC(), "note": "entry_ms and exit_ms are live client-to-node RTTs. current_path is included only when an actual multihop tunnel is connected; Router VPN does not fake an entry-to-exit hop measurement from arithmetic."}
	if entryErr == nil {
		payload["entry"] = entryValue
	} else {
		payload["entry_error"] = entryErr.Error()
	}
	if exitErr == nil {
		payload["exit"] = exitValue
	} else {
		payload["exit_error"] = exitErr.Error()
	}
	if entryErr != nil && exitErr != nil {
		http.Error(w, "both multihop node latency probes failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}
