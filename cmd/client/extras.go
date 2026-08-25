package main

import (
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
	h.HandleFunc("/api/public-ip", a.publicIP)
	h.HandleFunc("/api/dns/retest", a.retestDNS)
	registerMTURetestRoute(h, a)
	h.HandleFunc("/api/emergency-stop", a.emergencyStopTracked)
	// Linux keeps its native WG/AWG split-entry chain. Windows and macOS route
	// to their real native desktop multihop launchers instead of accidentally
	// exposing the Linux-only handler and returning a false unsupported result.
	registerDesktopMultihopRoutes(h, a)
}

type latencyRequest struct {
	ID      string `json:"id"`
	Samples int    `json:"samples"`
}

type latencyResponse struct {
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

	a.mu.Lock()
	p, ok := a.profileByIDLocked(q.ID)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "unknown router profile", http.StatusNotFound)
		return
	}
	if p.Endpoint == "" {
		http.Error(w, "router profile has no endpoint", http.StatusBadRequest)
		return
	}
	profileAtStart := fastestProfileSnapshotToken([]common.RouterProfile{p})

	port, err := pickTCPProbePort(p.Endpoint)
	if err != nil {
		http.Error(w, "node is not reachable on a known TCP listener: "+err.Error(), http.StatusBadGateway)
		return
	}

	values := make([]float64, 0, q.Samples)
	failed := 0
	for i := 0; i < q.Samples; i++ {
		started := time.Now()
		c, dialErr := net.DialTimeout("tcp", net.JoinHostPort(p.Endpoint, fmt.Sprintf("%d", port)), 1500*time.Millisecond)
		if dialErr != nil {
			failed++
			continue
		}
		_ = c.Close()
		values = append(values, float64(time.Since(started).Microseconds())/1000.0)
		if i%10 == 9 {
			time.Sleep(15 * time.Millisecond)
		}
	}
	if len(values) < 5 {
		http.Error(w, "too few successful latency samples", http.StatusBadGateway)
		return
	}
	sort.Float64s(values)
	minV := values[0]
	maxV := values[len(values)-1]
	avgV := average(values)
	medianV := percentile(values, 0.50)
	p90V := percentile(values, 0.90)
	trim := len(values) / 10
	trimmed := values
	if len(values)-2*trim >= 3 && trim > 0 {
		trimmed = values[trim : len(values)-trim]
	}
	trimmedV := average(trimmed)
	now := time.Now().UTC()
	resp := latencyResponse{
		ID:          p.ID,
		Port:        port,
		Samples:     len(values),
		Failed:      failed,
		MinMs:       round3(minV),
		MedianMs:    round3(medianV),
		TrimmedMs:   round3(trimmedV),
		AverageMs:   round3(avgV),
		P90Ms:       round3(p90V),
		MaxMs:       round3(maxV),
		MeasuredAt:  now,
		Description: "TCP handshake latency; median and 10% trimmed mean resist outliers",
	}

	a.mu.Lock()
	previousStore := cloneRouterProfileStore(a.profiles)
	current, currentOK := a.profileByIDLocked(p.ID)
	if !currentOK || fastestProfileSnapshotToken([]common.RouterProfile{current}) != profileAtStart {
		a.mu.Unlock()
		http.Error(w, "router profile identity changed while durable latency measurement was running", http.StatusConflict)
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
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func pickTCPProbePort(endpoint string) (int, error) {
	ports := []int{443, 8388, 10443, 11443, 12443, 13443, 14443, 15443}
	var last error
	for _, port := range ports {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint, fmt.Sprintf("%d", port)), 1200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return port, nil
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

func sameAsyncMeasurementSession(before, after connectionSession) bool {
	return before.ID != "" && after.ID == before.ID && after.Connected && after.Phase == "connected" && after.PathProof == "passed" &&
		after.RouterID == before.RouterID && after.ActualMode == before.ActualMode && after.ActualBase == before.ActualBase
}

func (a *app) publicIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	connected := a.state.Connected
	selected := a.profiles.SelectedID
	target := selected
	if a.state.Mode == "multihop" && a.state.RouterID != "" {
		target = a.state.RouterID
	}
	targetProfile, targetOK := a.profileByIDLocked(target)
	a.mu.Unlock()
	if !connected {
		http.Error(w, "connect the VPN first so the reported address is the VPN exit", http.StatusConflict)
		return
	}
	if !targetOK {
		http.Error(w, "active VPN node disappeared before public-exit lookup", http.StatusConflict)
		return
	}
	targetAtStart := fastestProfileSnapshotToken([]common.RouterProfile{targetProfile})
	sessionAtStart, sessionErr := captureAsyncMeasurementSession(a)
	if sessionErr != nil {
		http.Error(w, sessionErr.Error(), http.StatusConflict)
		return
	}
	a.mu.Lock()
	stateAtStart := mtuStateSnapshotToken(a.state)
	a.mu.Unlock()
	client := &http.Client{Timeout: 5 * time.Second}
	providers := []string{"https://api64.ipify.org", "https://api.ipify.org"}
	var result string
	for _, endpoint := range providers {
		resp, err := client.Get(endpoint)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		candidate := strings.TrimSpace(string(body))
		if resp.StatusCode/100 == 2 && net.ParseIP(candidate) != nil {
			result = candidate
			break
		}
	}
	if result == "" {
		http.Error(w, "could not determine public VPN exit address", http.StatusBadGateway)
		return
	}
	if !sameAsyncMeasurementSession(sessionAtStart, sessionTrackerFor(a).snapshot(0)) {
		http.Error(w, "VPN session/path changed while public-exit lookup was running", http.StatusConflict)
		return
	}
	a.mu.Lock()
	previousStore := cloneRouterProfileStore(a.profiles)
	currentTarget := a.profiles.SelectedID
	if a.state.Mode == "multihop" && a.state.RouterID != "" {
		currentTarget = a.state.RouterID
	}
	currentProfile, currentOK := a.profileByIDLocked(target)
	if !a.state.Connected || mtuStateSnapshotToken(a.state) != stateAtStart || currentTarget != target || !currentOK || fastestProfileSnapshotToken([]common.RouterProfile{currentProfile}) != targetAtStart {
		a.mu.Unlock()
		http.Error(w, "active VPN path changed while public-exit lookup was running", http.StatusConflict)
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
	a.mu.Unlock()
	if persistErr != nil {
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"public_ip": result, "router_id": target, "multihop": target != selected})
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
	p, err := a.activeProfile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	connected := a.state.Connected
	a.mu.Unlock()
	if !connected {
		http.Error(w, "connect this router first; DNS retest runs from the home node", http.StatusConflict)
		return
	}
	profileAtStart := fastestProfileSnapshotToken([]common.RouterProfile{p})
	sessionAtStart, sessionErr := captureAsyncMeasurementSession(a)
	if sessionErr != nil {
		http.Error(w, sessionErr.Error(), http.StatusConflict)
		return
	}
	a.mu.Lock()
	stateAtStart := mtuStateSnapshotToken(a.state)
	a.mu.Unlock()

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(p.RouterAPI, "/")+"/api/dns/benchmark", strings.NewReader(`{}`))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("content-type", "application/json")
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		http.Error(w, strings.TrimSpace(string(body)), resp.StatusCode)
		return
	}
	var payload dnsBenchmarkPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid DNS benchmark response", http.StatusBadGateway)
		return
	}

	if !sameAsyncMeasurementSession(sessionAtStart, sessionTrackerFor(a).snapshot(0)) {
		http.Error(w, "VPN session/path changed while DNS Retest was running", http.StatusConflict)
		return
	}
	a.mu.Lock()
	previousStore := cloneRouterProfileStore(a.profiles)
	current, currentOK := a.profileByIDLocked(p.ID)
	if !a.state.Connected || mtuStateSnapshotToken(a.state) != stateAtStart || a.profiles.SelectedID != p.ID || !currentOK || fastestProfileSnapshotToken([]common.RouterProfile{current}) != profileAtStart {
		a.mu.Unlock()
		http.Error(w, "selected node or DNS policy changed while DNS Retest was running", http.StatusConflict)
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
	a.mu.Unlock()
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
	a.cancelConnectionOperation()
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	if err := a.stopMode(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true,"message":"local Router VPN transports stopped"}`)
}
