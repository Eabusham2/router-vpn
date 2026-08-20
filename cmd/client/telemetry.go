package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
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
	if value <= 0 { value = fallback }
	if value < 1 { value = 1 }
	if value > 10 { value = 10 }
	return value
}

func liveProbePort(endpoint string) (int, error) {
	ports := []int{443, 8388, 10443, 11443, 12443, 13443, 14443, 15443}
	var last error
	for _, port := range ports {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint, fmt.Sprintf("%d", port)), 450*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return port, nil
		}
		last = err
	}
	if last == nil { last = errors.New("no live probe port") }
	return 0, last
}

func quickProfileLatency(p common.RouterProfile, samples int) (liveLatencyResult, error) {
	if strings.TrimSpace(p.Endpoint) == "" { return liveLatencyResult{}, errors.New("node has no endpoint") }
	port, err := liveProbePort(p.Endpoint)
	if err != nil { return liveLatencyResult{}, err }
	values := make([]float64, 0, samples)
	failed := 0
	for i := 0; i < samples; i++ {
		started := time.Now()
		c, dialErr := net.DialTimeout("tcp", net.JoinHostPort(p.Endpoint, fmt.Sprintf("%d", port)), 850*time.Millisecond)
		if dialErr != nil { failed++; continue }
		_ = c.Close()
		values = append(values, float64(time.Since(started).Microseconds())/1000.0)
		if i+1 < samples { time.Sleep(20 * time.Millisecond) }
	}
	if len(values) == 0 { return liveLatencyResult{}, errors.New("all live latency samples failed") }
	sort.Float64s(values)
	return liveLatencyResult{
		ID: p.ID, Name: p.Name, NodeKind: p.NodeKind, Endpoint: p.Endpoint, Port: port,
		Samples: len(values), Failed: failed, MinMs: round3(values[0]), MedianMs: round3(percentile(values, 0.50)),
		AverageMs: round3(average(values)), P90Ms: round3(percentile(values, 0.90)), MaxMs: round3(values[len(values)-1]),
		MeasuredAt: time.Now().UTC(), Description: "lightweight TCP-handshake RTT for live UI; use the 50-sample node benchmark for durable ranking",
	}, nil
}

func (a *app) liveProfileLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var q liveLatencyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
	q.Samples = clampLiveSamples(q.Samples, 3)
	a.mu.Lock(); p, ok := a.profileByIDLocked(strings.TrimSpace(q.ID)); a.mu.Unlock()
	if !ok { http.Error(w, "unknown router profile", http.StatusNotFound); return }
	result, err := quickProfileLatency(p, q.Samples)
	if err != nil { http.Error(w, err.Error(), http.StatusBadGateway); return }
	w.Header().Set("content-type", "application/json"); w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}

func updateStoredLiveLatency(p *common.RouterProfile, value liveLatencyResult) {
	p.LatencySamples = value.Samples
	p.LatencyMinMs = value.MinMs
	p.LatencyMedianMs = value.MedianMs
	p.LatencyTrimmedMeanMs = value.MedianMs
	p.LatencyAverageMs = value.AverageMs
	p.LatencyP90Ms = value.P90Ms
	p.LatencyMaxMs = value.MaxMs
	p.LatencyLastTest = value.MeasuredAt.Format(time.RFC3339)
}

func (a *app) fastestProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var q liveLatencyRequest
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil && !errors.Is(err, io.EOF) { http.Error(w, "bad json", http.StatusBadRequest); return }
	}
	q.Samples = clampLiveSamples(q.Samples, 5)
	selectWinner := true; if q.Select != nil { selectWinner = *q.Select }
	a.mu.Lock()
	if selectWinner && (a.state.Connected || profileSettingsBusy(a.state.Connected, a.state.Phase)) { a.mu.Unlock(); http.Error(w, "disconnect before switching to the fastest node", http.StatusConflict); return }
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	a.mu.Unlock()
	results := make([]liveLatencyResult, 0, len(profiles))
	for _, p := range profiles {
		kind := strings.ToLower(strings.TrimSpace(p.NodeKind)); if kind == "" { kind = "router-vpn" }
		if kind == "external" && !q.IncludeExternal { continue }
		if value, err := quickProfileLatency(p, q.Samples); err == nil { results = append(results, value) }
	}
	if len(results) == 0 { http.Error(w, "no node returned a live latency result", http.StatusBadGateway); return }
	sort.SliceStable(results, func(i, j int) bool { return results[i].MedianMs < results[j].MedianMs })
	winner := results[0]
	a.mu.Lock()
	for i := range a.profiles.Profiles {
		for _, value := range results { if a.profiles.Profiles[i].ID == value.ID { updateStoredLiveLatency(&a.profiles.Profiles[i], value); break } }
	}
	if selectWinner { a.profiles.SelectedID = winner.ID; a.state.RouterID = winner.ID }
	persistErr := a.persistProfilesLocked(); selectedID := a.profiles.SelectedID
	a.mu.Unlock()
	if persistErr != nil { http.Error(w, persistErr.Error(), http.StatusInternalServerError); return }
	w.Header().Set("content-type", "application/json"); w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"winner": winner, "results": results, "selected_id": selectedID, "selected": selectWinner, "note": "fastest-node chooses the lowest live median RTT; durable 50-sample node tests remain available separately"})
}

func activeLatencyTarget(a *app) (common.RouterProfile, state, error) {
	a.mu.Lock(); st := a.state; target := a.profiles.SelectedID; if st.Mode == "multihop" && st.RouterID != "" { target = st.RouterID }; p, ok := a.profileByIDLocked(target); a.mu.Unlock()
	if !st.Connected { return common.RouterProfile{}, st, errors.New("VPN is not connected") }
	if !ok { return common.RouterProfile{}, st, errors.New("active node is missing") }
	if strings.TrimSpace(p.RouterAPI) == "" { return common.RouterProfile{}, st, errors.New("active node has no private Router API") }
	return p, st, nil
}

func privatePathLatency(p common.RouterProfile, st state, samples int) (connectionLatencyResult, error) {
	values := make([]float64, 0, samples); failed := 0
	client := &http.Client{Timeout: 1800 * time.Millisecond}
	url := strings.TrimRight(p.RouterAPI, "/") + "/health"
	for i := 0; i < samples; i++ {
		req, err := http.NewRequest(http.MethodGet, url, nil); if err != nil { return connectionLatencyResult{}, err }
		if strings.TrimSpace(p.APIToken) != "" { req.Header.Set("Authorization", "Bearer "+p.APIToken) }
		started := time.Now(); resp, err := client.Do(req)
		if err != nil { failed++; continue }
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048)); _ = resp.Body.Close()
		if resp.StatusCode/100 != 2 { failed++; continue }
		values = append(values, float64(time.Since(started).Microseconds())/1000.0)
		if i+1 < samples { time.Sleep(35 * time.Millisecond) }
	}
	if len(values) == 0 { return connectionLatencyResult{}, errors.New("current private tunnel path did not answer") }
	sort.Float64s(values)
	return connectionLatencyResult{Connected: true, Mode: st.Mode, RouterID: p.ID, Name: p.Name, Samples: len(values), Failed: failed, MinMs: round3(values[0]), MedianMs: round3(percentile(values, .50)), AverageMs: round3(average(values)), P90Ms: round3(percentile(values, .90)), MaxMs: round3(values[len(values)-1]), MeasuredAt: time.Now().UTC(), Proof: "HTTP RTT to the active node private Router API through the current tunnel"}, nil
}

func (a *app) connectionLiveLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost { http.Error(w, "GET or POST only", http.StatusMethodNotAllowed); return }
	samples := 2
	if r.Method == http.MethodPost { var q liveLatencyRequest; if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err == nil { samples = clampLiveSamples(q.Samples, 2) } }
	p, st, err := activeLatencyTarget(a); if err != nil { http.Error(w, err.Error(), http.StatusConflict); return }
	value, err := privatePathLatency(p, st, samples); if err != nil { http.Error(w, err.Error(), http.StatusBadGateway); return }
	w.Header().Set("content-type", "application/json"); w.Header().Set("cache-control", "no-store"); _ = json.NewEncoder(w).Encode(value)
}

func clampSpeedBytes(value int64) int64 {
	if value == 0 { return 8 << 20 }
	if value < 1<<20 { return 1 << 20 }
	if value > 16<<20 { return 16 << 20 }
	return value
}

func privateBenchmarkRequest(method, url, token string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil { return nil, err }
	if strings.TrimSpace(token) != "" { req.Header.Set("Authorization", "Bearer "+token) }
	req.Header.Set("Cache-Control", "no-store")
	if body != nil { req.Header.Set("Content-Type", "application/octet-stream") }
	return req, nil
}

func (a *app) connectionSpeedTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var q connectionSpeedRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil && !errors.Is(err, io.EOF) { http.Error(w, "bad json", http.StatusBadRequest); return }
	q.Bytes = clampSpeedBytes(q.Bytes)
	p, st, err := activeLatencyTarget(a); if err != nil { http.Error(w, err.Error(), http.StatusConflict); return }
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil { http.Error(w, "private Router VPN throughput benchmark is unavailable for an external-only exit", http.StatusConflict); return }
	if strings.TrimSpace(p.APIToken) == "" { http.Error(w, "active node has no private benchmark token", http.StatusConflict); return }

	client := &http.Client{Timeout: 30 * time.Second}
	base := strings.TrimRight(p.RouterAPI, "/")
	downloadURL := base + "/api/benchmark/download?bytes=" + strconv.FormatInt(q.Bytes, 10)
	downloadReq, err := privateBenchmarkRequest(http.MethodGet, downloadURL, p.APIToken, nil); if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	downloadStarted := time.Now()
	downloadResp, err := client.Do(downloadReq); if err != nil { http.Error(w, "download benchmark failed: "+err.Error(), http.StatusBadGateway); return }
	downloaded, copyErr := io.Copy(io.Discard, io.LimitReader(downloadResp.Body, q.Bytes+1)); _ = downloadResp.Body.Close()
	if copyErr != nil { http.Error(w, "download benchmark read failed: "+copyErr.Error(), http.StatusBadGateway); return }
	if downloadResp.StatusCode/100 != 2 { http.Error(w, "download benchmark returned "+downloadResp.Status, http.StatusBadGateway); return }
	if downloaded != q.Bytes { http.Error(w, fmt.Sprintf("download benchmark returned %d bytes, expected %d", downloaded, q.Bytes), http.StatusBadGateway); return }
	downloadElapsed := time.Since(downloadStarted)

	uploadPayload := make([]byte, q.Bytes)
	if _, err := rand.Read(uploadPayload); err != nil { http.Error(w, "could not prepare incompressible upload payload", http.StatusInternalServerError); return }
	uploadURL := base + "/api/benchmark/upload"
	uploadReq, err := privateBenchmarkRequest(http.MethodPost, uploadURL, p.APIToken, bytes.NewReader(uploadPayload)); if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	uploadReq.ContentLength = q.Bytes
	uploadStarted := time.Now()
	uploadResp, err := client.Do(uploadReq); if err != nil { http.Error(w, "upload benchmark failed: "+err.Error(), http.StatusBadGateway); return }
	uploadBody, readErr := io.ReadAll(io.LimitReader(uploadResp.Body, 64<<10)); _ = uploadResp.Body.Close()
	if readErr != nil { http.Error(w, "upload benchmark response failed: "+readErr.Error(), http.StatusBadGateway); return }
	if uploadResp.StatusCode/100 != 2 { http.Error(w, "upload benchmark returned "+uploadResp.Status+": "+strings.TrimSpace(string(uploadBody)), http.StatusBadGateway); return }
	uploadElapsed := time.Since(uploadStarted)
	var uploadServer struct { ServerReceiveMs float64 `json:"server_receive_ms"`; Bytes int64 `json:"bytes"` }
	if err := json.Unmarshal(uploadBody, &uploadServer); err != nil { http.Error(w, "upload benchmark returned invalid JSON", http.StatusBadGateway); return }
	if uploadServer.Bytes != q.Bytes { http.Error(w, fmt.Sprintf("upload benchmark accepted %d bytes, expected %d", uploadServer.Bytes, q.Bytes), http.StatusBadGateway); return }

	mbits := float64(q.Bytes*8) / 1_000_000.0
	result := connectionSpeedResult{
		Connected: true, Mode: st.Mode, LogicalMode: st.LogicalMode, RouterID: p.ID, Name: p.Name, Bytes: q.Bytes,
		DownloadMbps: round3(mbits / downloadElapsed.Seconds()), UploadMbps: round3(mbits / uploadElapsed.Seconds()),
		DownloadMs: round3(float64(downloadElapsed.Microseconds()) / 1000.0), UploadMs: round3(float64(uploadElapsed.Microseconds()) / 1000.0),
		ServerReceiveMs: round3(uploadServer.ServerReceiveMs), MeasuredAt: time.Now().UTC(),
		Proof: "authenticated bounded upload/download against the active node private router-agent through the current VPN path",
	}
	w.Header().Set("content-type", "application/json"); w.Header().Set("cache-control", "no-store"); _ = json.NewEncoder(w).Encode(result)
}

func (a *app) multihopLiveLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var q liveLatencyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
	q.Samples = clampLiveSamples(q.Samples, 3)
	a.mu.Lock(); entry, entryOK := a.profileByIDLocked(strings.TrimSpace(q.EntryID)); exit, exitOK := a.profileByIDLocked(strings.TrimSpace(q.ExitID)); st := a.state; a.mu.Unlock()
	if !entryOK || !exitOK { http.Error(w, "unknown multihop entry or exit node", http.StatusNotFound); return }
	if entry.ID == exit.ID { http.Error(w, "multihop entry and exit must be different", http.StatusBadRequest); return }
	entryValue, entryErr := quickProfileLatency(entry, q.Samples); exitValue, exitErr := quickProfileLatency(exit, q.Samples)
	payload := map[string]any{"entry_id": entry.ID, "exit_id": exit.ID, "measured_at": time.Now().UTC(), "note": "entry_ms and exit_ms are live client-to-node RTTs. current_path is included only when an actual multihop tunnel is connected; Router VPN does not fake an entry-to-exit hop measurement from arithmetic."}
	if entryErr == nil { payload["entry"] = entryValue } else { payload["entry_error"] = entryErr.Error() }
	if exitErr == nil { payload["exit"] = exitValue } else { payload["exit_error"] = exitErr.Error() }
	if st.Connected && st.Mode == "multihop" {
		if p, current, err := activeLatencyTarget(a); err == nil { if path, pathErr := privatePathLatency(p, current, 2); pathErr == nil { payload["current_path"] = path } else { payload["current_path_error"] = pathErr.Error() } }
	}
	if entryErr != nil && exitErr != nil { http.Error(w, "both multihop node latency probes failed", http.StatusBadGateway); return }
	w.Header().Set("content-type", "application/json"); w.Header().Set("cache-control", "no-store"); _ = json.NewEncoder(w).Encode(payload)
}
