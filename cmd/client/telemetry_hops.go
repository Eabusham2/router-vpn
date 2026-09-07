package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type routedSpeedRequest struct {
	ID      string `json:"id,omitempty"`
	EntryID string `json:"entry_id,omitempty"`
	ExitID  string `json:"exit_id,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
}

type routedSpeedResult struct {
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

func registerHopTelemetryRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/profile/speed-test", a.profileSpeedTest)
	h.HandleFunc("/api/multihop/speed-test", a.multihopSpeedTest)
}

func newPrivateBenchmarkHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("private benchmark redirect refused")
		},
	}
}

func measureRoutedProfileSpeed(p common.RouterProfile, bytesCount int64) (routedSpeedResult, error) {
	return measureRoutedProfileSpeedContext(context.Background(), p, bytesCount)
}

func measureRoutedProfileSpeedContext(ctx context.Context, p common.RouterProfile, bytesCount int64) (routedSpeedResult, error) {
	if err := ctx.Err(); err != nil {
		return routedSpeedResult{}, err
	}
	bytesCount = clampSpeedBytes(bytesCount)
	kind := strings.ToLower(strings.TrimSpace(p.NodeKind))
	if kind == "external" || p.External != nil {
		return routedSpeedResult{}, errors.New("private Router VPN throughput benchmark is unavailable for an external-only node")
	}
	if strings.TrimSpace(p.RouterAPI) == "" || strings.TrimSpace(p.APIToken) == "" {
		return routedSpeedResult{}, errors.New("node has no private benchmark API/token")
	}
	client := newPrivateBenchmarkHTTPClient(30 * time.Second)
	defer client.CloseIdleConnections()
	base := strings.TrimRight(p.RouterAPI, "/")

	downloadURL := base + "/api/benchmark/download?bytes=" + strconv.FormatInt(bytesCount, 10)
	downloadReq, err := privateBenchmarkRequest(http.MethodGet, downloadURL, p.APIToken, nil)
	if err != nil {
		return routedSpeedResult{}, err
	}
	downloadReq = downloadReq.WithContext(ctx)
	downloadReq.Header.Set("Accept-Encoding", "identity")
	downloadStarted := time.Now()
	downloadResp, err := client.Do(downloadReq)
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("download benchmark failed: %w", err)
	}
	downloaded, copyErr := io.Copy(io.Discard, io.LimitReader(downloadResp.Body, bytesCount+1))
	_ = downloadResp.Body.Close()
	if copyErr != nil {
		return routedSpeedResult{}, fmt.Errorf("download benchmark read failed: %w", copyErr)
	}
	if downloadResp.StatusCode/100 != 2 {
		return routedSpeedResult{}, fmt.Errorf("download benchmark returned HTTP %d", downloadResp.StatusCode)
	}
	if downloaded != bytesCount {
		return routedSpeedResult{}, fmt.Errorf("download benchmark returned %d bytes; expected %d", downloaded, bytesCount)
	}
	downloadElapsed := time.Since(downloadStarted)

	payload := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		return routedSpeedResult{}, fmt.Errorf("prepare upload benchmark: %w", err)
	}
	uploadURL := base + "/api/benchmark/upload"
	uploadReq, err := privateBenchmarkRequest(http.MethodPost, uploadURL, p.APIToken, bytes.NewReader(payload))
	if err != nil {
		return routedSpeedResult{}, err
	}
	uploadReq = uploadReq.WithContext(ctx)
	uploadReq.ContentLength = bytesCount
	uploadStarted := time.Now()
	uploadResp, err := client.Do(uploadReq)
	if err != nil {
		return routedSpeedResult{}, fmt.Errorf("upload benchmark failed: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(uploadResp.Body, (64<<10)+1))
	_ = uploadResp.Body.Close()
	if readErr != nil {
		return routedSpeedResult{}, fmt.Errorf("upload benchmark response failed: %w", readErr)
	}
	if uploadResp.StatusCode/100 != 2 {
		return routedSpeedResult{}, fmt.Errorf("upload benchmark returned HTTP %d", uploadResp.StatusCode)
	}
	if len(body) > 64<<10 {
		return routedSpeedResult{}, errors.New("private benchmark upload response is oversized")
	}
	uploadElapsed := time.Since(uploadStarted)
	var ack struct {
		Bytes           int64   `json:"bytes"`
		ServerReceiveMs float64 `json:"server_receive_ms"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return routedSpeedResult{}, fmt.Errorf("upload benchmark proof is invalid: %w", err)
	}
	if ack.Bytes != bytesCount {
		return routedSpeedResult{}, fmt.Errorf("upload benchmark acknowledged %d bytes; expected %d", ack.Bytes, bytesCount)
	}

	if err := ctx.Err(); err != nil {
		return routedSpeedResult{}, err
	}

	mbits := float64(bytesCount*8) / 1_000_000.0
	return routedSpeedResult{
		RouterID: p.ID, Name: p.Name, Bytes: bytesCount,
		DownloadMbps: round3(mbits / downloadElapsed.Seconds()), UploadMbps: round3(mbits / uploadElapsed.Seconds()),
		DownloadMs: round3(float64(downloadElapsed.Microseconds()) / 1000.0), UploadMs: round3(float64(uploadElapsed.Microseconds()) / 1000.0),
		ServerReceiveMs: round3(ack.ServerReceiveMs), MeasuredAt: time.Now().UTC(),
		Proof: "authenticated private router-agent transfer to this node through the unchanged current client routing graph; not derived from RTT or another hop",
	}, nil
}

func validateRoutedSpeedSession(a *app, st state, sessionID string) error {
	currentSession := sessionTrackerFor(a).snapshot(0)
	if !st.Connected || strings.TrimSpace(st.Phase) != "connected" || strings.TrimSpace(st.RouterID) == "" || currentSession.RouterID != st.RouterID || sessionID == "" || currentSession.ID != sessionID || !currentSession.Connected || currentSession.Phase != "connected" || currentSession.PathProof != "passed" {
		return errors.New("VPN session changed while routed throughput was running; stale result was discarded")
	}
	a.mu.Lock()
	currentState := a.state
	a.mu.Unlock()
	if activeTelemetryPathToken(currentState) != activeTelemetryPathToken(st) {
		return errors.New("active VPN node/mode/base/path changed while routed throughput was running; stale result was discarded")
	}
	return nil
}

// All standalone routed speed endpoints share Speed Lab's joined observer.
// Reject unproved sessions before the first transfer, cancel the in-flight load
// on path loss, and synchronously validate again before returning measurements.
// This observes connection ownership; it never stops or replaces the VPN.
func routedSpeedPathContext(parent context.Context, a *app, st state, graph activeMultihopGraph, sessionID string, profiles ...common.RouterProfile) (context.Context, func(), func() error, error) {
	tokens := make(map[string]string)
	for _, p := range profiles {
		tokens[p.ID] = asyncMeasurementProfileToken(p)
	}
	// Entry changes also invalidate an exit-only test: both nodes own the
	// multihop dataplane even when only one lane is being measured.
	a.mu.Lock()
	ids := []string{st.RouterID}
	if st.Mode == "multihop" {
		ids = []string{graph.EntryID, graph.ExitID}
	}
	for _, id := range ids {
		if _, supplied := tokens[id]; !supplied {
			p, ok := a.profileByIDLocked(id)
			if !ok {
				a.mu.Unlock()
				return nil, nil, nil, errors.New("routed throughput node disappeared before measurement")
			}
			tokens[id] = asyncMeasurementProfileToken(p)
		}
	}
	a.mu.Unlock()
	validate := func() error {
		if st.Mode == "multihop" {
			if err := validateCurrentMultihopSpeedGraph(a, st, graph, sessionID); err != nil {
				return err
			}
		} else if err := validateRoutedSpeedSession(a, st, sessionID); err != nil {
			return err
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		for id, token := range tokens {
			p, ok := a.profileByIDLocked(id)
			if !ok || asyncMeasurementProfileToken(p) != token {
				return errors.New("routed throughput node credentials or path policy changed; stale result was discarded")
			}
		}
		return nil
	}
	ctx, stop, err := speedLabPathContext(parent, validate)
	return ctx, stop, validate, err
}

func (a *app) profileSpeedTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q routedSpeedRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	st := a.state
	id := strings.TrimSpace(q.ID)
	if id == "" {
		id = strings.TrimSpace(st.RouterID)
	}
	p, ok := a.profileByIDLocked(id)
	a.mu.Unlock()
	if !st.Connected {
		http.Error(w, "connect Router VPN before testing routed node speed", http.StatusConflict)
		return
	}
	if id == "" {
		http.Error(w, "active VPN node identity is unavailable; refusing to substitute the mutable selected node", http.StatusConflict)
		return
	}
	if st.Mode != "multihop" && id != strings.TrimSpace(st.RouterID) {
		http.Error(w, "requested Router VPN node does not match the active single-hop session; refusing to mislabel routed throughput", http.StatusConflict)
		return
	}
	if !ok {
		http.Error(w, "unknown Router VPN profile", http.StatusNotFound)
		return
	}
	sessionAtStart := sessionTrackerFor(a).snapshot(0).ID
	graph, graphOK := getActiveMultihopGraph(a)
	proxy := ""
	if st.Mode == "multihop" {
		if !graphOK {
			http.Error(w, "active multihop graph identity is unavailable; refusing ambiguous routed node speed", http.StatusConflict)
			return
		}
		if id == graph.EntryID {
			proxy = multihopEntryProofProxy
		} else if id == graph.ExitID {
			proxy = multihopProofProxy
		} else {
			http.Error(w, "requested Router VPN node is not part of the active multihop graph", http.StatusConflict)
			return
		}
	}
	measurementCtx, stopMeasurement, validatePath, err := routedSpeedPathContext(r.Context(), a, st, graph, sessionAtStart, p)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "routed node speed test") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stopMeasurement()

	var value routedSpeedResult
	var measureErr error
	if st.Mode == "multihop" {
		value, measureErr = measureRoutedProfileSpeedViaProxyContext(measurementCtx, p, q.Bytes, proxy)
	} else {
		value, measureErr = measureRoutedProfileSpeedContext(measurementCtx, p, q.Bytes)
	}
	if asyncMeasurementRequestError(w, r.Context(), measurementCtx, "routed node speed test") {
		return
	}
	if err := validatePath(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if measureErr != nil {
		http.Error(w, measureErr.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"connected": true, "mode": st.Mode, "logical_mode": st.LogicalMode, "result": value})
}

func validateActiveMultihopSpeedGraph(st state, graph activeMultihopGraph, graphOK bool, entryID, exitID string) error {
	if !st.Connected || st.Mode != "multihop" {
		return errors.New("connect the actual multihop graph before testing routed hop speed")
	}
	if !graphOK {
		return errors.New("active multihop graph identity is unavailable; refusing to guess hop ownership")
	}
	if graph.EntryID != entryID {
		return fmt.Errorf("requested entry %q does not match active multihop entry %q", entryID, graph.EntryID)
	}
	if graph.ExitID != exitID {
		return fmt.Errorf("requested exit %q does not match active multihop exit %q", exitID, graph.ExitID)
	}
	if st.RouterID != "" && st.RouterID != graph.ExitID {
		return errors.New("active multihop state and tracked exit identity disagree")
	}
	return nil
}

func sameActiveMultihopGraph(a, b activeMultihopGraph) bool {
	return a.EntryID == b.EntryID && a.ExitID == b.ExitID && a.Base == b.Base && a.ExitMode == b.ExitMode && a.Started.Equal(b.Started)
}

func validateCurrentMultihopSpeedGraph(a *app, st state, graph activeMultihopGraph, sessionID string) error {
	if err := validateRoutedSpeedSession(a, st, sessionID); err != nil {
		return err
	}
	a.mu.Lock()
	currentState := a.state
	a.mu.Unlock()
	currentGraph, ok := getActiveMultihopGraph(a)
	if err := validateActiveMultihopSpeedGraph(currentState, currentGraph, ok, graph.EntryID, graph.ExitID); err != nil {
		return err
	}
	if !sameActiveMultihopGraph(currentGraph, graph) {
		return errors.New("active multihop graph changed while routed hop throughput was running; stale results were discarded")
	}
	return nil
}

func (a *app) multihopSpeedTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q routedSpeedRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	entryID, exitID := strings.TrimSpace(q.EntryID), strings.TrimSpace(q.ExitID)
	if entryID == "" || exitID == "" || entryID == exitID {
		http.Error(w, "choose different multihop entry and exit nodes", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	st := a.state
	entry, entryOK := a.profileByIDLocked(entryID)
	exit, exitOK := a.profileByIDLocked(exitID)
	a.mu.Unlock()
	graph, graphOK := getActiveMultihopGraph(a)
	if err := validateActiveMultihopSpeedGraph(st, graph, graphOK, entryID, exitID); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if !entryOK || !exitOK {
		http.Error(w, "unknown multihop entry or exit node", http.StatusNotFound)
		return
	}
	sessionAtStart := sessionTrackerFor(a).snapshot(0).ID
	measurementCtx, stopMeasurement, validatePath, err := routedSpeedPathContext(r.Context(), a, st, graph, sessionAtStart, entry, exit)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "multihop speed test") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stopMeasurement()

	payload := map[string]any{
		"connected": true, "mode": st.Mode, "entry_id": graph.EntryID, "exit_id": graph.ExitID, "bytes": clampSpeedBytes(q.Bytes),
		"measured_at": time.Now().UTC(),
		"note":        "each hop result is an independent authenticated transfer through a reserved local proof lane bound to that hop's cryptographic Router VPN node identity; Router VPN never subtracts or divides another measurement to invent per-hop speed",
	}
	entryValue, entryErr := measureRoutedProfileSpeedViaProxyContext(measurementCtx, entry, q.Bytes, multihopEntryProofProxy)
	if asyncMeasurementRequestError(w, r.Context(), measurementCtx, "multihop speed test") {
		return
	}
	if err := validatePath(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if entryErr == nil {
		payload["entry"] = entryValue
	} else {
		payload["entry_error"] = entryErr.Error()
	}

	exitValue, exitErr := measureRoutedProfileSpeedViaProxyContext(measurementCtx, exit, q.Bytes, multihopProofProxy)
	if asyncMeasurementRequestError(w, r.Context(), measurementCtx, "multihop speed test") {
		return
	}
	if err := validatePath(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if exitErr == nil {
		payload["exit"] = exitValue
		payload["current_path"] = exitValue
	} else {
		payload["exit_error"] = exitErr.Error()
	}
	if entryErr != nil && exitErr != nil {
		http.Error(w, "neither exact multihop hop proof lane could complete its private benchmark", http.StatusBadGateway)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}
