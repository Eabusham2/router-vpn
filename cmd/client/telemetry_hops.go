package main

import (
	"bytes"
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

func measureRoutedProfileSpeed(p common.RouterProfile, bytesCount int64) (routedSpeedResult, error) {
	bytesCount = clampSpeedBytes(bytesCount)
	kind := strings.ToLower(strings.TrimSpace(p.NodeKind))
	if kind == "external" || p.External != nil { return routedSpeedResult{}, errors.New("private Router VPN throughput benchmark is unavailable for an external-only node") }
	if strings.TrimSpace(p.RouterAPI) == "" || strings.TrimSpace(p.APIToken) == "" { return routedSpeedResult{}, errors.New("node has no private benchmark API/token") }
	client := &http.Client{Timeout: 30 * time.Second}
	base := strings.TrimRight(p.RouterAPI, "/")

	downloadURL := base + "/api/benchmark/download?bytes=" + strconv.FormatInt(bytesCount, 10)
	downloadReq, err := privateBenchmarkRequest(http.MethodGet, downloadURL, p.APIToken, nil)
	if err != nil { return routedSpeedResult{}, err }
	downloadReq.Header.Set("Accept-Encoding", "identity")
	downloadStarted := time.Now()
	downloadResp, err := client.Do(downloadReq)
	if err != nil { return routedSpeedResult{}, fmt.Errorf("download benchmark failed: %w", err) }
	downloaded, copyErr := io.Copy(io.Discard, io.LimitReader(downloadResp.Body, bytesCount+1))
	_ = downloadResp.Body.Close()
	if copyErr != nil { return routedSpeedResult{}, fmt.Errorf("download benchmark read failed: %w", copyErr) }
	if downloadResp.StatusCode/100 != 2 { return routedSpeedResult{}, fmt.Errorf("download benchmark returned HTTP %d", downloadResp.StatusCode) }
	if downloaded != bytesCount { return routedSpeedResult{}, fmt.Errorf("download benchmark returned %d bytes; expected %d", downloaded, bytesCount) }
	downloadElapsed := time.Since(downloadStarted)

	payload := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil { return routedSpeedResult{}, fmt.Errorf("prepare upload benchmark: %w", err) }
	uploadURL := base + "/api/benchmark/upload"
	uploadReq, err := privateBenchmarkRequest(http.MethodPost, uploadURL, p.APIToken, bytes.NewReader(payload))
	if err != nil { return routedSpeedResult{}, err }
	uploadReq.ContentLength = bytesCount
	uploadStarted := time.Now()
	uploadResp, err := client.Do(uploadReq)
	if err != nil { return routedSpeedResult{}, fmt.Errorf("upload benchmark failed: %w", err) }
	body, readErr := io.ReadAll(io.LimitReader(uploadResp.Body, 64<<10))
	_ = uploadResp.Body.Close()
	if readErr != nil { return routedSpeedResult{}, fmt.Errorf("upload benchmark response failed: %w", readErr) }
	if uploadResp.StatusCode/100 != 2 { return routedSpeedResult{}, fmt.Errorf("upload benchmark returned HTTP %d", uploadResp.StatusCode) }
	uploadElapsed := time.Since(uploadStarted)
	var ack struct {
		Bytes           int64   `json:"bytes"`
		ServerReceiveMs float64 `json:"server_receive_ms"`
	}
	if err := json.Unmarshal(body, &ack); err != nil { return routedSpeedResult{}, fmt.Errorf("upload benchmark proof is invalid: %w", err) }
	if ack.Bytes != bytesCount { return routedSpeedResult{}, fmt.Errorf("upload benchmark acknowledged %d bytes; expected %d", ack.Bytes, bytesCount) }

	mbits := float64(bytesCount*8) / 1_000_000.0
	return routedSpeedResult{
		RouterID: p.ID, Name: p.Name, Bytes: bytesCount,
		DownloadMbps: round3(mbits / downloadElapsed.Seconds()), UploadMbps: round3(mbits / uploadElapsed.Seconds()),
		DownloadMs: round3(float64(downloadElapsed.Microseconds()) / 1000.0), UploadMs: round3(float64(uploadElapsed.Microseconds()) / 1000.0),
		ServerReceiveMs: round3(ack.ServerReceiveMs), MeasuredAt: time.Now().UTC(),
		Proof: "authenticated private router-agent transfer to this node through the current client routing graph; not derived from RTT or another hop",
	}, nil
}

func (a *app) profileSpeedTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var q routedSpeedRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil && !errors.Is(err, io.EOF) { http.Error(w, "bad json", http.StatusBadRequest); return }
	a.mu.Lock()
	st := a.state
	id := strings.TrimSpace(q.ID)
	if id == "" { id = a.profiles.SelectedID; if st.Mode == "multihop" && st.RouterID != "" { id = st.RouterID } }
	p, ok := a.profileByIDLocked(id)
	a.mu.Unlock()
	if !st.Connected { http.Error(w, "connect Router VPN before testing routed node speed", http.StatusConflict); return }
	if !ok { http.Error(w, "unknown Router VPN profile", http.StatusNotFound); return }
	value, err := measureRoutedProfileSpeed(p, q.Bytes)
	if err != nil { http.Error(w, err.Error(), http.StatusBadGateway); return }
	w.Header().Set("content-type", "application/json"); w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"connected": true, "mode": st.Mode, "logical_mode": st.LogicalMode, "result": value})
}

func validateActiveMultihopSpeedGraph(st state, graph activeMultihopGraph, graphOK bool, entryID, exitID string) error {
	if !st.Connected || st.Mode != "multihop" { return errors.New("connect the actual multihop graph before testing routed hop speed") }
	if !graphOK { return errors.New("active multihop graph identity is unavailable; refusing to guess hop ownership") }
	if graph.EntryID != entryID { return fmt.Errorf("requested entry %q does not match active multihop entry %q", entryID, graph.EntryID) }
	if graph.ExitID != exitID { return fmt.Errorf("requested exit %q does not match active multihop exit %q", exitID, graph.ExitID) }
	if st.RouterID != "" && st.RouterID != graph.ExitID { return errors.New("active multihop state and tracked exit identity disagree") }
	return nil
}

func (a *app) multihopSpeedTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var q routedSpeedRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
	entryID, exitID := strings.TrimSpace(q.EntryID), strings.TrimSpace(q.ExitID)
	if entryID == "" || exitID == "" || entryID == exitID { http.Error(w, "choose different multihop entry and exit nodes", http.StatusBadRequest); return }
	a.mu.Lock(); st := a.state; entry, entryOK := a.profileByIDLocked(entryID); exit, exitOK := a.profileByIDLocked(exitID); a.mu.Unlock()
	graph, graphOK := getActiveMultihopGraph(a)
	if err := validateActiveMultihopSpeedGraph(st, graph, graphOK, entryID, exitID); err != nil { http.Error(w, err.Error(), http.StatusConflict); return }
	if !entryOK || !exitOK { http.Error(w, "unknown multihop entry or exit node", http.StatusNotFound); return }

	payload := map[string]any{
		"connected": true, "mode": st.Mode, "entry_id": graph.EntryID, "exit_id": graph.ExitID, "bytes": clampSpeedBytes(q.Bytes),
		"measured_at": time.Now().UTC(),
		"note": "each hop result is an independent authenticated transfer to that hop's private router-agent through the active routing graph; Router VPN never subtracts or divides another measurement to invent per-hop speed",
	}
	entryValue, entryErr := measureRoutedProfileSpeed(entry, q.Bytes)
	if entryErr == nil { payload["entry"] = entryValue } else { payload["entry_error"] = entryErr.Error() }
	exitValue, exitErr := measureRoutedProfileSpeed(exit, q.Bytes)
	if exitErr == nil { payload["exit"] = exitValue; payload["current_path"] = exitValue } else { payload["exit_error"] = exitErr.Error() }
	if entryErr != nil && exitErr != nil { http.Error(w, "neither multihop node private benchmark is reachable through the active graph", http.StatusBadGateway); return }
	w.Header().Set("content-type", "application/json"); w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}
