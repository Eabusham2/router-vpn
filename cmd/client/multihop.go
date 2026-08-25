package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

const multihopProofProxy = "http://127.0.0.1:1099"

type multihopConnectRequest struct {
	EntryID  string `json:"entry_id"`
	ExitID   string `json:"exit_id"`
	Base     string `json:"base"`
	ExitMode string `json:"exit_mode"`
}

type multihopSelection struct {
	Control  common.RouterProfile
	Entry    common.RouterProfile
	Exit     common.RouterProfile
	Base     string
	ExitMode string
}

type multihopNodeSummary struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Location        string  `json:"location,omitempty"`
	Endpoint        string  `json:"endpoint,omitempty"`
	BaseTunnel      string  `json:"base_tunnel,omitempty"`
	Latitude        float64 `json:"latitude,omitempty"`
	Longitude       float64 `json:"longitude,omitempty"`
	LatencyMedianMs float64 `json:"latency_median_ms,omitempty"`
	LatencyTrimmed  float64 `json:"latency_trimmed_mean_ms,omitempty"`
	LatencyP90Ms    float64 `json:"latency_p90_ms,omitempty"`
}

// activeMultihopGraph records the graph that was actually launched.  The profile
// fields remain configuration/defaults; they are not used as proof of the live
// graph because callers may supply an explicit entry/exit to /api/multihop/connect.
type activeMultihopGraph struct {
	EntryID  string
	ExitID   string
	Base     string
	ExitMode string
	Started  time.Time
}

var activeMultihopGraphs sync.Map // map[*app]activeMultihopGraph

func setActiveMultihopGraph(a *app, sel multihopSelection) {
	activeMultihopGraphs.Store(a, activeMultihopGraph{
		EntryID: sel.Entry.ID, ExitID: sel.Exit.ID, Base: sel.Base, ExitMode: sel.ExitMode, Started: time.Now().UTC(),
	})
}

func clearActiveMultihopGraph(a *app) { activeMultihopGraphs.Delete(a) }

func getActiveMultihopGraph(a *app) (activeMultihopGraph, bool) {
	value, ok := activeMultihopGraphs.Load(a)
	if !ok {
		return activeMultihopGraph{}, false
	}
	graph, ok := value.(activeMultihopGraph)
	return graph, ok && graph.EntryID != "" && graph.ExitID != "" && graph.EntryID != graph.ExitID
}

func registerMultihopRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/multihop/status", a.multihopStatus)
	h.HandleFunc("/api/multihop/connect", a.multihopConnect)
}

func profileByID(profiles []common.RouterProfile, id string) (common.RouterProfile, bool) {
	for _, p := range profiles {
		if p.ID == id {
			return p, true
		}
	}
	return common.RouterProfile{}, false
}

func multihopNodeSummaries(profiles []common.RouterProfile) []multihopNodeSummary {
	out := make([]multihopNodeSummary, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, multihopNodeSummary{
			ID: p.ID, Name: p.Name, Location: p.Location, Endpoint: p.Endpoint,
			BaseTunnel: p.BaseTunnel, Latitude: p.Latitude, Longitude: p.Longitude,
			LatencyMedianMs: p.LatencyMedianMs, LatencyTrimmed: p.LatencyTrimmedMeanMs,
			LatencyP90Ms: p.LatencyP90Ms,
		})
	}
	return out
}

func resolveMultihopSelection(control common.RouterProfile, profiles []common.RouterProfile, q multihopConnectRequest) (multihopSelection, error) {
	entryID := strings.TrimSpace(q.EntryID)
	exitID := strings.TrimSpace(q.ExitID)
	if entryID == "" {
		entryID = strings.TrimSpace(control.MultihopEntryID)
	}
	if exitID == "" {
		exitID = strings.TrimSpace(control.MultihopExitID)
	}
	if entryID == "" || exitID == "" {
		return multihopSelection{}, errors.New("choose both an entry and an exit node")
	}
	if entryID == exitID {
		return multihopSelection{}, errors.New("multihop entry and exit nodes must be different")
	}
	entry, ok := profileByID(profiles, entryID)
	if !ok {
		return multihopSelection{}, fmt.Errorf("entry node %q is not linked", entryID)
	}
	exit, ok := profileByID(profiles, exitID)
	if !ok {
		return multihopSelection{}, fmt.Errorf("exit node %q is not linked", exitID)
	}
	if strings.TrimSpace(entry.Endpoint) == "" || strings.TrimSpace(exit.Endpoint) == "" {
		return multihopSelection{}, errors.New("both multihop nodes need public endpoints")
	}
	if strings.TrimSpace(entry.SocksHost) == "" || entry.SocksPort <= 0 {
		return multihopSelection{}, errors.New("entry node is missing its private SOCKS5 endpoint")
	}

	base := normalizeBase(q.Base)
	if base == "" || base == "auto" {
		base = normalizeBase(entry.BaseTunnel)
	}
	if base == "" || base == "auto" {
		base = normalizeBase(control.BaseTunnel)
	}
	if base == "" || base == "auto" {
		base = "wg"
	}
	if base != "wg" && base != "awg" {
		return multihopSelection{}, errors.New("multihop entry base must be WireGuard or AmneziaWG")
	}
	exitMode := strings.TrimSpace(q.ExitMode)
	if exitMode == "" {
		exitMode = "shadowsocks"
	}
	if exitMode != "shadowsocks" && exitMode != "hysteria2" {
		return multihopSelection{}, errors.New("first native multihop runtime supports only Shadowsocks or Hysteria2 as the exit transport")
	}
	return multihopSelection{Control: control, Entry: entry, Exit: exit, Base: base, ExitMode: exitMode}, nil
}

func (a *app) multihopStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	state := a.state
	a.mu.Unlock()
	graph, graphOK := getActiveMultihopGraph(a)
	actualEntry, actualExit := "", ""
	entryID, exitID := control.MultihopEntryID, control.MultihopExitID
	if state.Mode == "multihop" && graphOK {
		actualEntry, actualExit = graph.EntryID, graph.ExitID
		entryID, exitID = graph.EntryID, graph.ExitID
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"platform":              runtime.GOOS,
		"platform_supported":    runtime.GOOS == "linux",
		"entry_id":              entryID,
		"exit_id":               exitID,
		"configured_entry_id":   control.MultihopEntryID,
		"configured_exit_id":    control.MultihopExitID,
		"actual_entry_id":       actualEntry,
		"actual_exit_id":        actualExit,
		"enabled":               control.MultihopEnabled,
		"supported_entry_bases": []string{"wg", "awg"},
		"supported_exit_modes":  []string{"shadowsocks", "hysteria2"},
		"connected":             state.Connected && state.Mode == "multihop",
		"runtime_entry_base": func() string {
			if state.Mode == "multihop" && graphOK {
				return graph.Base
			}
			return ""
		}(),
		"runtime_exit_mode": func() string {
			if state.Mode == "multihop" && graphOK {
				return graph.ExitMode
			}
			return ""
		}(),
		"nodes": multihopNodeSummaries(profiles),
	})
}

func multihopCommand(a *app, sel multihopSelection) *exec.Cmd {
	cmd := exec.Command("bash", "run-multihop.sh", sel.Entry.ID, sel.Exit.ID, sel.Base, sel.ExitMode, sel.Control.ID)
	cmd.Dir = a.cfg.ScriptsDir
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	cmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+root)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func (a *app) multihopConnect(w http.ResponseWriter, r *http.Request) {
	_, finish, guardErr := a.beginConnectionOperation()
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer finish()

	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if runtime.GOOS != "linux" {
		http.Error(w, "real multihop is currently implemented on the Linux desktop dataplane only; this platform remains unavailable instead of faking a chain", http.StatusNotImplemented)
		return
	}
	var q multihopConnectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	control, ok := a.profileByIDLocked(a.profiles.SelectedID)
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "select a Router VPN control profile first", http.StatusBadRequest)
		return
	}
	sel, err := resolveMultihopSelection(control, profiles, q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// A new request invalidates any earlier graph identity before the old mode is
	// stopped. The graph is published only after the exact new process starts.
	clearActiveMultihopGraph(a)
	sessionTrackerFor(a).declareRequest("multihop", sel.Base)
	if err := a.stopMode(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cmd := multihopCommand(a, sel)
	if err := cmd.Start(); err != nil {
		a.mu.Lock()
		a.state.Phase = "failed"
		a.state.LastError = err.Error()
		a.state.Connected = false
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	a.cmd = cmd
	a.state.Mode = "multihop"
	a.state.LogicalMode = "multihop"
	a.state.RuntimeMode = sel.ExitMode
	a.state.Base = sel.Base
	a.state.RouterID = sel.Exit.ID
	a.state.Connected = false
	a.state.Phase = "multihop:proving-exit"
	a.state.LastError = ""
	a.mu.Unlock()
	setActiveMultihopGraph(a, sel)

	if err := a.proveMultihopExit(sel.Exit); err != nil {
		_ = a.stopMode()
		a.mu.Lock()
		a.state.Mode = "multihop"
		a.state.LogicalMode = "multihop"
		a.state.RuntimeMode = sel.ExitMode
		a.state.Base = sel.Base
		a.state.RouterID = sel.Exit.ID
		a.state.Phase = "failed"
		a.state.LastError = "multihop exit proof failed: " + err.Error()
		a.state.Connected = false
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure("multihop exit proof failed: " + err.Error())
		http.Error(w, "multihop exit proof failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	if err := a.checkConnectionOperation(); err != nil {
		a.stopOwnedConnectionRuntime(cmd)
		clearActiveMultihopGraph(a)
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.mu.Lock()
	if a.cmd != cmd {
		a.mu.Unlock()
		clearActiveMultihopGraph(a)
		http.Error(w, "multihop runtime changed during exit proof", http.StatusConflict)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	a.state.Connected = true
	a.state.Phase = "connected"
	a.state.LastError = ""
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == sel.Entry.ID || a.profiles.Profiles[i].ID == sel.Exit.ID {
			a.profiles.Profiles[i].UseCount++
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	}
	a.mu.Unlock()
	if persistErr != nil {
		_ = a.stopMode()
		clearActiveMultihopGraph(a)
		sessionTrackerFor(a).markRequestFailure(persistErr.Error())
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":              true,
		"mode":            "multihop",
		"entry_id":        sel.Entry.ID,
		"entry_name":      sel.Entry.Name,
		"exit_id":         sel.Exit.ID,
		"exit_name":       sel.Exit.Name,
		"entry_base":      sel.Base,
		"exit_mode":       sel.ExitMode,
		"exit_path_proof": "passed-through-exit-only-local-proxy",
		"route":           "client -> entry tunnel -> entry private SOCKS5 -> exit transport -> exit node -> Internet",
	})
}

func (a *app) proveMultihopExit(exit common.RouterProfile) error {
	proofURL := strings.TrimSpace(exit.PathProbeURL)
	if proofURL == "" {
		proofURL = a.cfg.HealthURL
	}
	if !trustedPathProbeURL(proofURL) {
		return errors.New("exit path proof URL is not private/local")
	}
	proxyURL, err := url.Parse(multihopProofProxy)
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.ForceAttemptHTTP2 = false
	client := &http.Client{Transport: transport, Timeout: 1200 * time.Millisecond}
	var last error
	deadline := time.Now().Add(9 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, proofURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if readErr == nil && resp.StatusCode/100 == 2 {
				if err := validateSelectedNodeProof(exit, body); err == nil {
					return nil
				} else {
					last = err
				}
			} else if readErr != nil {
				last = readErr
			} else {
				last = fmt.Errorf("exit proof returned HTTP %d", resp.StatusCode)
			}
		} else {
			last = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("exit proof timed out")
	}
	return last
}
