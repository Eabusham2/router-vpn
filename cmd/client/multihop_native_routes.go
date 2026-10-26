package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func registerDesktopMultihopRoutes(h *http.ServeMux, a *app) {
	registerPairingRoute(h, a)
	registerPlatformStandardExitRoutes(h, a)
	registerExternalProfileRoutes(h, a)
	if runtime.GOOS == "linux" && !retainedNativeMultihopSelected() {
		registerMultihopRoutes(h, a)
		return
	}
	h.HandleFunc("/api/multihop/status", a.nativeMultihopStatus)
	h.HandleFunc("/api/multihop/connect", a.nativeMultihopConnect)
}

func nativeMultihopPlatformSupported() bool {
	return retainedNativeMultihopSelected()
}

func desktopMultihopExitModes() []string {
	if runtime.GOOS == "linux" && !retainedNativeMultihopSelected() {
		return []string{"shadowsocks", "hysteria2"}
	}
	return mobilemultihop.NodeMultihopExitModes()
}

func resolveNativeMultihopSelection(control common.RouterProfile, profiles []common.RouterProfile, q multihopConnectRequest) (multihopSelection, error) {
	if q.Base != "" && q.Base != "auto" && q.Base != "wg" && q.Base != "awg" {
		return multihopSelection{}, errors.New("native multihop entry base must be Auto, WireGuard or AmneziaWG")
	}
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
	// A layer belongs to its saved node. Both selected nodes are fully compiled
	// below; a third control profile cannot supply a substitute layer.
	if control.ID != entry.ID && control.ID != exit.ID {
		if err := validateMultihopStartLayer(control); err != nil {
			return multihopSelection{}, err
		}
	}
	if (entry.NodeKind != "" && entry.NodeKind != "router-vpn") || (exit.NodeKind != "" && exit.NodeKind != "router-vpn") {
		return multihopSelection{}, errors.New("Router VPN node-to-node multihop requires Router VPN entry and exit profiles; use External Connect when the exit is a custom external node")
	}
	if strings.TrimSpace(entry.Endpoint) == "" || strings.TrimSpace(exit.Endpoint) == "" {
		return multihopSelection{}, errors.New("both multihop nodes need public endpoints")
	}
	base := resolveMultihopEntryBase(control, entry, q.Base)
	if base != "wg" && base != "awg" {
		return multihopSelection{}, errors.New("native desktop multihop requires a captured WireGuard or AmneziaWG entry")
	}
	exitMode := strings.TrimSpace(q.ExitMode)
	if exitMode == "auto" && q.Execution == "auto" {
		exitMode = "shadowsocks"
	}
	if exitMode == "" {
		exitMode = "shadowsocks"
	}
	if !mobilemultihop.NodeMultihopExitMode(exitMode) {
		return multihopSelection{}, errors.New("native desktop multihop requires a supported complete exit transport")
	}
	return multihopSelection{Control: control, Entry: entry, Exit: exit, Base: base, ExitMode: exitMode}, nil
}

func (a *app) nativeMultihopStatus(w http.ResponseWriter, r *http.Request) {
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
	entryID, exitID := control.MultihopEntryID, control.MultihopExitID
	actualEntry, actualExit, actualBase, actualMode := "", "", "", ""
	if state.Mode == "multihop" && graphOK {
		entryID, exitID = graph.EntryID, graph.ExitID
		actualEntry, actualExit = graph.EntryID, graph.ExitID
		actualBase, actualMode = graph.Base, graph.ExitMode
	}
	store, storeErr := loadStandardExitStore()
	standard := []standardExitSummary{}
	if storeErr == nil {
		for _, e := range store.Exits {
			standard = append(standard, standardExitSummaryFor(e))
		}
	}
	external := make([]map[string]any, 0)
	for _, p := range profiles {
		if p.NodeKind == "external" && p.External != nil {
			external = append(external, map[string]any{"id": p.ID, "name": p.Name, "protocol": p.External.Protocol, "endpoint": p.Endpoint, "expected_public_ip": p.External.ExpectedPublicIP, "location": p.Location, "latitude": p.Latitude, "longitude": p.Longitude})
		}
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"platform":                   runtime.GOOS,
		"platform_supported":         nativeMultihopPlatformSupported(),
		"entry_id":                   entryID,
		"exit_id":                    exitID,
		"configured_entry_id":        control.MultihopEntryID,
		"configured_exit_id":         control.MultihopExitID,
		"actual_entry_id":            actualEntry,
		"actual_exit_id":             actualExit,
		"enabled":                    control.MultihopEnabled,
		"comparison":                 comparisonProgress(a),
		"execution":                  graph.Execution,
		"supported_executions":       []string{"local", "server", "auto"},
		"supported_entry_bases":      []string{"wg", "awg"},
		"supported_exit_modes":       mobilemultihop.NodeMultihopExitModes(),
		"standard_exit_capabilities": externalProfileProtocolCapabilities(),
		"standard_exits":             standard,
		"external_profiles":          external,
		"standard_exit_store_error": func() string {
			if storeErr != nil {
				return storeErr.Error()
			}
			return ""
		}(),
		"connected":          state.Connected && state.Mode == "multihop" && graphOK,
		"runtime_entry_base": actualBase,
		"runtime_entry_mode": graph.EntryMode,
		"runtime_exit_mode":  actualMode,
		"nodes":              multihopNodeSummaries(profiles),
	})
}

func nativeMultihopPlatformCommand(a *app, sel multihopSelection) (*desktopNodeLaunch, error) {
	switch runtime.GOOS {
	case "windows":
		return nativeWindowsMultihopCommand(a, sel)
	case "darwin":
		return nativeDarwinMultihopCommand(a, sel)
	case "linux":
		return prepareOwnedNativeMultihopCommand(a, sel, nil)
	default:
		return nil, errors.New("native multihop has no retained desktop runtime on this platform")
	}
}

func (a *app) nativeMultihopConnect(w http.ResponseWriter, r *http.Request) {
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
	if !nativeMultihopPlatformSupported() {
		http.Error(w, "real multihop is unavailable on this platform instead of faking a chain", http.StatusNotImplemented)
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
	if control.NodeKind == "external" {
		http.Error(w, "selected node is external; use External Connect for direct or Router VPN-entry -> external-exit chaining", http.StatusBadRequest)
		return
	}
	sel, err := resolveNativeMultihopSelection(control, profiles, q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if execution, err := routeExecution(q); err != nil {
		http.Error(w, err.Error(), 400)
		return
	} else if execution != "local" {
		a.runMultihopExecution(w, r, sel, q)
		return
	}

	network := physicalNetworkIdentity()
	if network == "" {
		http.Error(w, "could not capture the physical multihop network", http.StatusConflict)
		return
	}
	sel, err = captureNativeMultihopForApp(a, sel, []string{sel.ExitMode})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	native, err := preflightOwnedNativeMultihopCommand(a, sel, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer func() { _ = retireUnstartedNativeMultihop(native) }()
	if network != physicalNetworkIdentity() || a.checkConnectionOperation() != nil {
		http.Error(w, "multihop network or request changed before launch", http.StatusConflict)
		return
	}

	// Preserve any existing graph until its owning runtime has actually stopped.
	// Failed teardown must keep exact entry/exit identity available for recovery.
	sessionTrackerFor(a).declareRequest("multihop", sel.Base)
	if err = a.stopMode(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if network != physicalNetworkIdentity() {
		err = errors.New("multihop physical network changed during prior cleanup")
	} else {
		err = stageOwnedNativeMultihopCommand(a, sel, native)
	}
	if err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cmd := native.command
	if err = a.checkConnectionOperation(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err = cmd.Start(); err != nil {
		a.mu.Lock()
		a.state.Phase = "failed"
		a.state.LastError = err.Error()
		a.state.Connected = false
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	desktopNodeOwners.Store(a, native)
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
	if err = bindNativeMultihopRuntime(a, native, sel, network); err != nil {
		message, _ := a.multihopStopFailure(cmd, err.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		http.Error(w, message, http.StatusConflict)
		return
	}
	if err = a.checkConnectionOperation(); err != nil {
		message, cleanupFailed := a.multihopStopFailure(cmd, err.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}
	proofErr := a.proveNativeMultihop(sel, cmd)
	if cancelErr := a.checkConnectionOperation(); cancelErr != nil {
		message, cleanupFailed := a.multihopStopFailure(cmd, cancelErr.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}
	if proofErr != nil {
		msg, cleanupFailed := a.multihopStopFailure(cmd, "multihop entry/exit proof failed: "+proofErr.Error())
		a.mu.Lock()
		a.state.Mode = "multihop"
		a.state.LogicalMode = "multihop"
		a.state.RuntimeMode = sel.ExitMode
		a.state.Base = sel.Base
		a.state.RouterID = sel.Exit.ID
		a.state.Phase = "failed"
		a.state.LastError = msg
		a.state.Connected = false
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(msg)
		status := http.StatusBadGateway
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, msg, status)
		return
	}
	a.mu.Lock()
	if a.cmd != cmd {
		a.mu.Unlock()
		retireNativeMultihopGraph(a, native)
		sessionTrackerFor(a).markRequestFailure("multihop runtime changed during exit proof")
		http.Error(w, "multihop runtime changed during exit proof", http.StatusConflict)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	a.state.Connected = true
	a.state.Phase = "connected"
	a.state.LastError = ""
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == sel.Entry.ID || a.profiles.Profiles[i].ID == sel.Exit.ID {
			a.profiles.Profiles[i].UseCount++
			a.profiles.Profiles[i].LastUsedAt = now
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	}
	a.mu.Unlock()
	if persistErr != nil {
		message, cleanupFailed := a.multihopStopFailure(cmd, "native multihop usage persistence failed: "+persistErr.Error())
		if !cleanupFailed {
			message += "; runtime was torn down"
		}
		sessionTrackerFor(a).markRequestFailure(message)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	a.startRouterNodeAutomaticMTU()
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": "multihop", "entry_id": sel.Entry.ID, "entry_name": sel.Entry.Name, "exit_id": sel.Exit.ID, "exit_name": sel.Exit.Name, "entry_base": sel.Base, "entry_mode": sel.Native.entryMode, "exit_mode": sel.ExitMode, "exit_path_proof": "passed-through-exit-only-local-proxy", "route": "client TUN -> captured exit proxy -> captured entry endpoint -> exit node -> Internet"})
}
