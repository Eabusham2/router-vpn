package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/exec"
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

func nativeNodeChainPlatformSupported() bool {
	return retainedNativeMultihopSelected() && (runtime.GOOS == "windows" || runtime.GOOS == "linux")
}

func desktopMultihopExitModes() []string {
	if runtime.GOOS == "linux" && !retainedNativeMultihopSelected() {
		return []string{"shadowsocks", "hysteria2"}
	}
	return mobilemultihop.NodeMultihopExitModes()
}

func resolveNativeMultihopSelection(control common.RouterProfile, profiles []common.RouterProfile, q multihopConnectRequest) (multihopSelection, error) {
	if q.ordered() {
		if err := q.validateOrdered(); err != nil {
			return multihopSelection{}, err
		}
		return resolveDesktopNodeChainSelection(control, profiles, q.Nodes, q.Execution)
	}
	if err := guardLegacyOrderedNodeDispatch(control); err != nil {
		return multihopSelection{}, err
	}
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
	if entry.NodeKind == "external" {
		return resolveDesktopImportedSelection(control, entry, exit, q)
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
	entryMode, base, err := resolveNativeMultihopEntryMode(control, entry, q.EntryMode, q.Base)
	if err != nil {
		return multihopSelection{}, err
	}
	exitMode := strings.TrimSpace(q.ExitMode)
	if exitMode == "auto" && q.Execution == "auto" {
		exitMode = "shadowsocks"
	}
	if exitMode == "" {
		exitMode = "shadowsocks"
	}
	if !nativeMultihopExitMode(exitMode) {
		return multihopSelection{}, errors.New("native desktop multihop requires a supported complete exit transport")
	}
	return multihopSelection{Control: control, Entry: entry, Exit: exit, Base: base, EntryMode: entryMode, ExitMode: exitMode}, nil
}

func (a *app) nativeMultihopStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	profiles := cloneRouterProfileStore(a.profiles).Profiles
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
			external = append(external, map[string]any{"id": p.ID, "profile_token": publicProfileToken(p), "name": p.Name, "protocol": p.External.Protocol, "endpoint": p.Endpoint, "expected_public_ip": p.External.ExpectedPublicIP, "location": p.Location, "latitude": p.Latitude, "longitude": p.Longitude})
		}
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"platform":                   runtime.GOOS,
		"platform_supported":         nativeMultihopPlatformSupported(),
		"ordered_nodes_supported":    nativeNodeChainPlatformSupported(),
		"ordered_prefix_modes":       []string{"wg", "awg2-fast", "awg2-strong"},
		"ordered_exit_modes":         []string{"shadowsocks", "hysteria2"},
		"ordered_executions":         []string{"local"},
		"ordered_max_nodes":          common.MultihopMaximumNodes,
		"entry_id":                   entryID,
		"exit_id":                    exitID,
		"configured_entry_id":        control.MultihopEntryID,
		"configured_entry_mode":      control.MultihopEntryMode,
		"configured_exit_id":         control.MultihopExitID,
		"actual_entry_id":            actualEntry,
		"actual_exit_id":             actualExit,
		"enabled":                    control.MultihopEnabled,
		"comparison":                 comparisonProgress(a),
		"execution":                  graph.Execution,
		"supported_executions":       []string{"local", "server", "auto"},
		"supported_entry_bases":      []string{"wg", "awg"},
		"supported_entry_modes":      append(mobilemultihop.NodeMultihopEntryModes(), "socks5", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn"),
		"paired_entry_modes":         mobilemultihop.NodeMultihopEntryModes(),
		"imported_entry_executions":  []string{"local"},
		"imported_entry_protocols":   []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn"},
		"imported_final_modes":       []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3"},
		"imported_entry_constraint":  "Requires a compatible captured path; SOCKS5 UDP paths currently require Windows with VPN protection enabled",
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

// Tests may model installed-image and proof boundaries while retaining the
// shipping selection, staging, process, graph and teardown transaction.
type nativeMultihopConnectRuntime struct {
	capture   func(*app, multihopSelection, []string) (multihopSelection, error)
	preflight func(*app, multihopSelection, *desktopExecutionDescriptor) (*desktopNodeLaunch, error)
	stage     func(*app, multihopSelection, *desktopNodeLaunch) error
	proof     func(*app, multihopSelection, *exec.Cmd) error
}

func (a *app) nativeMultihopConnect(w http.ResponseWriter, r *http.Request) {
	a.nativeMultihopConnectOwned(w, r, nativeMultihopConnectRuntime{
		capture: captureNativeMultihopForApp, preflight: preflightOwnedNativeMultihopCommand,
		stage: stageOwnedNativeMultihopCommand, proof: (*app).proveNativeMultihop,
	})
}

func (a *app) nativeMultihopConnectOwned(w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime) {
	operation, finish, guardErr := a.beginConnectionOperationContext(r.Context())
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
	q, err := decodeMultihopConnectRequest(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if q.ordered() && (!nativeNodeChainPlatformSupported() || desktopNodeChainHasSOCKS(q.Nodes) && !nativeNodeChainSOCKSPlatformSupported() || desktopNodeChainHasCONNECT(q.Nodes) && !nativeNodeChainCONNECTPlatformSupported()) {
		http.Error(w, "this platform has not enabled its protected ordered native host", http.StatusNotImplemented)
		return
	}
	a.mu.Lock()
	sel, err := a.resolveNativeMultihopRequestLocked(q)
	a.mu.Unlock()
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errDesktopProfileSelectionChanged) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	if execution, err := routeExecution(q); err != nil {
		http.Error(w, err.Error(), 400)
		return
	} else if execution != "local" {
		a.runMultihopExecution(w, r, sel, q)
		return
	}
	a.nativeMultihopConnectLocalOwned(w, r, operation, sel, driver)
}

// Public Connect and the installed native acceptance fixture both enter this
// transaction through the same request decoder and original-source validation.
func (a *app) nativeMultihopConnectLocalOwned(w http.ResponseWriter, r *http.Request, operation context.Context,
	sel multihopSelection, driver nativeMultihopConnectRuntime) {
	if operation == nil || a.checkCapturedConnectionOperation(operation) != nil || driver.capture == nil ||
		driver.preflight == nil || driver.stage == nil || driver.proof == nil {
		http.Error(w, "native Local launch lost its original operation", http.StatusConflict)
		return
	}
	network := physicalNetworkIdentity()
	if network == "" {
		http.Error(w, "could not capture the physical multihop network", http.StatusConflict)
		return
	}
	sel, err := driver.capture(a, sel, []string{sel.ExitMode})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	native, err := driver.preflight(a, sel, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer func() { _ = retireUnstartedNativeMultihop(native) }()
	if network != physicalNetworkIdentity() || a.checkConnectionOperation() != nil {
		http.Error(w, "multihop network or request changed before launch", http.StatusConflict)
		return
	}
	if err := a.guardDesktopOwnedNodeTransition(native); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Preserve any existing graph until its owning runtime has actually stopped.
	// Failed teardown must keep exact entry/exit identity available for recovery.
	tracker := sessionTrackerFor(a)
	tracker.declareRequest("multihop", sel.Base)
	if err = a.stopModeWithIntent(native.ownedNode != nil || desktopMultihopPlatformLaunch(native)); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if network != physicalNetworkIdentity() {
		err = errors.New("multihop physical network changed during prior cleanup")
	} else {
		err = driver.stage(a, sel, native)
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
	protected := native.ownedNode != nil || desktopMultihopPlatformLaunch(native)
	if desktopMultihopPlatformLaunch(native) {
		err = startDesktopMultihopPlatform(operation, a, sel, native)
		cmd = native.command
	} else if protected {
		a.mu.Lock()
		err = a.publishDesktopCapturedMultihopStartLocked(operation, native, sel)
		a.mu.Unlock()
	} else {
		err = cmd.Start()
	}
	if err != nil {
		if desktopMultihopPlatformLaunch(native) {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err = errors.Join(err, closeDesktopMultihopPlatform(cleanup, a, native))
			cancel()
			sessionTrackerFor(a).markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if nativeMultihopLaunchStarted(native) {
			message, _ := a.multihopStopFailure(cmd, err.Error())
			sessionTrackerFor(a).markRequestFailure(message)
			http.Error(w, message, http.StatusInternalServerError)
			return
		}
		a.mu.Lock()
		if !protected || a.connectionContext == operation && a.cmd == nil {
			a.state.Phase = "failed"
			a.state.LastError = err.Error()
			a.state.Connected = false
		}
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !protected {
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
	}
	if _, err = publishDesktopMultihopPlatformGraph(operation, a, native, sel, "local"); err != nil {
		message, _ := a.multihopStopFailure(cmd, err.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		http.Error(w, message, http.StatusConflict)
		return
	}
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
	if protected && !desktopMultihopPlatformLaunch(native) {
		if err := startDesktopCapturedMultihopOwned(operation, operation, a, native); err != nil {
			message, _ := a.multihopStopFailure(cmd, err.Error())
			sessionTrackerFor(a).markRequestFailure(message)
			http.Error(w, message, http.StatusInternalServerError)
			return
		}
	}
	originalRuntime, _ := nativeMultihopOwners.Load(a)
	originalGraph, originalGraphOK := getActiveMultihopGraph(a)
	originalRelay, _ := desktopRelays.Load(a)
	proofErr := driver.proof(a, sel, cmd)
	if proofErr == nil && desktopMultihopPlatformLaunch(native) {
		proofErr = activateDesktopMultihopPlatform(operation, native)
	}
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
		// Cleanup may block while another owner replaces the graph. Adopt both
		// diagnostics and request history only while the original transaction
		// still owns the completed teardown or the exact retained retry graph.
		tracker.mu.Lock()
		a.mu.Lock()
		currentTracker, tracked := sessionTrackers.Load(a)
		currentNode, nodePresent := desktopNodeOwners.Load(a)
		currentRuntime, runtimePresent := nativeMultihopOwners.Load(a)
		currentGraph, graphPresent := getActiveMultihopGraph(a)
		currentRelay, relayPresent := desktopRelays.Load(a)
		owned := tracked && currentTracker == tracker && a.connectionContext == operation
		if cleanupFailed {
			owned = owned && (a.cmd == nil || a.cmd == cmd) &&
				(desktopMultihopPlatformLaunch(native) && !nodePresent || nodePresent && currentNode == native) && runtimePresent && currentRuntime == originalRuntime &&
				originalGraphOK && graphPresent && currentGraph == originalGraph &&
				(!relayPresent || currentRelay == originalRelay)
		} else {
			owned = owned && a.cmd == nil && !nodePresent && !runtimePresent && !graphPresent && !relayPresent
		}
		if !owned {
			a.mu.Unlock()
			tracker.mu.Unlock()
			http.Error(w, "multihop failure cleanup lost its original runtime owner; replacement retained", http.StatusConflict)
			return
		}
		// A joined teardown already set off. Only incomplete cleanup retains
		// the full graph identity needed by the next exact Stop attempt.
		if cleanupFailed {
			a.state.Mode = "multihop"
			a.state.LogicalMode = "multihop"
			a.state.RuntimeMode = sel.ExitMode
			a.state.Base = sel.Base
			a.state.RouterID = sel.Exit.ID
		}
		a.state.Phase = "failed"
		a.state.LastError = msg
		a.state.Connected = false
		tracker.markRequestFailureLocked(msg)
		a.mu.Unlock()
		tracker.mu.Unlock()
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
	used := map[string]bool{sel.Entry.ID: true, sel.Exit.ID: true}
	for _, member := range sel.Nodes {
		used[member.Profile.ID] = true
	}
	for i := range a.profiles.Profiles {
		if used[a.profiles.Profiles[i].ID] {
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
	if sel.Native.chain != nil {
		if err := a.saveNodeChainStartupSelection(operation, native, sel); err != nil {
			log.Printf("Router VPN could not persist the proved ordered startup selection: %v", err)
		}
	}
	a.startRouterNodeAutomaticMTU()
	if protected && !desktopMultihopPlatformLaunch(native) {
		a.monitorDesktopOwnedNodeRuntime(native)
	}
	w.Header().Set("content-type", "application/json")
	route := "client TUN -> captured exit proxy -> captured entry endpoint -> exit node -> Internet"
	proof := "passed-through-exit-only-local-proxy"
	if sel.Native.chain != nil {
		route = "client TUN through every captured node in selected order to the final Internet exit"
		proof = "authenticated-every-prefix-and-final-dns-through-original-native-chain"
	} else if sel.ExitMode == "wg" {
		route = "client TUN -> captured WireGuard exit endpoint -> captured entry endpoint -> exit node -> Internet"
	} else if sel.ExitMode == "awg2-fast" || sel.ExitMode == "awg2-strong" {
		route = "client TUN -> captured AmneziaWG exit endpoint -> captured entry endpoint -> exit node -> Internet"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": "multihop", "entry_id": sel.Entry.ID, "entry_name": sel.Entry.Name, "exit_id": sel.Exit.ID, "exit_name": sel.Exit.Name, "entry_base": sel.Base, "entry_mode": sel.Native.entryMode, "exit_mode": sel.ExitMode, "exit_path_proof": proof, "route": route})
}
