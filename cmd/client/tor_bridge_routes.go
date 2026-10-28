package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"strings"

	"router-vpn/internal/common"
)

func (a *app) torBridgeStopFailure(cmd *exec.Cmd, cause string) (string, bool) {
	if cleanupErr := a.stopOwnedConnectionRuntime(cmd); cleanupErr != nil {
		return cause + "; runtime cleanup failed: " + cleanupErr.Error(), true
	}
	return cause, false
}

type torBridgeConnectRequest = externalProfileConnectRequest

func registerTorBridgeRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/tor-bridge/capabilities", a.torBridgeCapabilities)
	h.HandleFunc("/api/tor-bridge/import", a.torBridgeImport)
	h.HandleFunc("/api/tor-bridge/connect", a.torBridgeConnect)
	registerStartLayerRoutes(h, a)
}

func (a *app) torBridgeConnect(w http.ResponseWriter, r *http.Request) {
	a.torBridgeConnectWithRuntime(w, r, desktopTorConnectRuntime{})
}

func (a *app) torBridgeConnectWithRuntime(w http.ResponseWriter, r *http.Request, driver desktopTorConnectRuntime) {
	driver.requestContext = r.Context()
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
	q, err := decodeExternalProfileConnectRequest(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	profileID := strings.TrimSpace(q.ProfileID)
	if !validProfileID(profileID) {
		http.Error(w, "Tor bridge connect requires an explicit valid profile_id", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(profileID)
	profile = cloneRouterProfile(profile)
	expectationErr := a.validateExternalProfileExpectedProfilesLocked(q, profile)
	a.mu.Unlock()
	if expectationErr != nil {
		http.Error(w, expectationErr.Error(), http.StatusConflict)
		return
	}
	if !ok {
		http.Error(w, "Tor bridge profile not found", http.StatusNotFound)
		return
	}
	a.torBridgeConnectSelectionOwned(w, profile, q, nil, driver)
}

// torBridgeConnectOwned assumes the caller already owns beginConnectionOperation.
// This lets the unified external-profile route dispatch Tor without nested locks.
func (a *app) torBridgeConnectOwned(w http.ResponseWriter, profile common.RouterProfile) {
	a.torBridgeConnectCapturedOwned(w, profile, nil)
}

func (a *app) torBridgeConnectCapturedOwned(w http.ResponseWriter, profile common.RouterProfile, startup *startupPolicyCapture) {
	a.torBridgeConnectSelectionOwned(w, profile, externalProfileConnectRequest{ProfileID: profile.ID}, startup, desktopTorConnectRuntime{})
}

func (a *app) torBridgeConnectSelectionOwned(w http.ResponseWriter, profile common.RouterProfile, q externalProfileConnectRequest, startup *startupPolicyCapture, driver desktopTorConnectRuntime) {
	if startup != nil {
		if err := startup.current(a); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	a.mu.Lock()
	operation, selected := a.connectionContext, a.profiles.SelectedID
	operationErr := desktopTorOperationCurrentLocked(a, operation, selected)
	a.mu.Unlock()
	if operationErr != nil {
		http.Error(w, operationErr.Error(), http.StatusConflict)
		return
	}
	lookup := driver.lookup
	if lookup == nil {
		lookup = desktopTorEndpointLookup
	}
	execution, err := desktopTorRequestedExecution(profile, q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if execution == "auto" && driver.startupExecution == "" {
		a.torBridgeCompareSelectionOwned(w, profile, q, startup, driver)
		return
	}
	capturedRequest := cloneDesktopTorConnectRequest(q)
	if driver.startupExecution != "" {
		if startup == nil || a.retainedExternalStartupExecution(startup) != driver.startupExecution ||
			desktopTorExecution(driver.startupExecution) == "" || execution != "auto" && execution != driver.startupExecution {
			http.Error(w, "retained Tor execution differs from its captured Startup Last proof", http.StatusConflict)
			return
		}
		capturedRequest.Execution = driver.startupExecution
	}
	selection, err := captureDesktopTorSelection(a, profile, capturedRequest, lookup)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	selection.preference = execution
	if driver.capability == nil {
		driver.capability = func() standardExitCapability { return desktopTorPolicyRuntimeCapability(selection.policy) }
	}
	cap := driver.capability()
	if !cap.Supported {
		http.Error(w, cap.Reason, http.StatusNotImplemented)
		return
	}
	policy := selection.policy
	cmd, prelaunch, err := prepareTorBridgeCommandWithRuntime(a, policy, profile, selection.predecessor, driver)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	check := func() error {
		if err := a.checkConnectionOperation(); err != nil {
			return err
		}
		a.mu.Lock()
		operationErr := desktopTorOperationCurrentLocked(a, operation, selected)
		a.mu.Unlock()
		if operationErr != nil {
			return operationErr
		}
		if err := selection.current(a); err != nil {
			return err
		}
		if err := a.validateExternalProfileExpectedProfiles(q, profile); err != nil {
			return err
		}
		if startup != nil {
			return startup.current(a)
		}
		return nil
	}
	if err := check(); err != nil {
		failure := errors.Join(err, prelaunch.cleanup())
		prelaunch.close()
		http.Error(w, failure.Error(), http.StatusConflict)
		return
	}
	sessionBase := "tor"
	if selection.predecessor != nil {
		sessionBase = desktopExternalEntryBase(selection.predecessor.mode)
	}
	sessionTrackerFor(a).declareRequest("external-node", sessionBase)
	if err = a.stopModeWithIntent(true); err != nil {
		failure := errors.Join(err, prelaunch.cleanup())
		prelaunch.close()
		sessionTrackerFor(a).markRequestFailure(failure.Error())
		http.Error(w, failure.Error(), http.StatusInternalServerError)
		return
	}
	err = prelaunch.start(check)
	if err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		status := http.StatusInternalServerError
		if errors.Is(err, errTorPrelaunchRejected) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	a.mu.Lock()
	a.cmd = cmd
	a.state.Mode = "external-node"
	a.state.LogicalMode = "external-node"
	a.state.RuntimeMode = prelaunch.workspace.mode
	a.state.Base = sessionBase
	a.state.RouterID = profile.ID
	a.state.Connected = false
	a.state.Phase = profile.External.Protocol + ":bootstrapping"
	a.state.LastError = ""
	a.mu.Unlock()
	if err = check(); err != nil {
		message, cleanupFailed := a.torBridgeStopFailure(cmd, err.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}

	a.mu.Lock()
	if a.cmd == cmd {
		a.state.Phase = profile.External.Protocol + ":proving-exit"
	}
	a.mu.Unlock()
	actualIP, proofErr := a.proveTorBridgeExit()
	if cancelErr := check(); cancelErr != nil {
		message, cleanupFailed := a.torBridgeStopFailure(cmd, cancelErr.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}
	if proofErr != nil {
		message, cleanupFailed := a.torBridgeStopFailure(cmd, "Tor bridge public-exit proof failed: "+proofErr.Error())
		a.mu.Lock()
		a.state.Mode = "external-node"
		a.state.LogicalMode = "external-node"
		a.state.RuntimeMode = prelaunch.workspace.mode
		a.state.Base = sessionBase
		a.state.RouterID = profile.ID
		a.state.Connected = false
		a.state.Phase = "failed"
		a.state.LastError = message
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusBadGateway
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}

	retainedProof, retainedErr := a.readDesktopTorProof(prelaunch.workspace)
	if retainedErr == nil {
		retainedErr = check()
	}
	if retainedErr != nil {
		message, cleanupFailed := a.torBridgeStopFailure(cmd, "Tor native path retired before result adoption: "+retainedErr.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}
	saved, saveErr := a.commitDesktopTorChoice(selection, prelaunch.workspace, q, startup, operation, selected, actualIP)
	if saveErr != nil {
		message, cleanupFailed := a.torBridgeStopFailure(cmd, saveErr.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusConflict
		if cleanupFailed || errors.Is(saveErr, errDesktopTorChoiceSave) {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}
	retainedProof, err = saved.adopt(a)
	if err != nil {
		message, cleanupFailed := a.torBridgeStopFailure(cmd, "Tor path choice was saved, but the runtime could not be retained: "+err.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}

	a.monitorDesktopTorRuntime(prelaunch.workspace)
	a.startDesktopExternalAutomaticMTU(prelaunch.workspace)
	writeDesktopTorConnectedResponse(w, selection, retainedProof, nil)
}

func writeDesktopTorConnectedResponse(w http.ResponseWriter, selection *desktopTorSelection, retainedProof desktopTorProof, comparison any) {
	policy, profile := selection.policy, selection.profile
	transport, transportPath := "tor", "authenticated native guard proxy"
	if policy.External.TorBridge != nil {
		transport = strings.TrimSpace(policy.External.TorBridge.Transport)
		if transport == "" {
			transport = "custom"
		}
		transportPath = transport + " circumvention transport"
	}
	entryID, entryMode := "", ""
	route := "client full-device TUN -> local Tor SOCKS -> " + transportPath + " -> Tor circuit -> dynamic Tor exit -> Internet"
	if selection.predecessor != nil {
		entryID, entryMode = selection.predecessor.entry.ID, selection.predecessor.mode
		route = "client full-device TUN -> captured Router " + entryMode + " entry -> " + transportPath + " -> Tor circuit -> dynamic Tor exit -> Internet"
	}
	if policy.MultihopExecution == "server" {
		route = "client full-device TUN -> captured Router " + entryMode + " entry -> authenticated private Server lease -> " + transportPath + " -> Tor circuit -> dynamic Tor exit -> Internet"
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	response := map[string]any{
		"ok":                true,
		"mode":              "external-node",
		"profile_id":        profile.ID,
		"profile_name":      profile.Name,
		"protocol":          profile.External.Protocol,
		"tor_transport":     transport,
		"direct":            selection.predecessor == nil,
		"entry_id":          entryID,
		"entry_mode":        entryMode,
		"execution":         desktopTorExecution(retainedProof.Policy.Execution),
		"choice_saved":      true,
		"actual_public_ip":  retainedProof.Proof.IP,
		"actual_exit_proof": "tor-project-is-tor-passed",
		"dns_mode":          policy.DNSMode,
		"interface_name":    retainedProof.InterfaceName,
		"interface_index":   retainedProof.InterfaceIndex,
		"interface_mtu":     retainedProof.EffectiveMTU,
		"mtu_source":        "native-interface-readback",
		"route":             route,
	}
	response["execution_preference"] = selection.preference
	if comparison != nil {
		response["comparison"] = comparison
		response["last_node_measurement"] = "tor-last-relay-http"
		response["external_measurement"] = "same-captured-endpoint-http"
	}
	_ = json.NewEncoder(w).Encode(response)
}
