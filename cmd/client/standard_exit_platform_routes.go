package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
)

func registerPlatformStandardExitRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/standard-exits/capabilities", platformStandardExitCapabilitiesHandler)
	h.HandleFunc("/api/standard-exits", standardExitListHandler)
	h.HandleFunc("/api/standard-exit/save", a.guardedStandardExitSave)
	h.HandleFunc("/api/standard-exit/delete", a.guardedStandardExitDelete)
	h.HandleFunc("/api/standard-exit/connect", a.platformStandardExitConnect)
}

func platformStandardExitCapabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": standardExitStoreVersion, "capabilities": externalProfileProtocolCapabilities(), "external_entry_hop": true, "external_entry_protocols": []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"}, "openvpn_entry_hop": false})
}

func standardExitEntry(profiles []common.RouterProfile, control common.RouterProfile, q standardExitConnectRequest) (common.RouterProfile, string, error) {
	if q.Direct {
		return common.RouterProfile{}, "", nil
	}
	entryID := strings.TrimSpace(q.EntryID)
	if entryID == "" {
		entryID = strings.TrimSpace(control.MultihopEntryID)
	}
	if entryID == "" {
		return common.RouterProfile{}, "", errors.New("choose a linked entry node")
	}
	entry, ok := profileByID(profiles, entryID)
	if !ok {
		return common.RouterProfile{}, "", errors.New("entry node is not linked")
	}
	kind := strings.TrimSpace(entry.NodeKind)
	if kind == "" {
		kind = "router-vpn"
	}
	switch kind {
	case "router-vpn":
		base := normalizeBase(q.Base)
		if base != "" && base != "auto" && base != "wg" {
			return common.RouterProfile{}, "", errors.New("Router VPN entry hopping currently requires standard WireGuard")
		}
		if strings.TrimSpace(entry.Endpoint) == "" {
			return common.RouterProfile{}, "", errors.New("Router VPN entry node needs a public endpoint")
		}
	case "external":
		externalEntry, err := standardExitFromExternalProfile(entry)
		if err != nil {
			return common.RouterProfile{}, "", errors.New("invalid external entry: " + err.Error())
		}
		if externalEntry.Protocol == "openvpn" {
			return common.RouterProfile{}, "", errors.New("external OpenVPN is supported as a direct/final exit but not yet as an upstream hop; refusing competing default tunnels")
		}
	default:
		return common.RouterProfile{}, "", errors.New("unsupported entry node kind")
	}
	return entry, kind, nil
}

type platformStandardExitRuntime struct {
	prepareLegacy func(*app, *exec.Cmd, string, string, string) (legacyStandardExitLaunch, error)
	prove         func(*app, string) error
	proveDNS      func(context.Context, legacyStandardExitLaunch) error
	current       func(legacyStandardExitLaunch, context.Context) error
}

func (a *app) platformStandardExitConnect(w http.ResponseWriter, r *http.Request) {
	a.platformStandardExitConnectOwned(w, r, defaultPlatformStandardExitRuntime())
}

func defaultPlatformStandardExitRuntime() platformStandardExitRuntime {
	return platformStandardExitRuntime{
		prepareLegacy: prepareLegacyStandardExitOwner,
		prove:         (*app).proveStandardExitForOperation,
		proveDNS: func(ctx context.Context, owner legacyStandardExitLaunch) error {
			if proof, ok := owner.(interface{ ProveSelectedDNS(context.Context) error }); ok {
				return proof.ProveSelectedDNS(ctx)
			}
			return errors.New("retained standard exit has no original DNS proof capability")
		},
		current: func(owner legacyStandardExitLaunch, ctx context.Context) error { return owner.Current(ctx) },
	}
}

func (a *app) platformStandardExitConnectOwned(w http.ResponseWriter, r *http.Request, adapter platformStandardExitRuntime) {

	operation, finish, guardErr := a.beginConnectionOperation()
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer finish()
	a.platformStandardExitConnectCaptured(w, r, adapter, operation)
}

// Restoration remains inside its already-owned Speed Lab transaction. It cannot
// allocate a second intent or rerun a strategy that chooses another exit.
func (a *app) platformStandardExitConnectCaptured(w http.ResponseWriter, r *http.Request, adapter platformStandardExitRuntime, operation context.Context) {
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		http.Error(w, "custom standard exit runtime is unavailable on this platform instead of faking a connection", http.StatusNotImplemented)
		return
	}
	var q standardExitConnectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	control, ok := a.profileByIDLocked(a.profiles.SelectedID)
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "select a linked policy profile first", http.StatusBadRequest)
		return
	}
	exit, err := standardExitByID(strings.TrimSpace(q.StandardExitID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entry, entryKind, err := standardExitEntry(profiles, control, q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if exit.Protocol == "openvpn" {
		cap := openVPNRuntimeCapability()
		if runtime.GOOS == "windows" {
			cap = windowsOpenVPNRuntimeCapability()
		}
		if !cap.Supported {
			http.Error(w, cap.Reason, http.StatusNotImplemented)
			return
		}
		if !q.Direct && !openVPNProtocolIsTCP(exit.Method) {
			http.Error(w, "OpenVPN final-exit hopping currently supports TCP OpenVPN profiles only; UDP remains fail-closed instead of bypassing the entry", http.StatusBadRequest)
			return
		}
	}
	sessionBase := "external"
	if !q.Direct && entryKind == "router-vpn" {
		sessionBase = "wg"
	}
	tracker := sessionTrackerFor(a)
	tracker.declareRequest("standard-exit", sessionBase)
	// A captured stock standard exit must never run generic global release before
	// its original protection admission or succession. Existing owned runtimes still join normally.
	holdProtection := runtime.GOOS == "linux" && q.Direct && exit.Protocol != "openvpn" && exit.Protocol != "amneziawg" && exit.StartLayer == nil
	reverse, err := captureStandardReverse(operation, a, control, exit, holdProtection)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	var cmd *exec.Cmd
	if reverse != nil {
		defer reverse.DiscardPlanning()
		cmd, err = reverse.PrepareCommand()
		if err != nil {
			tracker.markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err = a.stopModeWithIntent(holdProtection); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if reverse != nil {
		// Use the exact command sealed while the original Node was live.
	} else if exit.Protocol == "openvpn" {
		if runtime.GOOS == "windows" {
			cmd, err = windowsOpenVPNStandardExitCommand(a, control, entry, exit, q.Direct)
		} else {
			cmd, err = openVPNStandardExitCommand(a, control, entry, exit, q.Direct)
		}
	} else if !q.Direct && entryKind == "external" {
		cmd, err = nativeExternalEntryStandardExitCommand(a, control, entry, exit)
	} else {
		cmd, err = nativeStandardExitCommand(a, control, entry, exit, q.Direct)
	}
	if err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stateID := "standard:" + exit.ID
	retained, err := adapter.prepareLegacy(a, cmd, "standard-"+exit.Protocol, sessionBase, stateID)
	if err != nil {
		tracker.markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if reverse != nil {
		if err := reverse.Bind(retained); err != nil {
			if retained != nil {
				_ = retained.Discard()
			}
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	if retained != nil {
		defer retained.Discard()
		if capture, ok := retained.(interface{ CaptureMTUExit(standardExit) error }); ok {
			if err := capture.CaptureMTUExit(exit); err != nil {
				tracker.markRequestFailure(err.Error())
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if capture, ok := retained.(interface {
			CaptureStandardServicePolicy(context.Context, standardExitConnectRequest, common.RouterProfile, standardExit) error
		}); ok {
			if err := capture.CaptureStandardServicePolicy(operation, q, control, exit); err != nil {
				tracker.markRequestFailure(err.Error())
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		cmd = retained.Command()
	}
	markOwnedFailure := func(message string) bool {
		if retained == nil {
			tracker.markRequestFailure(message)
			return true
		}
		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		a.mu.Lock()
		defer a.mu.Unlock()
		current, exists := sessionTrackers.Load(a)
		owned := exists && current == tracker && a.connectionContext == operation &&
			(a.cmd == cmd && legacyStandardExitFailureOwned(a, retained, false) || a.cmd == nil && legacyStandardExitFailureOwned(a, retained, true))
		if owned {
			tracker.markRequestFailureLocked(message)
		}
		return owned
	}
	if err = a.checkCapturedConnectionOperation(operation); err != nil {
		tracker.markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if retained != nil {
		err = retained.Start(operation)
	} else {
		err = cmd.Start()
	}
	if a.ownsConnectionRuntime(cmd) {
		err = errors.Join(err, a.speedLabOwnRuntime(cmd))
	}
	if err != nil {
		message := err.Error()
		if retained != nil && a.ownsConnectionRuntime(cmd) {
			message, _ = a.standardExitStopFailure(cmd, message)
		}
		if retained != nil {
			tracker.mu.Lock()
			a.mu.Lock()
			current, exists := sessionTrackers.Load(a)
			owned := exists && current == tracker && a.connectionContext == operation &&
				(a.cmd == cmd && legacyStandardExitFailureOwned(a, retained, false) || a.cmd == nil && legacyStandardExitFailureOwned(a, retained, true))
			if owned {
				a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
				tracker.markRequestFailureLocked(message)
			}
			a.mu.Unlock()
			tracker.mu.Unlock()
			if !owned {
				http.Error(w, "standard exit Start completion lost its original owner; replacement retained", http.StatusConflict)
				return
			}
		} else {
			tracker.markRequestFailure(message)
		}
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	if retained != nil && (a.cmd != cmd || a.connectionContext != operation || !legacyStandardExitFailureOwned(a, retained, false)) {
		a.mu.Unlock()
		http.Error(w, "standard exit Start lost original owner", http.StatusConflict)
		return
	}
	a.cmd = cmd
	a.state.Mode = "standard-exit"
	a.state.LogicalMode = "standard-exit"
	a.state.RuntimeMode = "standard-" + exit.Protocol
	a.state.Base = sessionBase
	a.state.RouterID = stateID
	a.state.Connected = false
	a.state.Phase = "standard-exit:proving-public-exit"
	a.state.LastError = ""
	a.mu.Unlock()
	if err = a.speedLabOwnRuntime(cmd); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err = a.checkCapturedConnectionOperation(operation); err != nil {
		message, cleanupFailed := a.standardExitStopFailure(cmd, err.Error())
		if !markOwnedFailure(message) {
			http.Error(w, "standard exit cleanup lost original history owner; replacement retained", http.StatusConflict)
			return
		}
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}
	var proofErr error
	if adapter.proveDNS != nil && retained != nil {
		proofErr = adapter.proveDNS(operation, retained)
	}
	if proofErr == nil && exit.Protocol == "openvpn" {
		proofErr = a.proveOpenVPNStandardExitForOperation(exit.ExpectedPublicIP)
	} else if proofErr == nil {
		proofErr = adapter.prove(a, exit.ExpectedPublicIP)
	}
	if proofErr == nil && retained != nil {
		proofErr = adapter.current(retained, operation)
	}
	if cancelErr := a.checkCapturedConnectionOperation(operation); cancelErr != nil {
		message, cleanupFailed := a.standardExitStopFailure(cmd, cancelErr.Error())
		if !markOwnedFailure(message) {
			http.Error(w, "standard exit cleanup lost original history owner; replacement retained", http.StatusConflict)
			return
		}
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}
	if proofErr != nil {
		msg, cleanupFailed := a.standardExitStopFailure(cmd, "standard exit proof failed: "+proofErr.Error())
		tracker.mu.Lock()
		a.mu.Lock()
		currentTracker, tracked := sessionTrackers.Load(a)
		owned := tracked && currentTracker == tracker && a.connectionContext == operation
		if retained != nil {
			if cleanupFailed {
				owned = owned && a.cmd == cmd && legacyStandardExitFailureOwned(a, retained, false)
			} else {
				owned = owned && a.cmd == nil && legacyStandardExitFailureOwned(a, retained, true)
			}
		}
		if !owned {
			a.mu.Unlock()
			tracker.mu.Unlock()
			http.Error(w, "standard exit cleanup lost original request ownership; replacement retained", http.StatusConflict)
			return
		}
		if retained == nil || cleanupFailed {
			a.state.Mode = "standard-exit"
			a.state.LogicalMode = "standard-exit"
			a.state.RuntimeMode = "standard-" + exit.Protocol
			a.state.Base = sessionBase
			a.state.RouterID = stateID
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
	if a.cmd != cmd || a.checkCapturedConnectionOperationLocked(operation) != nil || a.connectionCancelIntent == operation || retained != nil && !legacyStandardExitFailureOwned(a, retained, false) {
		a.mu.Unlock()
		if retained != nil && a.ownsConnectionRuntime(cmd) {
			message, _ := a.standardExitStopFailure(cmd, "standard exit request changed before final adoption")
			markOwnedFailure(message)
		}
		markOwnedFailure("standard exit runtime changed during proof")
		http.Error(w, "standard exit runtime changed during proof", http.StatusConflict)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	a.state.Connected = true
	a.state.Phase = "connected"
	a.state.LastError = ""
	if !q.Direct {
		usedAt := time.Now().UTC().Format(time.RFC3339)
		for i := range a.profiles.Profiles {
			if a.profiles.Profiles[i].ID == entry.ID {
				a.profiles.Profiles[i].UseCount++
				a.profiles.Profiles[i].LastUsedAt = usedAt
			}
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	}
	a.mu.Unlock()
	if persistErr != nil {
		message, cleanupFailed := a.standardExitStopFailure(cmd, "platform standard-exit usage persistence failed: "+persistErr.Error())
		if !cleanupFailed {
			message += "; runtime was torn down"
		}
		if !markOwnedFailure(message) {
			http.Error(w, "standard exit cleanup lost original history owner; replacement retained", http.StatusConflict)
			return
		}
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	if monitor, ok := retained.(interface{ ActivateMonitor(context.Context) error }); ok {
		if err := monitor.ActivateMonitor(operation); err != nil {
			message, _ := a.standardExitStopFailure(cmd, "standard exit monitoring failed: "+err.Error())
			a.mu.Lock()
			owned := a.connectionContext == operation && (a.cmd == cmd && legacyStandardExitFailureOwned(a, retained, false) || a.cmd == nil && legacyStandardExitFailureOwned(a, retained, true))
			if owned {
				a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
			}
			a.mu.Unlock()
			if !owned || !markOwnedFailure(message) {
				http.Error(w, "standard exit monitor cleanup lost original ownership; replacement retained", http.StatusConflict)
				return
			}
			http.Error(w, message, http.StatusInternalServerError)
			return
		}
	}
	a.startPlatformServiceAutomaticMTU()
	route := "client TUN -> direct external " + exit.Protocol + " exit -> Internet"
	entryID, entryName := "", ""
	if !q.Direct {
		if entryKind == "external" {
			route = "client TUN -> external " + entry.External.Protocol + " entry -> external " + exit.Protocol + " exit -> Internet"
		} else {
			route = "client TUN -> Router VPN WireGuard entry -> external " + exit.Protocol + " exit -> Internet"
		}
		entryID, entryName = entry.ID, entry.Name
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": "standard-exit", "direct": q.Direct, "entry_id": entryID, "entry_name": entryName, "entry_kind": entryKind, "standard_exit_id": exit.ID, "standard_exit_name": exit.Name, "protocol": exit.Protocol, "expected_public_ip": exit.ExpectedPublicIP, "exit_path_proof": "expected-public-ip-passed", "route": route})
}
