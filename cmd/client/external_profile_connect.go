package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func (a *app) externalProfileStopFailure(cmd *exec.Cmd, cause string) (string, bool) {
	if cleanupErr := a.stopOwnedConnectionRuntime(cmd); cleanupErr != nil {
		return cause + "; runtime cleanup failed: " + cleanupErr.Error(), true
	}
	return cause, false
}

type externalProfileConnectRequest struct {
	ProfileID              string            `json:"profile_id"`
	EntryID                string            `json:"entry_id"`
	EntryMode              string            `json:"entry_mode,omitempty"`
	Base                   string            `json:"base"`
	Direct                 *bool             `json:"direct,omitempty"`
	Execution              string            `json:"execution,omitempty"`
	ComparisonRequestID    string            `json:"comparison_request_id,omitempty"`
	ExpectedSelectedNodeID *string           `json:"expected_selected_node_id,omitempty"`
	ExpectedProfileTokens  map[string]string `json:"expected_profile_tokens,omitempty"`
}

// The default adapter is the shipping native preparation and staging path.
// Tests may supply an isolated child at this boundary while still exercising
// the real graph compiler, private staging, proof and teardown machinery.
type externalConnectRuntime struct {
	prepare func(*app, common.RouterProfile, common.RouterProfile, standardExit, bool, string) (*desktopNodeLaunch, error)
	stage   func(*app, *desktopNodeLaunch) error
	tor     desktopTorConnectRuntime
}

func registerExternalProfileRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/nodes", a.listPublicNodes)
	h.HandleFunc("/api/external-profile/connect", a.externalProfileConnect)
	h.HandleFunc("/api/external-profile/capabilities", a.externalProfileCapabilities)
}

func (a *app) externalRouterEntryModes() []map[string]string {
	entryModes := []map[string]string{}
	for _, mode := range a.modes {
		if mobilemultihop.NodeProfileMode(mode.ID) {
			entryModes = append(entryModes, map[string]string{"id": mode.ID, "name": mode.Name})
		}
	}
	return entryModes
}

func (a *app) externalProfileCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node_kind":                    "external",
		"desktop_runtime":              runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
		"protocols":                    externalProfileProtocolCapabilities(),
		"direct":                       true,
		"router_vpn_entry_hop":         true,
		"external_entry_hop":           true,
		"external_entry_protocols":     []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"},
		"router_vpn_entry_modes":       a.externalRouterEntryModes(),
		"entry_requirement":            "captured native Router VPN entry with its selected mode, base and Start Layer, or a supported external standard entry",
		"profile_source_preconditions": true,
	})
}

func externalRuntimePolicy(profile common.RouterProfile) (common.RouterProfile, error) {
	policy := cloneRouterProfile(profile)
	if err := common.NormalizeRouterProfile(&policy); err != nil {
		return common.RouterProfile{}, err
	}
	if policy.NodeKind != "external" {
		return common.RouterProfile{}, errors.New("selected profile is not an external node")
	}
	if strings.TrimSpace(policy.DNSMode) == "" {
		// A missing choice is the product's Home AdGuard default. Reachability
		// is resolved against the captured entry before starting a runtime;
		// never turn an absent choice into an unrequested public resolver.
		policy.DNSMode, policy.DNSProtocol, policy.DNSPort = "home", "udp", 53
		policy.DNSHost, policy.DNSServerName, policy.DNSPath = "", "", ""
	}
	return policy, nil
}

func externalDNSPolicyForPath(policy, entry common.RouterProfile, direct bool) (common.RouterProfile, error) {
	policy = cloneRouterProfile(policy)
	if policy.NodeKind != "external" || policy.External == nil {
		return common.RouterProfile{}, errors.New("external DNS policy requires the captured external node")
	}
	routerEntry := !direct && entry.ID != "" && (entry.NodeKind == "" || entry.NodeKind == "router-vpn") && entry.External == nil
	if policy.DNSMode == "home" || strings.TrimSpace(policy.DNSMode) == "" {
		if !routerEntry {
			return common.RouterProfile{}, errors.New("Home AdGuard is selected; choose a Router VPN entry or explicitly choose another DNS policy in DNS settings before connecting this external path")
		}
		policy.AdGuardIPv4, policy.AdGuardIPv6 = entry.AdGuardIPv4, entry.AdGuardIPv6
	}
	var err error
	switch policy.External.Protocol {
	case "tor", "tor-bridge":
		if direct && entry.ID != "" || !direct && entry.ID == "" {
			return common.RouterProfile{}, errors.New("Tor DNS entry differs from the requested path")
		}
		_, err = capturedTorBridgeDNS(policy, entry, false)
	default:
		_, err = selectedStandardExitDNS(policy, !routerEntry)
	}
	if err != nil {
		return common.RouterProfile{}, err
	}
	return policy, nil
}

func (a *app) externalProfileConnect(w http.ResponseWriter, r *http.Request) {
	a.externalProfileConnectWithRuntime(w, r, externalConnectRuntime{})
}

func (a *app) externalProfileConnectWithRuntime(w http.ResponseWriter, r *http.Request, driver externalConnectRuntime) {
	driver.tor.requestContext = r.Context()
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
	a.externalProfileConnectOwned(w, q, "", nil, driver)
}

// Both interactive Connect and startup already hold one connection transaction.
// A retained execution is internal Last-state evidence, never an HTTP override.
func (a *app) externalProfileConnectOwned(w http.ResponseWriter, q externalProfileConnectRequest, retained string, startup *startupPolicyCapture, driver externalConnectRuntime) {
	if err := a.guardDesktopOwnedNodeTransition(nil); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		http.Error(w, "desktop external-node runtime is unavailable on this platform", http.StatusNotImplemented)
		return
	}
	if startup != nil {
		if err := startup.current(a); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	if driver.prepare == nil {
		driver.prepare = prepareDesktopExternalLaunch
	}
	if driver.stage == nil {
		driver.stage = stageDesktopNodeLaunch
	}

	profileID := strings.TrimSpace(q.ProfileID)
	if !validProfileID(profileID) {
		http.Error(w, "external connect requires an explicit valid profile_id", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	externalProfile, ok := a.profileByIDLocked(profileID)
	expectedErr := a.validateExternalProfileExpectedProfilesLocked(q, externalProfile)
	externalProfile = cloneRouterProfile(externalProfile)
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	a.mu.Unlock()
	if expectedErr != nil {
		http.Error(w, expectedErr.Error(), http.StatusConflict)
		return
	}
	if !ok {
		http.Error(w, "external profile not found", http.StatusNotFound)
		return
	}
	if externalProfile.NodeKind != "external" || externalProfile.External == nil {
		http.Error(w, "choose an external custom node profile", http.StatusBadRequest)
		return
	}
	// Primary native Connect sends only the node reference. A restored complete
	// profile therefore owns its saved entry choice until the user explicitly
	// requests Direct or supplies a different entry.
	if q.Direct == nil && strings.TrimSpace(q.EntryID) == "" && externalProfile.MultihopEnabled {
		if externalProfile.MultihopExitID != externalProfile.ID || !validProfileID(externalProfile.MultihopEntryID) || externalProfile.MultihopEntryID == externalProfile.ID {
			http.Error(w, "saved external path has invalid entry/exit references", http.StatusBadRequest)
			return
		}
		q.EntryID = externalProfile.MultihopEntryID
	}

	if desktopTorProtocol(externalProfile.External.Protocol) {
		if retained != "" {
			direct := q.Direct != nil && *q.Direct || q.Direct == nil && q.EntryID == ""
			selected, err := externalExecutionChoice(externalProfile, q.Execution, direct)
			if err != nil || desktopTorExecution(retained) == "" || retained != selected && selected != "auto" ||
				startup == nil || a.retainedExternalStartupExecution(startup) != retained {
				http.Error(w, "retained Tor execution differs from the captured Local or Server selection", http.StatusConflict)
				return
			}
			driver.tor.startupExecution = retained
		}
		// Keep the exact request through Tor capture and native preflight. Its
		// entry, Direct choice and source revisions must not be replaced by a
		// profile-only dispatch that loses the user's visible path selection.
		a.torBridgeConnectSelectionOwned(w, externalProfile, q, startup, driver.tor)
		return
	}

	policy, err := externalRuntimePolicy(externalProfile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	exit, err := standardExitFromExternalProfile(externalProfile)
	if err != nil {
		http.Error(w, "invalid external profile: "+err.Error(), http.StatusBadRequest)
		return
	}

	direct := true
	if q.Direct != nil {
		direct = *q.Direct
	} else if strings.TrimSpace(q.EntryID) != "" {
		direct = false
	}
	entry := common.RouterProfile{}
	entryKind := ""
	if direct && q.EntryMode != "" {
		http.Error(w, "direct external connection cannot apply an entry mode", http.StatusBadRequest)
		return
	}
	if direct {
		policy.MultihopEntryMode = ""
	}
	if !direct {
		entryID := strings.TrimSpace(q.EntryID)
		if entryID == "" {
			entryID = strings.TrimSpace(externalProfile.MultihopEntryID)
		}
		if entryID == "" {
			http.Error(w, "choose an entry node for this external exit", http.StatusBadRequest)
			return
		}
		if entryID == externalProfile.ID {
			http.Error(w, "entry and exit nodes must be different", http.StatusBadRequest)
			return
		}
		entry, ok = profileByID(profiles, entryID)
		if !ok {
			http.Error(w, "entry node is not linked", http.StatusBadRequest)
			return
		}
		entryKind = entry.NodeKind
		if entryKind == "" {
			entryKind = "router-vpn"
		}
		switch entryKind {
		case "router-vpn":
			mode, modeErr := desktopExternalEntryMode(policy, entry, q.EntryMode, q.Base)
			if modeErr != nil {
				http.Error(w, modeErr.Error(), http.StatusBadRequest)
				return
			}
			policy.MultihopEntryMode = mode
			if strings.TrimSpace(entry.Endpoint) == "" {
				http.Error(w, "entry Router VPN node has no public endpoint", http.StatusBadRequest)
				return
			}
		case "external":
			if q.EntryMode != "" {
				http.Error(w, "an ordinary external entry uses its saved protocol, not a Router entry mode", http.StatusBadRequest)
				return
			}
			policy.MultihopEntryMode = ""
			if entry.External != nil && desktopTorProtocol(entry.External.Protocol) {
				http.Error(w, "Tor bridge is not yet supported as an upstream external entry hop; refusing an unproved nested Tor graph", http.StatusNotImplemented)
				return
			}
			_, entryErr := standardExitFromExternalProfile(entry)
			if entryErr != nil {
				http.Error(w, "invalid external entry: "+entryErr.Error(), http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "unsupported entry node kind", http.StatusBadRequest)
			return
		}
	}

	policy, err = externalDNSPolicyForPath(policy, entry, direct)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	execution, err := externalExecutionChoice(externalProfile, q.Execution, direct)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	policy.MultihopExecution = execution
	sourceToken, err := startupExternalSourceToken(a, entry, policy.MultihopEntryMode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var native *desktopNodeLaunch
	if desktopExternalNativeProtocol(exit.Protocol) {
		native, err = driver.prepare(a, policy, entry, exit, direct, retained)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if execution != "local" {
		http.Error(w, "this external protocol needs a paired server credential adapter before Server/Compare can execute", http.StatusBadRequest)
		return
	}
	if err := a.validateExternalProfileExpectedProfiles(q, externalProfile); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	currentSource, sourceErr := startupExternalSourceToken(a, entry, policy.MultihopEntryMode)
	if sourceErr != nil || currentSource != sourceToken {
		http.Error(w, "external entry source changed during native preparation", http.StatusConflict)
		return
	}
	if startup != nil {
		if err := startup.current(a); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	sessionBase := "external"
	if !direct && entryKind == "router-vpn" {
		sessionBase = desktopExternalEntryBase(policy.MultihopEntryMode)
	}
	sessionTrackerFor(a).declareRequest("external-node", sessionBase)
	if err = a.stopModeWithIntent(true); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var cmdErr error
	var proofErr error
	var startedCmd *exec.Cmd
	if exit.Protocol == "openvpn" && native == nil {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd, err = windowsOpenVPNStandardExitCommand(a, policy, entry, exit, direct)
		} else {
			cmd, err = openVPNStandardExitCommand(a, policy, entry, exit, direct)
		}
		if err != nil {
			sessionTrackerFor(a).markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = a.checkConnectionOperation()
		if err == nil && startup != nil {
			err = startup.current(a)
		}
		if err != nil {
			sessionTrackerFor(a).markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err = cmd.Start(); err != nil {
			sessionTrackerFor(a).markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		startedCmd = cmd
		a.mu.Lock()
		a.cmd = cmd
		a.state.Mode = "external-node"
		a.state.LogicalMode = "external-node"
		a.state.RuntimeMode = "external-openvpn"
		a.state.Base = sessionBase
		a.state.RouterID = externalProfile.ID
		a.state.Connected = false
		a.state.Phase = "external-node:openvpn:proving-public-exit"
		a.state.LastError = ""
		a.mu.Unlock()
		if err = a.checkConnectionOperation(); err != nil {
			message, cleanupFailed := a.externalProfileStopFailure(cmd, err.Error())
			sessionTrackerFor(a).markRequestFailure(message)
			status := http.StatusConflict
			if cleanupFailed {
				status = http.StatusInternalServerError
			}
			http.Error(w, message, status)
			return
		}
		proofErr = a.proveOpenVPNStandardExitForOperation(exit.ExpectedPublicIP)
		if proofErr == nil {
			a.mu.Lock()
			if a.cmd != cmd {
				cmdErr = errors.New("OpenVPN external-node runtime changed during exit proof")
			}
			a.mu.Unlock()
		}
	} else {
		var realCmd *exec.Cmd
		var realCmdErr error
		if native != nil {
			realCmdErr = driver.stage(a, native)
			realCmd = native.command
		} else if !direct && entryKind == "external" {
			realCmd, realCmdErr = nativeExternalEntryStandardExitCommand(a, policy, entry, exit)
		} else {
			realCmd, realCmdErr = nativeStandardExitCommand(a, policy, entry, exit, direct)
		}
		if realCmdErr != nil {
			sessionTrackerFor(a).markRequestFailure(realCmdErr.Error())
			http.Error(w, realCmdErr.Error(), http.StatusBadRequest)
			return
		}
		err = a.checkConnectionOperation()
		if err == nil && startup != nil {
			err = startup.current(a)
		}
		if err != nil {
			if native != nil && native.directory != "" {
				_ = cleanupDesktopNodeLaunch(native)
			}
			sessionTrackerFor(a).markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err = realCmd.Start(); err != nil {
			if native != nil && native.directory != "" {
				_ = cleanupDesktopNodeLaunch(native)
			}
			sessionTrackerFor(a).markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		startedCmd = realCmd
		if native != nil {
			native.external.started = time.Now()
			desktopNodeOwners.Store(a, native)
		}
		a.mu.Lock()
		a.cmd = realCmd
		a.state.Mode = "external-node"
		a.state.LogicalMode = "external-node"
		a.state.RuntimeMode = "external-" + exit.Protocol
		a.state.Base = sessionBase
		a.state.RouterID = externalProfile.ID
		a.state.Connected = false
		a.state.Phase = "external-node:proving-public-exit"
		a.state.LastError = ""
		a.mu.Unlock()
		if err = a.checkConnectionOperation(); err != nil {
			message, cleanupFailed := a.externalProfileStopFailure(realCmd, err.Error())
			sessionTrackerFor(a).markRequestFailure(message)
			status := http.StatusConflict
			if cleanupFailed {
				status = http.StatusInternalServerError
			}
			http.Error(w, message, status)
			return
		}
		if native != nil {
			_, proofErr = a.waitDesktopExternalProof(a.connectionOperationContextOrBackground(), native)
			if proofErr == nil {
				proofErr = registerActiveDNSRuntimeConfig(a, externalProfile.ID, "external-"+exit.Protocol, filepath.Join(native.directory, "sing-box.json"))
			}
		} else {
			proofErr = a.proveStandardExitForOperation(exit.ExpectedPublicIP)
		}
		if proofErr == nil {
			a.mu.Lock()
			if a.cmd != realCmd {
				cmdErr = errors.New("external-node runtime changed during exit proof")
			}
			a.mu.Unlock()
		}
	}

	if cancelErr := a.checkConnectionOperation(); cancelErr != nil {
		cmdErr = cancelErr
	}
	if startup != nil && cmdErr == nil {
		cmdErr = startup.current(a)
	}
	if proofErr != nil || cmdErr != nil {
		if !a.ownsConnectionRuntime(startedCmd) {
			http.Error(w, "external startup or connection lost its runtime owner; replacement retained", http.StatusConflict)
			return
		}
		failure := cmdErr
		status := http.StatusConflict
		if failure == nil {
			failure = proofErr
			status = http.StatusBadGateway
		}
		msg := "external node exit proof failed: " + failure.Error()
		var cleanupFailed bool
		msg, cleanupFailed = a.externalProfileStopFailure(startedCmd, msg)
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		a.mu.Lock()
		a.state.Mode = "external-node"
		a.state.LogicalMode = "external-node"
		a.state.RuntimeMode = "external-" + exit.Protocol
		a.state.Base = sessionBase
		a.state.RouterID = externalProfile.ID
		a.state.Phase = "failed"
		a.state.LastError = msg
		a.state.Connected = false
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(msg)
		http.Error(w, msg, status)
		return
	}

	if native != nil {
		if _, err := a.readDesktopExternalProof(native); err != nil {
			message, _ := a.externalProfileStopFailure(startedCmd, err.Error())
			http.Error(w, message, http.StatusConflict)
			return
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	a.mu.Lock()
	if a.cmd != startedCmd || startedCmd == nil {
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure("external-node runtime changed before result adoption")
		http.Error(w, "external-node runtime changed before result adoption", http.StatusConflict)
		return
	}
	current, stillLinked := a.profileByIDLocked(externalProfile.ID)
	unchanged := stillLinked && desktopExternalProfilesUnchanged(current, externalProfile)
	if startup != nil {
		unchanged = unchanged && startup.currentLocked(a) == nil
	}
	if !direct {
		currentEntry, stillLinked := a.profileByIDLocked(entry.ID)
		unchanged = unchanged && stillLinked && desktopExternalProfilesUnchanged(currentEntry, entry)
	}
	if !unchanged {
		a.mu.Unlock()
		message, _ := a.externalProfileStopFailure(startedCmd, "captured external node or entry changed before result adoption")
		http.Error(w, message, http.StatusConflict)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	a.state.Connected = true
	a.state.Phase = "connected"
	a.state.LastError = ""
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == externalProfile.ID {
			a.profiles.Profiles[i].UseCount++
			a.profiles.Profiles[i].LastUsedAt = now
			a.profiles.Profiles[i].PublicIP = exit.ExpectedPublicIP
			a.profiles.Profiles[i].MultihopEnabled = !direct
			a.profiles.Profiles[i].MultihopExecution = execution
			a.profiles.Profiles[i].MultihopEntryMode = policy.MultihopEntryMode
			a.profiles.Profiles[i].MultihopEntryID, a.profiles.Profiles[i].MultihopExitID = "", ""
			if !direct {
				a.profiles.Profiles[i].MultihopEntryID, a.profiles.Profiles[i].MultihopExitID = entry.ID, externalProfile.ID
			}
		}
		if !direct && a.profiles.Profiles[i].ID == entry.ID {
			a.profiles.Profiles[i].UseCount++
			a.profiles.Profiles[i].LastUsedAt = now
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	} else if native != nil {
		captureDesktopMTUBaselineLocked(a, native)
	}
	a.mu.Unlock()
	if persistErr != nil {
		message, cleanupFailed := a.externalProfileStopFailure(startedCmd, "external-node usage/public-exit persistence failed: "+persistErr.Error())
		if !cleanupFailed {
			message += "; runtime was torn down"
		}
		sessionTrackerFor(a).markRequestFailure(message)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	if err := a.checkConnectionOperation(); err != nil {
		message, cleanupFailed := a.externalProfileStopFailure(startedCmd, err.Error())
		sessionTrackerFor(a).markRequestFailure(message)
		status := http.StatusConflict
		if cleanupFailed {
			status = http.StatusInternalServerError
		}
		http.Error(w, message, status)
		return
	}
	chosenExecution := "local"
	if native != nil {
		native.external.mu.Lock()
		chosenExecution = native.external.execution
		native.external.mu.Unlock()
		a.saveExternalStartupSelection(native, sourceToken, chosenExecution)
		a.monitorDesktopExternalRuntime(native)
	}

	route := "client TUN -> direct external " + exit.Protocol + " node -> Internet"
	entryID, entryName := "", ""
	if !direct {
		if entryKind == "external" {
			route = "client TUN -> external " + entry.External.Protocol + " entry -> external " + exit.Protocol + " exit -> Internet"
		} else {
			route = "client TUN -> Router VPN " + policy.MultihopEntryMode + " entry -> external " + exit.Protocol + " exit -> Internet"
			if chosenExecution == "server" {
				route = "client TUN -> Router VPN " + policy.MultihopEntryMode + " entry -> owned server relay -> external " + exit.Protocol + " exit -> Internet"
			}
		}
		entryID = entry.ID
		entryName = entry.Name
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "mode": "external-node", "profile_id": externalProfile.ID, "profile_name": externalProfile.Name, "protocol": exit.Protocol, "direct": direct,
		"entry_id": entryID, "entry_name": entryName, "entry_kind": entryKind, "expected_public_ip": exit.ExpectedPublicIP, "actual_exit_proof": "expected-public-ip-passed", "dns_mode": policy.DNSMode, "route": route,
		"execution": chosenExecution, "execution_preference": execution, "entry_mode": policy.MultihopEntryMode,
	})
}
