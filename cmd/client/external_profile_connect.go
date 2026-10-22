package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
)

func (a *app) externalProfileStopFailure(cmd *exec.Cmd, cause string) (string, bool) {
	if cleanupErr := a.stopOwnedConnectionRuntime(cmd); cleanupErr != nil {
		return cause + "; runtime cleanup failed: " + cleanupErr.Error(), true
	}
	return cause, false
}

type externalProfileConnectRequest struct {
	ProfileID string `json:"profile_id"`
	EntryID   string `json:"entry_id"`
	Base      string `json:"base"`
	Direct    *bool  `json:"direct,omitempty"`
}

func registerExternalProfileRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/nodes", a.listPublicNodes)
	h.HandleFunc("/api/external-profile/connect", a.externalProfileConnect)
	h.HandleFunc("/api/external-profile/capabilities", a.externalProfileCapabilities)
}

func (a *app) externalProfileCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node_kind":                "external",
		"desktop_runtime":          runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
		"protocols":                externalProfileProtocolCapabilities(),
		"direct":                   true,
		"router_vpn_entry_hop":     true,
		"external_entry_hop":       true,
		"external_entry_protocols": []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"},
		"entry_requirement":        "Router VPN WireGuard or supported external standard entry; OpenVPN and Tor bridge remain fail-closed as upstream entry hops",
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
	case "openvpn":
		_, err = openVPNDNSLines(policy, direct)
	case "tor-bridge":
		_, err = selectedTorBridgeDNS(policy)
	default:
		_, err = selectedStandardExitDNS(policy, !routerEntry)
	}
	if err != nil {
		return common.RouterProfile{}, err
	}
	return policy, nil
}

func (a *app) externalProfileConnect(w http.ResponseWriter, r *http.Request) {
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
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		http.Error(w, "desktop external-node runtime is unavailable on this platform; mobile adapters remain fail-closed until their native engines are wired", http.StatusNotImplemented)
		return
	}
	var q externalProfileConnectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	profileID := strings.TrimSpace(q.ProfileID)
	if !validProfileID(profileID) {
		http.Error(w, "external connect requires an explicit valid profile_id", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	externalProfile, ok := a.profileByIDLocked(profileID)
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	a.mu.Unlock()
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

	if externalProfile.External.Protocol == "tor-bridge" {
		if strings.TrimSpace(q.EntryID) != "" || (q.Direct != nil && !*q.Direct) {
			http.Error(w, "Tor bridge is currently a direct full-device external path only; Tor-as-entry hopping remains unavailable until that graph is implemented and proved", http.StatusNotImplemented)
			return
		}
		a.torBridgeConnectOwned(w, externalProfile)
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
			base := normalizeBase(q.Base)
			if base != "" && base != "auto" && base != "wg" {
				http.Error(w, "Router VPN entry hopping currently requires a standard WireGuard entry", http.StatusBadRequest)
				return
			}
			if strings.TrimSpace(entry.Endpoint) == "" {
				http.Error(w, "entry Router VPN node has no public endpoint", http.StatusBadRequest)
				return
			}
		case "external":
			if entry.External != nil && entry.External.Protocol == "tor-bridge" {
				http.Error(w, "Tor bridge is not yet supported as an upstream external entry hop; refusing an unproved nested Tor graph", http.StatusNotImplemented)
				return
			}
			entryExit, entryErr := standardExitFromExternalProfile(entry)
			if entryErr != nil {
				http.Error(w, "invalid external entry: "+entryErr.Error(), http.StatusBadRequest)
				return
			}
			if entryExit.Protocol == "openvpn" {
				http.Error(w, "external OpenVPN is supported as a direct/final exit but not yet as an upstream hop; refusing competing default tunnels", http.StatusNotImplemented)
				return
			}
		default:
			http.Error(w, "unsupported entry node kind", http.StatusBadRequest)
			return
		}
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
		if !direct && !openVPNProtocolIsTCP(exit.Method) {
			http.Error(w, "OpenVPN final-exit hopping currently supports TCP OpenVPN profiles only; UDP remains fail-closed instead of bypassing the entry", http.StatusBadRequest)
			return
		}
	}

	policy, err = externalDNSPolicyForPath(policy, entry, direct)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sessionBase := "external"
	if !direct && entryKind == "router-vpn" {
		sessionBase = "wg"
	}
	sessionTrackerFor(a).declareRequest("external-node", sessionBase)
	if err = a.stopMode(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var cmdErr error
	var proofErr error
	var startedCmd *exec.Cmd
	if exit.Protocol == "openvpn" {
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
		if err = a.checkConnectionOperation(); err != nil {
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
		if !direct && entryKind == "external" {
			realCmd, realCmdErr = nativeExternalEntryStandardExitCommand(a, policy, entry, exit)
		} else {
			realCmd, realCmdErr = nativeStandardExitCommand(a, policy, entry, exit, direct)
		}
		if realCmdErr != nil {
			sessionTrackerFor(a).markRequestFailure(realCmdErr.Error())
			http.Error(w, realCmdErr.Error(), http.StatusBadRequest)
			return
		}
		if err = a.checkConnectionOperation(); err != nil {
			sessionTrackerFor(a).markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err = realCmd.Start(); err != nil {
			sessionTrackerFor(a).markRequestFailure(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		startedCmd = realCmd
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
		proofErr = a.proveStandardExitForOperation(exit.ExpectedPublicIP)
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
	if proofErr != nil || cmdErr != nil {
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

	now := time.Now().UTC().Format(time.RFC3339)
	a.mu.Lock()
	if a.cmd != startedCmd || startedCmd == nil {
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure("external-node runtime changed before result adoption")
		http.Error(w, "external-node runtime changed before result adoption", http.StatusConflict)
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

	route := "client TUN -> direct external " + exit.Protocol + " node -> Internet"
	entryID, entryName := "", ""
	if !direct {
		if entryKind == "external" {
			route = "client TUN -> external " + entry.External.Protocol + " entry -> external " + exit.Protocol + " exit -> Internet"
		} else {
			route = "client TUN -> Router VPN WireGuard entry -> external " + exit.Protocol + " exit -> Internet"
		}
		entryID = entry.ID
		entryName = entry.Name
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "mode": "external-node", "profile_id": externalProfile.ID, "profile_name": externalProfile.Name, "protocol": exit.Protocol, "direct": direct,
		"entry_id": entryID, "entry_name": entryName, "entry_kind": entryKind, "expected_public_ip": exit.ExpectedPublicIP, "actual_exit_proof": "expected-public-ip-passed", "dns_mode": policy.DNSMode, "route": route,
	})
}
