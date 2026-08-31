package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"router-vpn/internal/common"
)

// registerPlatformStandardExitRoutes keeps the legacy standard-exits.json API
// truthful with the unified external-node runtime. Both surfaces now report the
// same platform capabilities and use the same native Windows/OpenVPN and
// external-entry dataplanes.
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
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema_version":           standardExitStoreVersion,
		"capabilities":             externalProfileProtocolCapabilities(),
		"external_entry_hop":       true,
		"external_entry_protocols": []string{"wireguard", "socks5", "shadowsocks", "hysteria2"},
		"openvpn_entry_hop":        false,
	})
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

func (a *app) platformStandardExitConnect(w http.ResponseWriter, r *http.Request) {
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
	sessionTrackerFor(a).declareRequest("standard-exit", sessionBase)
	if err = a.stopMode(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var cmd *exec.Cmd
	if exit.Protocol == "openvpn" {
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

	stateID := "standard:" + exit.ID
	a.mu.Lock()
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
	if err = a.checkConnectionOperation(); err != nil {
		a.stopOwnedConnectionRuntime(cmd)
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	var proofErr error
	if exit.Protocol == "openvpn" {
		proofErr = a.proveOpenVPNStandardExitForOperation(exit.ExpectedPublicIP)
	} else {
		proofErr = a.proveStandardExitForOperation(exit.ExpectedPublicIP)
	}
	if cancelErr := a.checkConnectionOperation(); cancelErr != nil {
		a.stopOwnedConnectionRuntime(cmd)
		sessionTrackerFor(a).markRequestFailure(cancelErr.Error())
		http.Error(w, cancelErr.Error(), http.StatusConflict)
		return
	}
	if proofErr != nil {
		_ = a.stopMode()
		msg := "standard exit proof failed: " + proofErr.Error()
		a.mu.Lock()
		a.state.Mode = "standard-exit"
		a.state.LogicalMode = "standard-exit"
		a.state.RuntimeMode = "standard-" + exit.Protocol
		a.state.Base = sessionBase
		a.state.RouterID = stateID
		a.state.Phase = "failed"
		a.state.LastError = msg
		a.state.Connected = false
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(msg)
		http.Error(w, msg, http.StatusBadGateway)
		return
	}

	a.mu.Lock()
	if a.cmd != cmd {
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure("standard exit runtime changed during proof")
		http.Error(w, "standard exit runtime changed during proof", http.StatusConflict)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	a.state.Connected = true
	a.state.Phase = "connected"
	a.state.LastError = ""
	if !q.Direct {
		for i := range a.profiles.Profiles {
			if a.profiles.Profiles[i].ID == entry.ID {
				a.profiles.Profiles[i].UseCount++
			}
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	}
	a.mu.Unlock()
	if persistErr != nil {
		_ = a.stopMode()
		sessionTrackerFor(a).markRequestFailure(persistErr.Error())
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}

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
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                 true,
		"mode":               "standard-exit",
		"direct":             q.Direct,
		"entry_id":           entryID,
		"entry_name":         entryName,
		"entry_kind":         entryKind,
		"standard_exit_id":   exit.ID,
		"standard_exit_name": exit.Name,
		"protocol":           exit.Protocol,
		"expected_public_ip": exit.ExpectedPublicIP,
		"exit_path_proof":    "expected-public-ip-passed",
		"route":              route,
	})
}
