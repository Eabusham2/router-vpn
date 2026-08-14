package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type externalProfileConnectRequest struct {
	ProfileID string `json:"profile_id"`
	EntryID   string `json:"entry_id"`
	Base      string `json:"base"`
	Direct    *bool  `json:"direct,omitempty"`
}

func registerExternalProfileRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/external-profile/connect", a.externalProfileConnect)
	h.HandleFunc("/api/external-profile/capabilities", a.externalProfileCapabilities)
}

func (a *app) externalProfileCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "GET only", http.StatusMethodNotAllowed); return }
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node_kind": "external",
		"desktop_runtime": runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
		"protocols": standardExitCapabilities(),
		"direct": true,
		"router_vpn_entry_hop": true,
		"entry_requirement": "standard WireGuard Router VPN entry for hopped external exits",
	})
}

func externalRuntimePolicy(profile common.RouterProfile) (common.RouterProfile, error) {
	policy := profile
	if err := common.NormalizeRouterProfile(&policy); err != nil { return common.RouterProfile{}, err }
	if policy.NodeKind != "external" { return common.RouterProfile{}, errors.New("selected profile is not an external node") }
	// Fresh external nodes must not inherit Home AdGuard just because Router VPN
	// nodes default to it. If the user has not selected an external-node DNS
	// policy yet, use the existing encrypted Rescue policy through the external
	// exit. An explicit custom/fastest/DoH/DoT/DoH3 selection remains untouched.
	if strings.TrimSpace(policy.DNSMode) == "" {
		policy.DNSMode = "rescue"
		policy.DNSProtocol = "https"
		policy.DNSHost = "1.1.1.1"
		policy.DNSPort = 443
		policy.DNSServerName = "cloudflare-dns.com"
		policy.DNSPath = "/dns-query"
	}
	return policy, nil
}

func (a *app) externalProfileConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		http.Error(w, "desktop external-node runtime is unavailable on this platform; mobile adapters remain fail-closed until their native engines are wired", http.StatusNotImplemented)
		return
	}
	var q externalProfileConnectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }

	a.mu.Lock()
	profileID := strings.TrimSpace(q.ProfileID)
	if profileID == "" { profileID = a.profiles.SelectedID }
	externalProfile, ok := a.profileByIDLocked(profileID)
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	a.mu.Unlock()
	if !ok { http.Error(w, "external profile not found", http.StatusNotFound); return }
	if externalProfile.NodeKind != "external" || externalProfile.External == nil { http.Error(w, "choose an external custom node profile", http.StatusBadRequest); return }

	policy, err := externalRuntimePolicy(externalProfile)
	if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
	exit, err := standardExitFromExternalProfile(externalProfile)
	if err != nil { http.Error(w, "invalid external profile: "+err.Error(), http.StatusBadRequest); return }

	direct := true
	if q.Direct != nil { direct = *q.Direct } else if strings.TrimSpace(q.EntryID) != "" { direct = false }
	entry := common.RouterProfile{}
	if !direct {
		base := normalizeBase(q.Base)
		if base != "auto" && base != "wg" { http.Error(w, "external-node hopping currently requires a standard WireGuard Router VPN entry", http.StatusBadRequest); return }
		entryID := strings.TrimSpace(q.EntryID)
		if entryID == "" { entryID = strings.TrimSpace(externalProfile.MultihopEntryID) }
		if entryID == "" { http.Error(w, "choose a Router VPN entry node for this external exit", http.StatusBadRequest); return }
		entry, ok = profileByID(profiles, entryID)
		if !ok { http.Error(w, "entry node is not linked", http.StatusBadRequest); return }
		if entry.NodeKind != "" && entry.NodeKind != "router-vpn" { http.Error(w, "external-node hopping currently requires a Router VPN entry node", http.StatusBadRequest); return }
		if strings.TrimSpace(entry.Endpoint) == "" { http.Error(w, "entry Router VPN node has no public endpoint", http.StatusBadRequest); return }
	}

	if exit.Protocol == "openvpn" {
		cap := openVPNRuntimeCapability()
		if !cap.Supported { http.Error(w, cap.Reason, http.StatusNotImplemented); return }
		if !direct && !openVPNProtocolIsTCP(exit.Method) { http.Error(w, "Router VPN -> external OpenVPN hopping currently supports TCP OpenVPN profiles only; UDP remains fail-closed instead of bypassing the entry", http.StatusBadRequest); return }
	}

	sessionBase := "external"
	if !direct { sessionBase = "wg" }
	sessionTrackerFor(a).declareRequest("external-node", sessionBase)
	if err = a.stopMode(); err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusInternalServerError); return }

	var cmdErr error
	var proofErr error
	if exit.Protocol == "openvpn" {
		cmd, err := openVPNStandardExitCommand(a, policy, entry, exit, direct)
		if err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusBadRequest); return }
		if err = cmd.Start(); err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusInternalServerError); return }
		a.mu.Lock(); a.cmd=cmd; a.state.Mode="external-node"; a.state.LogicalMode="external-node"; a.state.RuntimeMode="external-openvpn"; a.state.Base=sessionBase; a.state.RouterID=externalProfile.ID; a.state.Connected=false; a.state.Phase="external-node:openvpn:proving-public-exit"; a.state.LastError=""; a.mu.Unlock()
		proofErr = proveOpenVPNStandardExit(exit.ExpectedPublicIP)
		if proofErr == nil {
			a.mu.Lock(); if a.cmd != cmd { cmdErr = errors.New("OpenVPN external-node runtime changed during exit proof") }; a.mu.Unlock()
		}
	} else {
		cmd, err := nativeStandardExitCommand(a, policy, entry, exit, direct)
		if err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusBadRequest); return }
		if err = cmd.Start(); err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusInternalServerError); return }
		a.mu.Lock(); a.cmd=cmd; a.state.Mode="external-node"; a.state.LogicalMode="external-node"; a.state.RuntimeMode="external-"+exit.Protocol; a.state.Base=sessionBase; a.state.RouterID=externalProfile.ID; a.state.Connected=false; a.state.Phase="external-node:proving-public-exit"; a.state.LastError=""; a.mu.Unlock()
		proofErr = proveStandardExit(exit.ExpectedPublicIP)
		if proofErr == nil {
			a.mu.Lock(); if a.cmd != cmd { cmdErr = errors.New("external-node runtime changed during exit proof") }; a.mu.Unlock()
		}
	}

	if proofErr != nil || cmdErr != nil {
		failure := proofErr
		if failure == nil { failure = cmdErr }
		_ = a.stopMode()
		msg := "external node exit proof failed: " + failure.Error()
		a.mu.Lock(); a.state.Mode="external-node"; a.state.LogicalMode="external-node"; a.state.RuntimeMode="external-"+exit.Protocol; a.state.Base=sessionBase; a.state.RouterID=externalProfile.ID; a.state.Phase="failed"; a.state.LastError=msg; a.state.Connected=false; a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(msg); http.Error(w, msg, http.StatusBadGateway); return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	a.mu.Lock()
	a.state.Connected=true; a.state.Phase="connected"; a.state.LastError=""
	for i:=range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID==externalProfile.ID { a.profiles.Profiles[i].UseCount++; a.profiles.Profiles[i].LastUsedAt=now; a.profiles.Profiles[i].PublicIP=exit.ExpectedPublicIP }
		if !direct && a.profiles.Profiles[i].ID==entry.ID { a.profiles.Profiles[i].UseCount++; a.profiles.Profiles[i].LastUsedAt=now }
	}
	persistErr:=a.persistProfilesLocked(); a.mu.Unlock()
	if persistErr!=nil { _=a.stopMode(); sessionTrackerFor(a).markRequestFailure(persistErr.Error()); http.Error(w,persistErr.Error(),http.StatusInternalServerError); return }

	route := "client TUN -> direct external " + exit.Protocol + " node -> Internet"
	entryID, entryName := "", ""
	if !direct { route = "client TUN -> Router VPN WireGuard entry -> external " + exit.Protocol + " exit -> Internet"; entryID=entry.ID; entryName=entry.Name }
	w.Header().Set("content-type","application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":true,"mode":"external-node","profile_id":externalProfile.ID,"profile_name":externalProfile.Name,"protocol":exit.Protocol,"direct":direct,
		"entry_id":entryID,"entry_name":entryName,"expected_public_ip":exit.ExpectedPublicIP,"actual_exit_proof":"expected-public-ip-passed","dns_mode":policy.DNSMode,"route":route,
	})
}
