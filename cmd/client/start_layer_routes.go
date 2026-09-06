package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"router-vpn/internal/common"
)

type startLayerModeCapability struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	AuthenticatedEncryption bool   `json:"authenticated_encryption"`
	XORWhitening            bool   `json:"xor_whitening"`
	XORRole                 string `json:"xor_role,omitempty"`
	Description             string `json:"description"`
}

func registerStartLayerRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/start-layer/capabilities", a.startLayerCapabilities)
}

func startLayerProfileState(profile common.RouterProfile, found bool, missingReason string) (string, bool, string) {
	if !found {
		return common.StartLayerOff, false, missingReason
	}
	kind := strings.ToLower(strings.TrimSpace(profile.NodeKind))
	if kind == "" {
		kind = "router-vpn"
	}
	if kind != "router-vpn" {
		return common.StartLayerOff, false, "Start Layer is owned by Router VPN home-node profiles; external nodes keep their own transport security."
	}
	normalized, err := common.NormalizeStartLayerMode(profile.StartLayer)
	if err != nil {
		return common.StartLayerOff, false, "Router VPN node has an invalid Start Layer preference: " + err.Error()
	}
	return normalized, true, ""
}

func (a *app) startLayerCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	a.mu.Lock()
	selectedID := strings.TrimSpace(a.profiles.SelectedID)
	st := a.state
	effectiveID := selectedID
	active := profileSettingsBusy(st.Connected, st.Phase)
	if active {
		// A connected/transitioning runtime is owned by state.RouterID. Never
		// substitute a newer mutable selection when reporting live Start Layer
		// truth; this is the same identity boundary used by path/DNS telemetry.
		effectiveID = strings.TrimSpace(st.RouterID)
	}
	var selected, effective common.RouterProfile
	selectedFound, effectiveFound := false, false
	for _, profile := range a.profiles.Profiles {
		if profile.ID == selectedID {
			selected = profile
			selectedFound = true
		}
		if profile.ID == effectiveID {
			effective = profile
			effectiveFound = true
		}
	}
	a.mu.Unlock()

	selectedLayer, selectedNodeSupported, selectedNodeReason := startLayerProfileState(selected, selectedFound, "Select a Router VPN home node to use Start Layer.")
	effectiveMissing := "No effective Router VPN node is available to evaluate Start Layer."
	if active && effectiveID == "" {
		effectiveMissing = "Active Router VPN session has no node identity; refusing to substitute the mutable selected node."
	}
	effectiveLayer, effectiveNodeSupported, effectiveNodeReason := startLayerProfileState(effective, effectiveFound, effectiveMissing)

	runtimeMode := strings.ToLower(strings.TrimSpace(st.RuntimeMode))
	runtimeSupported := false
	runtimeReason := "No active raw runtime is available to evaluate."
	if runtimeMode != "" && runtimeMode != "off" {
		runtimeSupported = common.StartLayerSupportsRawMode(runtimeMode)
		if runtimeSupported {
			runtimeReason = ""
		} else {
			runtimeReason = runtimeMode + " has no proved Start Layer composition path yet."
		}
	}

	modes := []startLayerModeCapability{
		{
			ID: common.StartLayerOff, Name: "Off",
			Description: "No additional pre-tunnel Start Layer.",
		},
		{
			ID: common.StartLayerAES256GCM, Name: "AES-256-GCM",
			AuthenticatedEncryption: true,
			Description: "Authenticated Shadowsocks 2022 BLAKE3 AES-256-GCM pre-tunnel layer.",
		},
		{
			ID: common.StartLayerAES256GCMXOR, Name: "AES-256-GCM + XOR whitening",
			AuthenticatedEncryption: true, XORWhitening: true, XORRole: "obfuscation-only",
			Description: "The authenticated AES-256-GCM layer remains the security boundary; XOR only whitens the already-encrypted byte stream and is never counted as encryption.",
		},
	}

	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                              true,
		"modes":                           modes,
		"aes_transport":                   common.StartLayerAES256GCMTransport,
		"supported_raw_modes":             append([]string(nil), common.StartLayerSupportedRawModes...),
		"selected_profile_id":             selectedID,
		"selected_start_layer":            selectedLayer,
		"selected_node_supported":         selectedNodeSupported,
		"selected_node_reason":            selectedNodeReason,
		"effective_profile_id":            effectiveID,
		"effective_start_layer":           effectiveLayer,
		"effective_node_supported":        effectiveNodeSupported,
		"effective_node_reason":           effectiveNodeReason,
		"current_runtime_mode":            runtimeMode,
		"current_runtime_supported":       runtimeSupported,
		"current_runtime_reason":          runtimeReason,
		"current_runtime_layer_active":    effectiveNodeSupported && effectiveLayer != common.StartLayerOff && runtimeSupported,
		"xor_counts_as_encryption":        false,
		"xor_without_aead_allowed":        false,
		"authenticated_aead_required":     true,
	})
}
