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

func (a *app) startLayerCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	a.mu.Lock()
	selectedID := a.profiles.SelectedID
	st := a.state
	var selected common.RouterProfile
	found := false
	for _, profile := range a.profiles.Profiles {
		if profile.ID == selectedID {
			selected = profile
			found = true
			break
		}
	}
	a.mu.Unlock()

	selectedLayer := common.StartLayerOff
	selectedNodeSupported := false
	selectedNodeReason := "Select a Router VPN home node to use Start Layer."
	if found {
		kind := strings.ToLower(strings.TrimSpace(selected.NodeKind))
		if kind == "" {
			kind = "router-vpn"
		}
		if kind == "router-vpn" {
			selectedNodeSupported = true
			selectedNodeReason = ""
			if normalized, err := common.NormalizeStartLayerMode(selected.StartLayer); err == nil {
				selectedLayer = normalized
			} else {
				selectedNodeSupported = false
				selectedNodeReason = "Selected node has an invalid Start Layer preference: " + err.Error()
			}
		} else {
			selectedNodeReason = "Start Layer is owned by Router VPN home-node profiles; external nodes keep their own transport security."
		}
	}

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
		"ok":                          true,
		"modes":                       modes,
		"aes_transport":               common.StartLayerAES256GCMTransport,
		"supported_raw_modes":         append([]string(nil), common.StartLayerSupportedRawModes...),
		"selected_profile_id":         selectedID,
		"selected_start_layer":        selectedLayer,
		"selected_node_supported":     selectedNodeSupported,
		"selected_node_reason":        selectedNodeReason,
		"current_runtime_mode":        runtimeMode,
		"current_runtime_supported":   runtimeSupported,
		"current_runtime_reason":      runtimeReason,
		"xor_counts_as_encryption":    false,
		"xor_without_aead_allowed":    false,
		"authenticated_aead_required": true,
	})
}
