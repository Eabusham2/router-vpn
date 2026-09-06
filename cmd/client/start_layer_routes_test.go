package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestStartLayerCapabilitiesExposeSecurityTruth(t *testing.T) {
	a := &app{
		profiles: common.RouterProfileStore{
			SchemaVersion: common.RouterProfileSchemaVersion,
			SelectedID:    "home",
			Profiles: []common.RouterProfile{{
				SchemaVersion: common.RouterProfileSchemaVersion,
				ID:            "home",
				Name:          "Home",
				NodeKind:      "router-vpn",
				StartLayer:    common.StartLayerAES256GCMXOR,
			}},
		},
		state: state{Mode: "hysteria2", RuntimeMode: "hysteria2", RouterID: "home", Connected: true, Phase: "connected"},
	}
	rr := httptest.NewRecorder()
	a.startLayerCapabilities(rr, httptest.NewRequest(http.MethodGet, "/api/start-layer/capabilities", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	var body struct {
		SelectedStartLayer       string   `json:"selected_start_layer"`
		SelectedNodeSupported    bool     `json:"selected_node_supported"`
		EffectiveProfileID       string   `json:"effective_profile_id"`
		EffectiveStartLayer      string   `json:"effective_start_layer"`
		EffectiveNodeSupported   bool     `json:"effective_node_supported"`
		CurrentRuntimeSupported  bool     `json:"current_runtime_supported"`
		CurrentRuntimeLayerActive bool    `json:"current_runtime_layer_active"`
		SupportedRawModes        []string `json:"supported_raw_modes"`
		XORCountsAsEncryption    bool     `json:"xor_counts_as_encryption"`
		XORWithoutAEADAllowed    bool     `json:"xor_without_aead_allowed"`
		AuthenticatedAEAD        bool     `json:"authenticated_aead_required"`
		Modes                    []struct {
			ID                      string `json:"id"`
			AuthenticatedEncryption bool   `json:"authenticated_encryption"`
			XORWhitening            bool   `json:"xor_whitening"`
			XORRole                 string `json:"xor_role"`
		} `json:"modes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.SelectedStartLayer != common.StartLayerAES256GCMXOR || !body.SelectedNodeSupported || !body.CurrentRuntimeSupported {
		t.Fatalf("wrong selected/runtime capability: %+v", body)
	}
	if body.EffectiveProfileID != "home" || body.EffectiveStartLayer != common.StartLayerAES256GCMXOR || !body.EffectiveNodeSupported || !body.CurrentRuntimeLayerActive {
		t.Fatalf("wrong effective Start Layer capability: %+v", body)
	}
	if body.XORCountsAsEncryption || body.XORWithoutAEADAllowed || !body.AuthenticatedAEAD {
		t.Fatalf("XOR/AEAD security truth regressed: %+v", body)
	}
	if len(body.SupportedRawModes) != len(common.StartLayerSupportedRawModes) {
		t.Fatalf("supported raw modes drifted: got=%v want=%v", body.SupportedRawModes, common.StartLayerSupportedRawModes)
	}
	foundXOR := false
	for _, mode := range body.Modes {
		if mode.ID == common.StartLayerAES256GCMXOR {
			foundXOR = true
			if !mode.AuthenticatedEncryption || !mode.XORWhitening || mode.XORRole != "obfuscation-only" {
				t.Fatalf("AES+XOR mode truth regressed: %+v", mode)
			}
		}
	}
	if !foundXOR {
		t.Fatal("AES+XOR capability missing")
	}
}

func TestStartLayerCapabilitiesUseLiveRouterInsteadOfMutableSelection(t *testing.T) {
	a := &app{
		profiles: common.RouterProfileStore{
			SchemaVersion: common.RouterProfileSchemaVersion,
			SelectedID:    "selected",
			Profiles: []common.RouterProfile{
				{SchemaVersion: common.RouterProfileSchemaVersion, ID: "selected", Name: "Selected", NodeKind: "router-vpn", StartLayer: common.StartLayerOff},
				{SchemaVersion: common.RouterProfileSchemaVersion, ID: "live", Name: "Live", NodeKind: "router-vpn", StartLayer: common.StartLayerAES256GCM},
			},
		},
		state: state{Mode: "hysteria2", RuntimeMode: "hysteria2", RouterID: "live", Connected: true, Phase: "connected"},
	}
	rr := httptest.NewRecorder()
	a.startLayerCapabilities(rr, httptest.NewRequest(http.MethodGet, "/api/start-layer/capabilities", nil))
	if rr.Code != http.StatusOK { t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String()) }
	var body struct {
		SelectedProfileID        string `json:"selected_profile_id"`
		SelectedStartLayer       string `json:"selected_start_layer"`
		EffectiveProfileID       string `json:"effective_profile_id"`
		EffectiveStartLayer      string `json:"effective_start_layer"`
		CurrentRuntimeLayerActive bool  `json:"current_runtime_layer_active"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil { t.Fatal(err) }
	if body.SelectedProfileID != "selected" || body.SelectedStartLayer != common.StartLayerOff {
		t.Fatalf("selected settings identity drifted: %+v", body)
	}
	if body.EffectiveProfileID != "live" || body.EffectiveStartLayer != common.StartLayerAES256GCM || !body.CurrentRuntimeLayerActive {
		t.Fatalf("live Start Layer substituted mutable selected node: %+v", body)
	}

	a.state.RouterID = ""
	missing := httptest.NewRecorder()
	a.startLayerCapabilities(missing, httptest.NewRequest(http.MethodGet, "/api/start-layer/capabilities", nil))
	var failClosed map[string]any
	if err := json.Unmarshal(missing.Body.Bytes(), &failClosed); err != nil { t.Fatal(err) }
	if supported, _ := failClosed["effective_node_supported"].(bool); supported {
		t.Fatalf("missing live RouterID substituted selected node: %v", failClosed)
	}
	if reason, _ := failClosed["effective_node_reason"].(string); !strings.Contains(reason, "no node identity") {
		t.Fatalf("missing live RouterID did not fail closed explicitly: %v", failClosed)
	}
}

func TestStartLayerCapabilitiesRejectExternalNodeAndWrites(t *testing.T) {
	a := &app{
		profiles: common.RouterProfileStore{
			SchemaVersion: common.RouterProfileSchemaVersion,
			SelectedID:    "external",
			Profiles: []common.RouterProfile{{ID: "external", Name: "External", NodeKind: "external"}},
		},
		state: state{Mode: "off", Phase: "off"},
	}
	rr := httptest.NewRecorder()
	a.startLayerCapabilities(rr, httptest.NewRequest(http.MethodGet, "/api/start-layer/capabilities", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%q", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if supported, _ := body["selected_node_supported"].(bool); supported {
		t.Fatalf("external node incorrectly advertised Start Layer support: %v", body)
	}
	if reason, _ := body["selected_node_reason"].(string); reason == "" {
		t.Fatalf("external node missing unsupported reason: %v", body)
	}

	write := httptest.NewRecorder()
	a.startLayerCapabilities(write, httptest.NewRequest(http.MethodPost, "/api/start-layer/capabilities", nil))
	if write.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status=%d want %d", write.Code, http.StatusMethodNotAllowed)
	}
}
