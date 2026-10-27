package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopTorBridgeUpdateFormCatalog(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_TOR_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("native Tor editor supplies its callback payload directory")
	}
	a, _, _ := torBridgeUpdateSourceFixture(t)
	response := httptest.NewRecorder()
	a.listPublicNodes(response, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	if response.Code != http.StatusOK || response.Header().Get("cache-control") != "no-store" {
		t.Fatal("Tor editor catalog did not use the actual private-source projection")
	}
	for _, secret := range []string{"cert=", "private-token", "api_token", "private_key"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("Tor form catalog exposed source credentials", secret)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "tor-update-source-catalog.json"), response.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	// The unchanged-protection callback receives a separate real projection,
	// including the revision token of the saved Always policy.
	a.profiles.Profiles[0].KillSwitchPolicy = "always"
	a.profiles.Profiles[0].KillSwitch = true
	response = httptest.NewRecorder()
	a.listPublicNodes(response, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	if response.Code != http.StatusOK {
		t.Fatal("saved Always source projection failed")
	}
	if err := os.WriteFile(filepath.Join(directory, "tor-update-always-source-catalog.json"), response.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	a.torBridgeCapabilities(response, httptest.NewRequest(http.MethodGet, "/api/tor-bridge/capabilities", nil))
	var capability map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &capability) != nil || capability["profile_update_source_preconditions"] != true {
		t.Fatal("Tor update capability omitted its unconditional source contract")
	}
	// The native editor intentionally prevents choosing unavailable transports.
	// This fixture exercises its idle import callbacks with simulated installed
	// availability; it does not claim this test app owns a runtime or a tunnel.
	capability["test_fixture_runtime_availability"] = "simulated: idle bridge form/import only"
	capability["supported"] = true
	rows, ok := capability["transports"].([]any)
	if !ok {
		t.Fatal("Tor capability transport catalog is missing")
	}
	for _, row := range rows {
		transport, ok := row.(map[string]any)
		if !ok {
			t.Fatal("Tor capability transport is not an object")
		}
		if _, tested := torBridgeUpdateInputLines()[transport["id"].(string)]; tested {
			transport["supported"] = true
			transport["helper"] = "test-only simulated runtime availability"
			delete(transport, "reason")
		}
	}
	capabilityBytes, err := json.MarshalIndent(capability, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tor-update-capabilities.json"), capabilityBytes, 0600); err != nil {
		t.Fatal(err)
	}
	lines, err := json.MarshalIndent(torBridgeUpdateInputLines(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "tor-update-input-lines.json"), lines, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopTorBridgeUpdateFormPayload(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_TOR_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("native Tor editor supplies its callback payload directory")
	}
	t.Run("unchanged-saved-protection", func(t *testing.T) {
		a, old, entry := torBridgeUpdateSourceFixture(t)
		old.KillSwitchPolicy, old.KillSwitch = "always", true
		a.profiles.Profiles[0] = old
		raw, err := os.ReadFile(filepath.Join(directory, "tor-update-preserved-protection.json"))
		if err != nil {
			t.Fatal(err)
		}
		var request torBridgeImportRequest
		if json.Unmarshal(raw, &request) != nil || request.KillSwitchPolicy != "always" || request.Name != old.Name || len(request.ExpectedProfileTokens) != 2 {
			t.Fatal("actual checkbox and Save did not preserve the saved protection/name/source")
		}
		checkTorBridgePreservedUpdate(t, a, old, entry, postTorBridgeUpdate(a, raw), "snowflake", "always")
	})
	for transport := range torBridgeUpdateInputLines() {
		for _, kill := range []string{"off", "on-connect", "always"} {
			t.Run(transport+"/"+kill, func(t *testing.T) {
				a, old, entry := torBridgeUpdateSourceFixture(t)
				raw, err := os.ReadFile(filepath.Join(directory, "tor-update-"+transport+"-"+kill+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var q torBridgeImportRequest
				if err = json.Unmarshal(raw, &q); err != nil {
					t.Fatal("actual native bridge form is not the shipping API contract", err)
				}
				if q.ID != old.ID || q.Transport != transport || q.KillSwitchPolicy != kill || q.ExpectedSelectedNodeID == nil || *q.ExpectedSelectedNodeID != old.ID || len(q.ExpectedProfileTokens) != 2 {
					t.Fatal("native editor omitted or changed its captured target, protection or source revisions")
				}
				if err = a.validateExternalProfileExpectedProfiles(q.expectedProfiles(), old); err != nil {
					t.Fatal("native editor body cannot pass the actual source guard", err)
				}
				checkTorBridgePreservedUpdate(t, a, old, entry, postTorBridgeUpdate(a, raw), transport, kill)
				for _, relinked := range []string{"tor-edit", "entry"} {
					replaced, _, _ := torBridgeUpdateSourceFixture(t)
					if relinked == "entry" {
						replaced.profiles.Profiles[1].APIToken = "replacement-private-entry-token"
					} else {
						replaced.profiles.Profiles[0].External.TorBridge.Bridges = []string{strings.Replace(torImportObfs4Bridge, "203.0.113.44", "203.0.113.45", 1)}
					}
					if response := postTorBridgeUpdate(replaced, raw); response.Code != http.StatusConflict {
						t.Fatal("native editor adopted a relinked source", relinked, response.Code, response.Body.String())
					}
				}
			})
		}
	}
}
