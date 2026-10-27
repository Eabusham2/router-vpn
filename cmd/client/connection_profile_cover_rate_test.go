package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"router-vpn/internal/common"
)

func TestCompleteConnectionProfileKeepsDormantTorRateThroughCRUD(t *testing.T) {
	for _, rate := range []int{0, 32, 64, 192} {
		a := externalConnectionTestApp(t, "tor-bridge", false)
		a.profiles.Profiles[3].DAITARateKbps = rate
		id := savedExternalConnectionID(t, a)
		store, err := loadConnectionProfileStore(a)
		if err != nil || store.Profiles[0].External.DAITARateKbps == nil || *store.Profiles[0].External.DAITARateKbps != rate {
			t.Fatal("Add omitted the saved cover rate", err)
		}
		a.profiles.Profiles[3].DAITARateKbps = 96
		response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
		if response.Code != http.StatusOK || a.profiles.Profiles[3].DAITARateKbps != rate || a.profiles.Profiles[3].DAITAEnabled {
			t.Fatal("Load lost dormant rate or enabled cover", response.Code, response.Body.String())
		}
		a.profiles.Profiles[3].DAITARateKbps = 128
		response = postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": id, "name": "Updated cover", "mode": "external", "multihop_enabled": false})
		if response.Code != http.StatusOK {
			t.Fatal("Update failed", response.Body.String())
		}
		store, err = loadConnectionProfileStore(a)
		if err != nil || store.Profiles[0].External.DAITARateKbps == nil || *store.Profiles[0].External.DAITARateKbps != 128 {
			t.Fatal("Update lost selected rate", err)
		}
		response = postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": id})
		if response.Code != http.StatusOK || a.profiles.Profiles[3].DAITARateKbps != 128 {
			t.Fatal("Delete changed linked node rate")
		}
	}
}

func TestCompleteConnectionProfileRateLegacyAndValidation(t *testing.T) {
	node := common.RouterProfile{ID: "router", NodeKind: "router-vpn", Endpoint: "203.0.113.10", DAITAEnabled: true, DAITARateKbps: 64}
	prefs, err := snapshotConnectionPreferences(node, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(prefs)
	var restored connectionProfilePreferences
	if json.Unmarshal(raw, &restored) != nil || restored.DAITARateKbps == nil || *restored.DAITARateKbps != 64 {
		t.Fatal("Router capture lost cover rate")
	}
	node.DAITARateKbps = 192
	got, err := applySavedRouterConnectionPolicy(node, &restored)
	if err != nil || got.DAITARateKbps != 64 || !got.DAITAEnabled {
		t.Fatal("Router restore lost cover rate", err)
	}
	external := externalConnectionTestNode(t, "tor-bridge")
	external.DAITARateKbps = 64
	capture, err := snapshotExternalConnectionPolicy(external)
	if err != nil {
		t.Fatal(err)
	}
	externalRaw, _ := json.Marshal(capture)
	for _, original := range []struct {
		raw      []byte
		external bool
	}{{raw, false}, {externalRaw, true}} {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(original.raw, &fields)
		for _, value := range []string{"null", "-1", "31", "193", "64.5", `"64"`} {
			fields["daita_rate_kbps"] = json.RawMessage(value)
			bad, _ := json.Marshal(fields)
			var err error
			if original.external {
				var p connectionProfileExternalCapture
				err = json.Unmarshal(bad, &p)
			} else {
				var p connectionProfilePreferences
				err = json.Unmarshal(bad, &p)
			}
			if err == nil {
				t.Fatal("malformed saved rate admitted", original.external, value)
			}
		}
		delete(fields, "daita_rate_kbps")
		legacy, _ := json.Marshal(fields)
		if original.external {
			var p connectionProfileExternalCapture
			if err := json.Unmarshal(legacy, &p); err != nil || p.DAITARateKbps != nil {
				t.Fatal("legacy external record rejected", err)
			}
			external.DAITARateKbps = 96
			got, err := p.apply(external)
			if err != nil || got.DAITARateKbps != 96 {
				t.Fatal("legacy record invented a rate", err)
			}
		} else {
			var p connectionProfilePreferences
			if err := json.Unmarshal(legacy, &p); err != nil || p.DAITARateKbps != nil {
				t.Fatal("legacy Router record rejected", err)
			}
			got, err := applySavedRouterConnectionPolicy(node, &p)
			if err != nil || got.DAITARateKbps != 192 {
				t.Fatal("legacy Router record invented a rate", err)
			}
		}
	}
}
