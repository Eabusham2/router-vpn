package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"router-vpn/internal/common"
)

func readModeIDsForProfileTest(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row.ID == "" {
			t.Fatalf("blank mode id in %s", path)
		}
		out[row.ID] = struct{}{}
	}
	return out
}

func TestPersistedConnectionProfileModeSetMatchesCanonicalCatalogs(t *testing.T) {
	root := filepath.Join("..", "..", "configs", "client")
	expected := readModeIDsForProfileTest(t, filepath.Join(root, "logical-modes.json"))
	for id := range readModeIDsForProfileTest(t, filepath.Join(root, "modes.json")) {
		expected[id] = struct{}{}
	}
	if len(expected) != len(connectionProfilePersistedModeIDs) {
		t.Fatalf("persisted mode set size=%d canonical union=%d", len(connectionProfilePersistedModeIDs), len(expected))
	}
	for id := range expected {
		if _, ok := connectionProfilePersistedModeIDs[id]; !ok {
			t.Fatalf("canonical mode %q is missing from persisted compatibility set", id)
		}
	}
	for id := range connectionProfilePersistedModeIDs {
		if _, ok := expected[id]; !ok {
			t.Fatalf("stale persisted mode %q is not in either canonical catalog", id)
		}
	}
}

func TestConnectionProfileRecordRejectsUnknownAndContextWrongModes(t *testing.T) {
	prefs := &connectionProfilePreferences{HomeLANAccess: true, KillSwitchPolicy: "off", IPv6Mode: "on", BaseTunnel: "auto", MTUPolicy: "auto"}
	for name, record := range map[string]connectionProfileRecord{
		"unknown": {ID: "one", Name: "One", NodeID: "home", Mode: "totally-fake-mode", Prefs: prefs},
		"router-as-external": {ID: "one", Name: "One", NodeID: "home", Mode: "external", Prefs: prefs},
		"custom-without-layers": {ID: "one", Name: "One", NodeID: "home", Mode: "custom", Prefs: prefs},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := json.Marshal(record); err == nil {
				t.Fatalf("invalid saved profile mode was marshalable: %+v", record)
			}
		})
	}

	valid := []connectionProfileRecord{
		{ID: "logical", Name: "Logical", NodeID: "home", Mode: "base-raw", Prefs: prefs},
		{ID: "legacy-raw", Name: "Legacy raw", NodeID: "home", Mode: "wg", Prefs: prefs},
		{ID: "auto", Name: "Auto", NodeID: "home", Mode: "smart-auto", Prefs: prefs},
		{ID: "external", Name: "External", NodeID: "ext", Mode: "external", Prefs: nil},
		{ID: "custom", Name: "Custom", NodeID: "home", Mode: "custom", Prefs: &connectionProfilePreferences{CustomLayers: []string{"wireguard"}}},
	}
	for _, record := range valid {
		if _, err := json.Marshal(record); err != nil {
			t.Fatalf("valid saved profile mode %q rejected: %v", record.Mode, err)
		}
	}
}

func TestConnectionProfileRecordRejectsUnknownModeOnRead(t *testing.T) {
	var record connectionProfileRecord
	if err := json.Unmarshal([]byte(`{"id":"one","name":"One","node_id":"home","mode":"totally-fake-mode","preferences":{"home_lan_access":true}}`), &record); err == nil {
		t.Fatal("unknown persisted connection profile mode was accepted on read")
	}
}

func TestLiveConnectionProfileSaveValidatorUsesLogicalCatalog(t *testing.T) {
	a := &app{cfg: common.ClientConfig{ModesFile: filepath.Join("..", "..", "configs", "client", "modes.json")}}
	if err := a.validateConnectionProfileModeForSave("base-raw", nil); err != nil {
		t.Fatalf("current logical mode rejected: %v", err)
	}
	if err := a.validateConnectionProfileModeForSave("wg", nil); err == nil {
		t.Fatal("raw runtime id should not be accepted for a new logical connection profile")
	}
	if err := a.validateConnectionProfileModeForSave("custom", []string{"wireguard"}); err != nil {
		t.Fatalf("valid CUSTOM profile rejected: %v", err)
	}
	if err := a.validateConnectionProfileModeForSave("custom", nil); err == nil {
		t.Fatal("empty CUSTOM profile was accepted")
	}
	if err := a.validateConnectionProfileModeForSave("totally-fake-mode", nil); err == nil {
		t.Fatal("unknown logical mode was accepted")
	}
}
