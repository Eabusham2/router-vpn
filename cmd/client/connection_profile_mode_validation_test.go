package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const profileRecordTestCreated = "2026-08-24T00:00:00Z"
const profileRecordTestUpdated = "2026-08-24T00:00:01Z"

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

func recordForModeTest(id, nodeID, mode string, prefs *connectionProfilePreferences) connectionProfileRecord {
	return connectionProfileRecord{
		ID: id, Name: id, NodeID: nodeID, Mode: mode, Prefs: prefs,
		CreatedAt: profileRecordTestCreated, UpdatedAt: profileRecordTestUpdated,
	}
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

func TestConnectionProfileSaveModeSetMatchesLogicalCatalog(t *testing.T) {
	expected := readModeIDsForProfileTest(t, filepath.Join("..", "..", "configs", "client", "logical-modes.json"))
	if len(expected) != len(connectionProfileSaveLogicalModeIDs) {
		t.Fatalf("save-mode set size=%d logical catalog=%d", len(connectionProfileSaveLogicalModeIDs), len(expected))
	}
	for id := range expected {
		if _, ok := connectionProfileSaveLogicalModeIDs[id]; !ok {
			t.Fatalf("logical mode %q is missing from new-save mode set", id)
		}
	}
	for id := range connectionProfileSaveLogicalModeIDs {
		if _, ok := expected[id]; !ok {
			t.Fatalf("stale new-save mode %q is not in the logical catalog", id)
		}
	}
}

func TestConnectionProfileSaveRequestRejectsRawAndUnknownModes(t *testing.T) {
	for name, raw := range map[string]string{
		"raw-runtime": `{"name":"Raw","mode":"wg"}`,
		"unknown": `{"name":"Unknown","mode":"totally-fake-mode"}`,
		"empty-custom": `{"name":"Custom","mode":"custom","custom_layers":[]}`,
		"unknown-field": `{"name":"Hidden","mode":"base-raw","hidden":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			var request connectionProfileSaveRequest
			if err := json.Unmarshal([]byte(raw), &request); err == nil {
				t.Fatalf("invalid new connection-profile request %s was accepted", name)
			}
		})
	}
}

func TestConnectionProfileSaveRequestAcceptsLogicalStrategyCustomAndExternal(t *testing.T) {
	for name, raw := range map[string]string{
		"logical": `{"name":"Logical","mode":"base-raw"}`,
		"smart": `{"name":"Smart","mode":"smart-auto"}`,
		"auto": `{"name":"Auto","mode":"auto"}`,
		"custom": `{"name":"Custom","mode":"custom:privacy","custom_layers":["wireguard"]}`,
		"external-compat": `{"name":"External","mode":"external"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var request connectionProfileSaveRequest
			if err := json.Unmarshal([]byte(raw), &request); err != nil {
				t.Fatalf("valid new connection-profile request %s rejected: %v", name, err)
			}
		})
	}
}

func TestConnectionProfileRecordRejectsUnknownAndContextWrongModes(t *testing.T) {
	prefs := &connectionProfilePreferences{HomeLANAccess: true, KillSwitchPolicy: "off", IPv6Mode: "on", BaseTunnel: "auto", MTUPolicy: "auto"}
	invalid := map[string]connectionProfileRecord{
		"unknown": recordForModeTest("unknown", "home", "totally-fake-mode", prefs),
		"router-as-external": recordForModeTest("router-external", "home", "external", prefs),
		"external-as-router": recordForModeTest("external-router", "ext", "smart-auto", nil),
		"custom-without-layers": recordForModeTest("empty-custom", "home", "custom", prefs),
	}
	for name, record := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := json.Marshal(record); err == nil {
				t.Fatalf("invalid saved profile mode was marshalable: %+v", record)
			}
		})
	}

	valid := []connectionProfileRecord{
		recordForModeTest("logical", "home", "base-raw", prefs),
		recordForModeTest("legacy-raw", "home", "wg", prefs),
		recordForModeTest("auto", "home", "smart-auto", prefs),
		recordForModeTest("external", "ext", "external", nil),
		recordForModeTest("custom", "home", "custom", &connectionProfilePreferences{CustomLayers: []string{"wireguard"}}),
	}
	for _, record := range valid {
		if _, err := json.Marshal(record); err != nil {
			t.Fatalf("valid saved profile mode %q rejected: %v", record.Mode, err)
		}
	}
}

func TestConnectionProfileRecordRejectsInvalidMetadata(t *testing.T) {
	prefs := &connectionProfilePreferences{KillSwitchPolicy: "off", IPv6Mode: "on", BaseTunnel: "auto", MTUPolicy: "auto"}
	base := recordForModeTest("valid-id", "home", "smart-auto", prefs)
	for name, mutate := range map[string]func(*connectionProfileRecord){
		"bad-id": func(p *connectionProfileRecord) { p.ID = "../escape" },
		"bad-node": func(p *connectionProfileRecord) { p.NodeID = "../node" },
		"blank-name": func(p *connectionProfileRecord) { p.Name = "" },
		"bad-created": func(p *connectionProfileRecord) { p.CreatedAt = "yesterday" },
		"bad-updated": func(p *connectionProfileRecord) { p.UpdatedAt = "later-ish" },
		"reversed-time": func(p *connectionProfileRecord) { p.CreatedAt, p.UpdatedAt = profileRecordTestUpdated, profileRecordTestCreated },
	} {
		t.Run(name, func(t *testing.T) {
			record := base
			mutate(&record)
			if _, err := json.Marshal(record); err == nil {
				t.Fatalf("invalid profile metadata %s was marshalable", name)
			}
		})
	}
}

func TestConnectionProfileRecordRejectsUnknownModeOnRead(t *testing.T) {
	var record connectionProfileRecord
	raw := `{"id":"one","name":"One","node_id":"home","mode":"totally-fake-mode","preferences":{"home_lan_access":true},"created_at":"2026-08-24T00:00:00Z","updated_at":"2026-08-24T00:00:01Z"}`
	if err := json.Unmarshal([]byte(raw), &record); err == nil {
		t.Fatal("unknown persisted connection profile mode was accepted on read")
	}
}

func TestConnectionProfileRecordRejectsKindModeMismatchOnRead(t *testing.T) {
	for name, raw := range map[string]string{
		"router-as-external": `{"id":"one","name":"One","node_id":"home","mode":"external","preferences":{"home_lan_access":true},"created_at":"2026-08-24T00:00:00Z","updated_at":"2026-08-24T00:00:01Z"}`,
		"external-as-router": `{"id":"one","name":"One","node_id":"ext","mode":"smart-auto","created_at":"2026-08-24T00:00:00Z","updated_at":"2026-08-24T00:00:01Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var record connectionProfileRecord
			if err := json.Unmarshal([]byte(raw), &record); err == nil {
				t.Fatalf("persisted connection profile kind/mode mismatch %s was accepted", name)
			}
		})
	}
}

func TestConnectionProfileRecordRejectsUnknownFieldsOnRead(t *testing.T) {
	var record connectionProfileRecord
	raw := `{"id":"one","name":"One","node_id":"ext","mode":"external","created_at":"2026-08-24T00:00:00Z","updated_at":"2026-08-24T00:00:01Z","unexpected":"hidden-state"}`
	if err := json.Unmarshal([]byte(raw), &record); err == nil {
		t.Fatal("unknown persisted connection profile record field was silently accepted")
	}
}
