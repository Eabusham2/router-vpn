package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestConnectionProfileStoreAllowsLegacyMissingVersion(t *testing.T) {
	var store connectionProfileStore
	if err := json.Unmarshal([]byte(`{"profiles":[]}`), &store); err != nil {
		t.Fatalf("legacy store without version rejected before migration: %v", err)
	}
	if store.Version != 0 || len(store.Profiles) != 0 {
		t.Fatalf("legacy store decoded unexpectedly: %+v", store)
	}
}

func TestConnectionProfileStoreRejectsUnknownTopLevelField(t *testing.T) {
	var store connectionProfileStore
	raw := []byte(`{"version":4,"profiles":[],"future_state":{"enabled":true}}`)
	if err := json.Unmarshal(raw, &store); err == nil {
		t.Fatal("connection profile store silently accepted an unsupported top-level field")
	}
}

func externalRecordJSON(id string) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"node_id":%q,"mode":"external","created_at":"2026-08-24T00:00:00Z","updated_at":"2026-08-24T00:00:01Z"}`, id, id, "node-"+id)
}

func TestConnectionProfileStoreRejectsDuplicateProfileIDs(t *testing.T) {
	var store connectionProfileStore
	record := externalRecordJSON("same")
	raw := `{"version":4,"profiles":[` + record + `,` + record + `]}`
	if err := json.Unmarshal([]byte(raw), &store); err == nil {
		t.Fatal("connection profile store silently accepted duplicate profile ids")
	}
}

func TestConnectionProfileStoreRejectsTooManyProfiles(t *testing.T) {
	rows := make([]string, 0, connectionProfileStoreMaxEntries+1)
	for i := 0; i <= connectionProfileStoreMaxEntries; i++ {
		rows = append(rows, externalRecordJSON(fmt.Sprintf("p-%d", i)))
	}
	var store connectionProfileStore
	raw := `{"version":4,"profiles":[` + strings.Join(rows, ",") + `]}`
	if err := json.Unmarshal([]byte(raw), &store); err == nil {
		t.Fatal("connection profile store silently accepted more than the configured profile limit")
	}
}
