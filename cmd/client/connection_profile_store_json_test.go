package main

import (
	"encoding/json"
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
