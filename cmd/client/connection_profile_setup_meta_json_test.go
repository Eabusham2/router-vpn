package main

import (
	"encoding/json"
	"testing"
)

func TestConnectionProfileSetupMetaAllowsLegacyMissingVersion(t *testing.T) {
	var store connectionProfileSetupMetaStore
	if err := json.Unmarshal([]byte(`{"entries":{"saved-one":{"multihop_exit_mode":"shadowsocks"}}}`), &store); err != nil {
		t.Fatalf("legacy setup metadata without version rejected: %v", err)
	}
	if store.Version != 0 || store.Entries["saved-one"].MultihopExitMode != "shadowsocks" {
		t.Fatalf("legacy setup metadata decoded unexpectedly: %+v", store)
	}
}

func TestConnectionProfileSetupMetaRejectsUnknownFields(t *testing.T) {
	for name, raw := range map[string]string{
		"store-field": `{"version":1,"entries":{},"hidden":true}`,
		"entry-field": `{"version":1,"entries":{"saved-one":{"multihop_exit_mode":"shadowsocks","hidden":true}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var store connectionProfileSetupMetaStore
			if err := json.Unmarshal([]byte(raw), &store); err == nil {
				t.Fatalf("unknown setup metadata field %s was silently accepted", name)
			}
		})
	}
}
