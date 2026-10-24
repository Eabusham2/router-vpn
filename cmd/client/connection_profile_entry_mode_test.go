package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func TestExternalConnectionProfileRestoresExactEntryModeAndExecution(t *testing.T) {
	count := 0
	for mode := range readModeIDsForProfileTest(t, filepath.Join("..", "..", "configs", "client", "modes.json")) {
		if !mobilemultihop.NodeProfileMode(mode) {
			continue
		}
		count++
		t.Run(mode, func(t *testing.T) {
			a := externalConnectionTestApp(t, "socks5", true)
			a.profiles.Profiles[3].MultihopEntryMode = mode
			a.profiles.Profiles[3].MultihopExecution = "auto"
			id := savedExternalConnectionID(t, a)
			store, err := loadConnectionProfileStore(a)
			if err != nil || store.Profiles[0].External.MultihopEntryMode != mode || store.Profiles[0].External.MultihopExecution != "auto" {
				t.Fatal("saved connection lost its exact entry mode or execution choice", err)
			}
			a.profiles.Profiles[3].MultihopEntryMode = "wg"
			a.profiles.Profiles[3].MultihopExecution = "local"
			response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if response.Code != http.StatusOK {
				t.Fatal(response.Body.String())
			}
			var body map[string]any
			if json.Unmarshal(response.Body.Bytes(), &body) != nil || body["multihop_entry_mode"] != mode || body["multihop_execution"] != "auto" {
				t.Fatal("load response substituted another path selection")
			}
			p := a.profiles.Profiles[3]
			public := publicProfileFor(p)
			if p.MultihopEntryMode != mode || p.MultihopExecution != "auto" || public.MultihopEntryMode != mode || public.MultihopExecution != "auto" || a.state.Connected {
				t.Fatal("load did not restore exact idle preferences")
			}
		})
	}
	if count != 19 {
		t.Fatalf("captured native entry matrix changed: got %d modes", count)
	}
}

func TestExternalConnectionProfileRejectsUnresolvedEntryMode(t *testing.T) {
	a := externalConnectionTestApp(t, "socks5", true)
	p, err := snapshotExternalConnectionPolicy(a.profiles.Profiles[3])
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"auto", "smart-auto", "custom", "unregistered", "WG", " wg", "wg\n"} {
		copy := *p
		copy.MultihopEntryMode = mode
		if copy.validate() == nil {
			t.Fatalf("accepted unresolved or malformed saved entry mode %q", mode)
		}
	}
	p.MultihopEnabled, p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = false, "", "", "wg"
	if p.validate() == nil {
		t.Fatal("direct saved profile retained an unowned entry mode")
	}
	p.MultihopEntryMode = ""
	if p.validate() != nil {
		t.Fatal("legacy direct profile lost its compatible blank entry selection")
	}
}
