package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestDesktopImportedTrioExecutionSavedProfileRetainsSource(t *testing.T) {
	testDesktopImportedExecutionSavedProfile(t, 3)
}

func TestDesktopImportedPrefixExecutionSavedProfileRetainsSource(t *testing.T) {
	for _, count := range []int{4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) { testDesktopImportedExecutionSavedProfile(t, count) })
	}
}

func testDesktopImportedExecutionSavedProfile(t *testing.T, count int) {
	for _, requested := range []string{"server", "auto"} {
		t.Run(requested, func(t *testing.T) {
			a, nodes := savedNodeChainFixture(t, count)
			installDesktopOrderedImportedCipher(t, a, nodes, "2022-blake3-aes-256-gcm", 32)
			response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Imported execution", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes})
			if response.Code != http.StatusOK {
				t.Fatalf("literal imported Save %d: %s", response.Code, response.Body.String())
			}
			store, err := loadConnectionProfileStore(a)
			if err != nil || len(store.Profiles) != 1 {
				t.Fatal("saved imported source absent", err)
			}
			saved := store.Profiles[0]
			if saved.Prefs.MultihopExecution != requested || len(saved.NodeChain) != count || saved.NodeChain[count-2].NodeProofID != "" || saved.NodeChain[count-2].External == nil {
				t.Fatal("saved imported execution replaced identity or purpose")
			}
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
			if response.Code != http.StatusOK {
				t.Fatalf("literal imported Load %d: %s", response.Code, response.Body.String())
			}
			var body map[string]any
			if json.Unmarshal(response.Body.Bytes(), &body) != nil || body["multihop_execution"] != requested || a.cmd != nil || a.state.Connected {
				t.Fatal("Load changed execution or fabricated connection")
			}
			final, _ := profileByID(a.profiles.Profiles, a.profiles.SelectedID)
			if !reflect.DeepEqual(final.MultihopNodes, nodes) || final.MultihopExecution != requested {
				t.Fatal("Load lost complete original prefix")
			}
			for i := range a.profiles.Profiles {
				if a.profiles.Profiles[i].ID == nodes[count-2].ID {
					a.profiles.Profiles[i].External.Shadowsocks.Password = "changed-original-key"
				}
			}
			before := cloneRouterProfileStore(a.profiles)
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
			if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) || a.cmd != nil {
				t.Fatal("saved execution borrowed foreign imported credentials or partially mutated profiles")
			}
		})
	}
}
