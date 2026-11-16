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
			for _, fault := range []string{"prefix-mode", "wrong-position", "paired-import", "foreign-protocol", "source-digest", "prefix-source", "prefix-identity", "selection-order"} {
				raw, err := json.Marshal(saved)
				var changed connectionProfileRecord
				if err != nil || json.Unmarshal(raw, &changed) != nil {
					t.Fatal("saved imported source clone failed", err)
				}
				middle := count - 2
				switch fault {
				case "prefix-mode":
					changed.NodeChain[middle-1].Mode = "shadowsocks"
					changed.Prefs.MultihopNodes[middle-1].Mode = "shadowsocks"
				case "wrong-position":
					changed.NodeChain[middle-1], changed.NodeChain[middle] = changed.NodeChain[middle], changed.NodeChain[middle-1]
					changed.Prefs.MultihopNodes[middle-1], changed.Prefs.MultihopNodes[middle] = changed.Prefs.MultihopNodes[middle], changed.Prefs.MultihopNodes[middle-1]
				case "paired-import":
					changed.NodeChain[middle].NodeKind = ""
				case "foreign-protocol":
					changed.NodeChain[middle].External.Protocol = "socks5"
				case "source-digest":
					changed.NodeChain[middle].Sources[0].SHA256 = "foreign"
				case "prefix-source":
					changed.NodeChain[middle-1].Sources[0].SHA256 = "foreign"
				case "prefix-identity":
					changed.NodeChain[middle-1].NodeProofID = ""
				case "selection-order":
					changed.Prefs.MultihopNodes[0], changed.Prefs.MultihopNodes[count-1] = changed.Prefs.MultihopNodes[count-1], changed.Prefs.MultihopNodes[0]
				}
				if validateSavedNodeChain(changed) == nil {
					t.Fatal("saved imported execution admitted changed positional source", fault)
				}
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
			response = postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": saved.ID, "name": "Updated imported choice", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes})
			if response.Code != http.StatusOK {
				t.Fatalf("literal imported Update %d: %s", response.Code, response.Body.String())
			}
			updated, err := loadConnectionProfileStore(a)
			if err != nil || len(updated.Profiles) != 1 || updated.Profiles[0].Prefs.MultihopExecution != requested || !reflect.DeepEqual(updated.Profiles[0].NodeChain, saved.NodeChain) {
				t.Fatal("Update changed original imported members or choice", err)
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
			if count > 3 {
				// A complete, independently captured longer CONNECT Local path
				// cannot borrow the generic SS execution length admission.
				connectApp, connectNodes := desktopCONNECTPrefixCaptureFixture(t, count-2, "wg", "password", "off")
				desktopCONNECTSelectPublicHandler(t, connectApp)
				connectID := saveOrderedConnectionFixture(t, connectApp, connectNodes)
				connectStore, err := loadConnectionProfileStore(connectApp)
				if err != nil || len(connectStore.Profiles) != 1 || connectStore.Profiles[0].ID != connectID || validateSavedNodeChain(connectStore.Profiles[0]) != nil {
					t.Fatal("original longer CONNECT Local source was not captured", err)
				}
				connectStore.Profiles[0].Prefs.MultihopExecution = requested
				if validateSavedNodeChain(connectStore.Profiles[0]) == nil {
					t.Fatal("longer saved CONNECT borrowed generic imported SS execution bounds")
				}
			}
		})
	}
}
