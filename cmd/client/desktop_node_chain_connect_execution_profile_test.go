package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"router-vpn/internal/common"
	"testing"
)

func TestDesktopCONNECTTrioExecutionSavedProfileRetainsSource(t *testing.T) {
	testDesktopCONNECTExecutionSavedProfile(t, 3)
}

func testDesktopCONNECTExecutionSavedProfile(t *testing.T, count int) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, requested := range []string{"server", "auto"} {
			t.Run(protocol+"/"+requested, func(t *testing.T) {
				a, nodes := desktopCONNECTPrefixProductApp(t, count-2, "wg", protocol)
				response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Imported execution", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes})
				if response.Code != http.StatusOK {
					t.Fatalf("literal imported Save %d: %s", response.Code, response.Body.String())
				}
				store, err := loadConnectionProfileStore(a)
				if err != nil || len(store.Profiles) != 1 {
					t.Fatal("saved imported source absent", err)
				}
				saved := store.Profiles[0]
				for _, fault := range []string{"long", "final-layer", "middle-kind", "middle-protocol", "source-digest"} {
					raw, _ := json.Marshal(saved)
					var changed connectionProfileRecord
					if json.Unmarshal(raw, &changed) != nil {
						t.Fatal("saved fixture clone")
					}
					switch fault {
					case "long":
						changed.NodeChain = append(changed.NodeChain[:1], append([]connectionProfileNodeChainCapture{changed.NodeChain[0]}, changed.NodeChain[1:]...)...)
						changed.Prefs.MultihopNodes = append(changed.Prefs.MultihopNodes[:1], append([]common.MultihopNodeSelection{changed.Prefs.MultihopNodes[0]}, changed.Prefs.MultihopNodes[1:]...)...)
					case "final-layer":
						changed.NodeChain[count-1].Preferences.StartLayer = "aes-256-gcm"
					case "middle-kind":
						changed.NodeChain[count-2].NodeKind = "router-vpn"
					case "middle-protocol":
						changed.NodeChain[count-2].External.Protocol = "socks5"
					case "source-digest":
						changed.NodeChain[count-2].Sources[0].SHA256 = "foreign"
					}
					if validateSavedNodeChain(changed) == nil {
						t.Fatal("saved CONNECT execution admitted foreign original", fault)
					}
				}

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
					t.Fatal("Load lost original complete CONNECT path")
				}
				response = postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": saved.ID, "name": "Updated CONNECT choice", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes})
				if response.Code != http.StatusOK {
					t.Fatalf("CONNECT Update %d: %s", response.Code, response.Body.String())
				}
				updated, err := loadConnectionProfileStore(a)
				if err != nil || len(updated.Profiles) != 1 || updated.Profiles[0].Prefs.MultihopExecution != requested || !reflect.DeepEqual(updated.Profiles[0].NodeChain, saved.NodeChain) {
					t.Fatal("Update changed original CONNECT members or choice", err)
				}
				for i := range a.profiles.Profiles {
					if a.profiles.Profiles[i].ID == nodes[count-2].ID {
						if protocol == "http-connect" {
							a.profiles.Profiles[i].External.HTTPConnect.Password = "changed-original-key"
						} else {
							a.profiles.Profiles[i].External.HTTPSConnect.Password = "changed-original-key"
						}
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
}
