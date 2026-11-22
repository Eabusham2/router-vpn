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
	testDesktopImportedExecutionSavedProfileWith(t, count, false)
}

func testDesktopImportedExecutionSavedProfileWith(t *testing.T, count int, hostname bool) {
	for _, requested := range []string{"server", "auto"} {
		t.Run(requested, func(t *testing.T) {
			a, nodes := savedNodeChainFixture(t, count)
			if hostname {
				installDesktopOrderedHostname(t, a, nodes)
			} else {
				installDesktopOrderedImportedCipher(t, a, nodes, "2022-blake3-aes-256-gcm", 32)
			}
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
				if fault == "wrong-position" && count > 3 {
					// Saved records carry policy and source hashes; their credential
					// family is validated against the linked node during restoration.
					// Moving an interior SS reference can describe schema six, but
					// cannot restore the original unmodified requested positions.
					if err := validateSavedNodeChain(changed); err != nil {
						t.Fatal("saved independent interior reference rejected", err)
					}
					selected, found := a.profileByIDLocked(a.profiles.SelectedID)
					original, err := applySavedRouterConnectionPolicy(selected, saved.Prefs)
					if !found || err != nil {
						t.Fatal("original saved control source unavailable", err)
					}
					if _, err := a.restoreConnectionNodeChainLocked(saved, original); err != nil {
						t.Fatal("original saved control and source no longer restore", err)
					}
					if _, err := a.restoreConnectionNodeChainLocked(changed, original); err == nil {
						t.Fatal("changed saved positions restored into the original request")
					}
					if !hostname && count == 4 {
						fresh, rows := savedNodeChainFixture(t, count)
						installDesktopOrderedImportedCipher(t, fresh, rows, "2022-blake3-aes-256-gcm", 32)
						rows[middle-1], rows[middle] = rows[middle], rows[middle-1]
						response := postSetup(t, fresh, "/api/connection-profile/setup/save", map[string]any{
							"name": "Independent interior", "mode": "shadowsocks", "multihop_enabled": true,
							"multihop_execution": requested, "multihop_nodes": rows})
						store, err := loadConnectionProfileStore(fresh)
						if response.Code != http.StatusOK || err != nil || len(store.Profiles) != 1 ||
							!reflect.DeepEqual(store.Profiles[0].Prefs.MultihopNodes, rows) ||
							store.Profiles[0].Prefs.MultihopExecution != requested || store.Profiles[0].NodeChain[middle-1].External == nil {
							t.Fatal("fresh independent literal source did not retain its moved position", response.Code, err)
						}
						loaded := postSetup(t, fresh, "/api/connection-profile/setup/load", map[string]any{"id": store.Profiles[0].ID})
						if loaded.Code != http.StatusOK || fresh.cmd != nil {
							t.Fatal("fresh independent source could not be loaded while disconnected", loaded.Code)
						}
					}
					if hostname {
						moved, err := applySavedRouterConnectionPolicy(selected, changed.Prefs)
						if err != nil {
							t.Fatal("moved saved policy unavailable", err)
						}
						if _, err := a.restoreConnectionNodeChainLocked(changed, moved); err == nil {
							t.Fatal("selected independent reference borrowed a hostname-only imported source")
						}
					}
				} else if validateSavedNodeChain(changed) == nil {
					t.Fatal("saved imported execution admitted changed positional source", fault)
				}
			}
			originalHostname := a.profiles.Profiles[count-2]
			if hostname {
				a.profiles.Profiles[count-2].DNSPort++
				a.profiles.Profiles[count-2].HomeLANAccess = true
			}
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
			if hostname {
				restored := a.profiles.Profiles[count-2]
				if restored.Endpoint != originalHostname.Endpoint || restored.DNSHost != originalHostname.DNSHost || restored.DNSPort != originalHostname.DNSPort || restored.DNSProtocol != "tcp" || restored.HomeLANAccess != originalHostname.HomeLANAccess || !reflect.DeepEqual(restored.External, originalHostname.External) {
					t.Fatal("hostname Load lost exact saved resolver or credentials")
				}
			}
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
			if hostname {
				response = postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": saved.ID})
				remaining, deleteErr := loadConnectionProfileStore(a)
				if response.Code != http.StatusOK || deleteErr != nil || len(remaining.Profiles) != 0 || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("hostname Delete changed private sources or retained saved profile", deleteErr)
				}
			}
			if count > 3 {
				// Independently captured CONNECT prefixes use their own typed source
				// family; generic imported SS captures cannot substitute for it.
				connectApp, connectNodes := desktopCONNECTPrefixCaptureFixture(t, count-2, "wg", "password", "off")
				desktopCONNECTSelectPublicHandler(t, connectApp)
				connectID := saveOrderedConnectionFixture(t, connectApp, connectNodes)
				connectStore, err := loadConnectionProfileStore(connectApp)
				if err != nil || len(connectStore.Profiles) != 1 || connectStore.Profiles[0].ID != connectID || validateSavedNodeChain(connectStore.Profiles[0]) != nil {
					t.Fatal("original longer CONNECT Local source was not captured", err)
				}
				connectStore.Profiles[0].Prefs.MultihopExecution = requested
				if err := validateSavedNodeChain(connectStore.Profiles[0]); err != nil {
					t.Fatal("original complete CONNECT execution source was refused", err)
				}
				connectStore.Profiles[0].NodeChain[count-2].Sources[0].Mode = "external-shadowsocks"
				if validateSavedNodeChain(connectStore.Profiles[0]) == nil {
					t.Fatal("saved CONNECT borrowed generic imported SS source identity")
				}
			}
		})
	}
}
