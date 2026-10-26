package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func routerEntryProfileTestApp(t *testing.T) *app {
	t.Helper()
	a := setupProfileTestApp(t)
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].AdGuardIPv4 = "10.77.0.53"
		if a.profiles.Profiles[i].ID == "exit" {
			a.profiles.Profiles[i].AdGuardIPv4 = "10.88.0.53"
		}
	}
	return a
}

func TestConnectionProfileRouterEntryModeExactRoundTrip(t *testing.T) {
	for _, mode := range mobilemultihop.NodeMultihopEntryModes() {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run(mode+"/"+execution, func(t *testing.T) {
				a := routerEntryProfileTestApp(t)
				body := map[string]any{"name": "Saved native entry", "mode": "smart-auto", "multihop_enabled": true, "multihop_entry_id": "entry", "multihop_exit_id": "exit", "multihop_entry_mode": mode, "multihop_exit_mode": "shadowsocks", "multihop_execution": execution}
				saved := postSetup(t, a, "/api/connection-profile/setup/save", body)
				if saved.Code != http.StatusOK {
					t.Fatal(saved.Body.String())
				}
				var response map[string]any
				if err := json.Unmarshal(saved.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				id := response["profile"].(map[string]any)["id"].(string)
				if response["multihop_entry_mode"] != mode {
					t.Fatal("save response lost the explicit entry")
				}
				body["id"], body["name"] = id, "Updated native entry"
				updated := postSetup(t, a, "/api/connection-profile/setup/update", body)
				if updated.Code != http.StatusOK {
					t.Fatal(updated.Body.String())
				}
				store, err := loadConnectionProfileStore(a)
				if err != nil || len(store.Profiles) != 1 || store.Profiles[0].Prefs.MultihopEntryMode != mode {
					t.Fatalf("saved entry policy: %+v %v", store, err)
				}
				meta, err := loadConnectionProfileSetupMeta(a)
				if err != nil || meta.Entries[id].MultihopEntryMode != mode {
					t.Fatalf("saved entry metadata: %+v %v", meta, err)
				}
				// Loading must replace a different current raw selection while each
				// hop still refers to its original private credentials.
				a.profiles.Profiles[0].MultihopEntryMode = "wg"
				loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
				if loaded.Code != http.StatusOK {
					t.Fatal(loaded.Body.String())
				}
				if err := json.Unmarshal(loaded.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response["multihop_entry_mode"] != mode || response["multihop_execution"] != execution || a.profiles.Profiles[0].MultihopEntryMode != mode || a.state.Connected {
					t.Fatal("load changed the captured entry, execution or connection state")
				}
				for _, node := range a.profiles.Profiles {
					if node.ID == "entry" && node.APIToken != "ENTRY-SECRET" || node.ID == "exit" && node.APIToken != "EXIT-SECRET" {
						t.Fatal("entry mode restore substituted another node's credentials")
					}
				}
				for _, path := range []string{connectionProfileStorePath(a), connectionProfileSetupMetaPath(a)} {
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					for _, secret := range []string{"HOME-SECRET", "ENTRY-SECRET", "EXIT-SECRET", "api_token", "private_key"} {
						if bytes.Contains(raw, []byte(secret)) {
							t.Fatal("entry profile duplicated private node material")
						}
					}
				}
			})
		}
	}
}

func TestConnectionProfileRouterEntryModeRejectsInvalidWithoutMutation(t *testing.T) {
	for name, mode := range map[string]any{"case": "WG", "leading-space": " wg", "trailing-space": "wg ", "auto": "auto", "wireguard-alias": "wireguard", "awg-alias": "awg", "max-unknown": "max-unknown", "openvpn": "openvpn", "socks5": "socks5", "null": nil, "wrong-type": 7} {
		t.Run(name, func(t *testing.T) {
			a := routerEntryProfileTestApp(t)
			before, _ := json.Marshal(a.profiles)
			rr := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Invalid entry", "multihop_enabled": true, "multihop_entry_id": "entry", "multihop_exit_id": "exit", "multihop_entry_mode": mode, "multihop_exit_mode": "shadowsocks"})
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("invalid entry accepted: %d %s", rr.Code, rr.Body.String())
			}
			after, _ := json.Marshal(a.profiles)
			if !bytes.Equal(before, after) {
				t.Fatal("invalid entry request changed private nodes")
			}
			if _, err := os.Stat(connectionProfileStorePath(a)); !os.IsNotExist(err) {
				t.Fatal("invalid entry request created a saved profile")
			}
		})
	}
}

func TestConnectionProfileRouterEntryPersistedSchemasRejectMalformedModes(t *testing.T) {
	for _, value := range []string{`null`, `7`, `"auto"`, `"WG"`, `" wg"`, `"naive"`} {
		var prefs connectionProfilePreferences
		raw := `{"multihop_enabled":true,"multihop_entry_id":"entry","multihop_exit_id":"exit","multihop_entry_mode":` + value + `}`
		if err := json.Unmarshal([]byte(raw), &prefs); err == nil {
			t.Fatal("saved preferences adopted malformed raw entry", value)
		}
		var meta connectionProfileSetupMeta
		if err := json.Unmarshal([]byte(`{"multihop_entry_mode":`+value+`}`), &meta); err == nil {
			t.Fatal("setup metadata adopted malformed raw entry", value)
		}
	}
}

func TestConnectionProfileRouterEntryMetadataCannotOverrideSnapshot(t *testing.T) {
	a := routerEntryProfileTestApp(t)
	saved := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Pinned entry", "multihop_enabled": true, "multihop_entry_id": "entry", "multihop_exit_id": "exit", "multihop_entry_mode": "reality-xhttp", "multihop_exit_mode": "shadowsocks"})
	if saved.Code != http.StatusOK {
		t.Fatal(saved.Body.String())
	}
	var payload map[string]any
	_ = json.Unmarshal(saved.Body.Bytes(), &payload)
	id := payload["profile"].(map[string]any)["id"].(string)
	meta, err := loadConnectionProfileSetupMeta(a)
	if err != nil {
		t.Fatal(err)
	}
	entry := meta.Entries[id]
	entry.MultihopEntryMode = "wg"
	meta.Entries[id] = entry
	if err := persistConnectionProfileSetupMeta(a, meta); err != nil {
		t.Fatal(err)
	}
	a.profiles.SelectedID = "entry"
	a.state.RouterID = "entry"
	before, _ := json.Marshal(a.profiles)
	loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if loaded.Code < 400 {
		t.Fatal("mismatched entry metadata replaced the captured graph")
	}
	after, _ := json.Marshal(a.profiles)
	if !bytes.Equal(before, after) || a.state.RouterID != "entry" {
		t.Fatal("mismatched metadata partially loaded a profile")
	}
	// Missing entry metadata remains a valid legacy mirror; the captured
	// preferences continue to own the exact raw transport.
	entry.MultihopEntryMode = ""
	meta.Entries[id] = entry
	if err := persistConnectionProfileSetupMeta(a, meta); err != nil {
		t.Fatal(err)
	}
	loaded = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if loaded.Code != http.StatusOK || a.profiles.Profiles[0].MultihopEntryMode != "reality-xhttp" {
		t.Fatal("legacy metadata discarded the saved entry mode", loaded.Body.String())
	}
}

func TestConnectionProfileRouterEntryLegacyFallbackAndDisabledCleanup(t *testing.T) {
	for _, mode := range []string{"", "naive-h3"} {
		t.Run(mode, func(t *testing.T) {
			a := routerEntryProfileTestApp(t)
			a.profiles.Profiles[0].MultihopEntryMode = mode
			saved := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Legacy entry", "multihop_enabled": true, "multihop_entry_id": "entry", "multihop_exit_id": "exit", "multihop_exit_mode": "shadowsocks"})
			if saved.Code != http.StatusOK {
				t.Fatal(saved.Body.String())
			}
			var payload map[string]any
			_ = json.Unmarshal(saved.Body.Bytes(), &payload)
			id := payload["profile"].(map[string]any)["id"].(string)
			a.profiles.Profiles[0].MultihopEntryMode = "max-tls-wg"
			loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if loaded.Code != http.StatusOK || a.profiles.Profiles[0].MultihopEntryMode != mode {
				t.Fatal("legacy profile adopted a later raw entry selection", loaded.Body.String())
			}
			updated := postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": id, "name": "Disabled graph", "multihop_enabled": false, "multihop_entry_mode": "max-tls-wg"})
			if updated.Code != http.StatusOK {
				t.Fatal(updated.Body.String())
			}
			loaded = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if loaded.Code != http.StatusOK || a.profiles.Profiles[0].MultihopEnabled || a.profiles.Profiles[0].MultihopEntryMode != "" {
				t.Fatal("disabled graph revived an old raw entry", loaded.Body.String())
			}
		})
	}
}
