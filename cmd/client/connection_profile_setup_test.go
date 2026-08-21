package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func setupProfileTestApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", dir)
	profilesFile := filepath.Join(dir, "routers.json")
	a := &app{cfg: common.ClientConfig{ProfilesFile: profilesFile}, state: state{Mode: "off", Phase: "off"}}
	a.profiles = common.RouterProfileStore{SelectedID: "home", Profiles: []common.RouterProfile{
		{ID: "home", Name: "Home", NodeKind: "router-vpn", Endpoint: "203.0.113.10", RouterAPI: "http://10.77.0.1:8787", APIToken: "HOME-SECRET", IPv6Mode: "on", MTUPolicy: "auto", DNSMode: "home", KillSwitchPolicy: "on-connect"},
		{ID: "entry", Name: "Entry", NodeKind: "router-vpn", Endpoint: "203.0.113.11", RouterAPI: "http://10.77.0.1:8787", APIToken: "ENTRY-SECRET", IPv6Mode: "on", MTUPolicy: "auto", DNSMode: "home"},
		{ID: "exit", Name: "Exit", NodeKind: "router-vpn", Endpoint: "203.0.113.12", RouterAPI: "http://10.77.0.1:8787", APIToken: "EXIT-SECRET", IPv6Mode: "on", MTUPolicy: "auto", DNSMode: "home"},
		{ID: "external", Name: "External", NodeKind: "external", Endpoint: "198.51.100.9", External: &common.ExternalNodeConfig{Protocol: "socks5", ExpectedPublicIP: "203.0.113.50", SOCKS5: &common.ExternalSOCKS5Config{Host: "198.51.100.9", Port: 1080}}},
	}}
	return a
}

func postSetup(t *testing.T, a *app, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("content-type", "application/json")
	rr := httptest.NewRecorder()
	switch path {
	case "/api/connection-profile/setup/save": a.saveConnectionProfileSetup(rr, req)
	case "/api/connection-profile/setup/update": a.updateConnectionProfileSetup(rr, req)
	case "/api/connection-profile/setup/load": a.loadConnectionProfileSetup(rr, req)
	case "/api/connection-profile/setup/delete": a.deleteConnectionProfileSetup(rr, req)
	default: t.Fatalf("unsupported test path %s", path)
	}
	return rr
}

func TestConnectionProfileSetupStoresExactHopGraphAndNoSecrets(t *testing.T) {
	a := setupProfileTestApp(t)
	rr := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
		"name": "Gaming multihop", "mode": "custom:stealth", "custom_layers": []string{"wireguard", "reality"},
		"multihop_enabled": true, "multihop_entry_id": "entry", "multihop_exit_id": "exit", "multihop_exit_mode": "hysteria2",
	})
	if rr.Code != http.StatusOK { t.Fatalf("save setup status=%d body=%s", rr.Code, rr.Body.String()) }
	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil { t.Fatal(err) }
	profile, _ := response["profile"].(map[string]any)
	id, _ := profile["id"].(string)
	if !validProfileID(id) { t.Fatalf("invalid returned setup id: %#v", response) }

	store, err := loadConnectionProfileStore(a); if err != nil { t.Fatal(err) }
	if len(store.Profiles) != 1 { t.Fatalf("profiles=%#v", store.Profiles) }
	got := store.Profiles[0]
	if got.Mode != "custom:stealth" || got.Prefs == nil { t.Fatalf("unexpected profile=%#v", got) }
	if !got.Prefs.MultihopEnabled || got.Prefs.MultihopEntryID != "entry" || got.Prefs.MultihopExitID != "exit" { t.Fatalf("exact multihop graph not stored: %#v", got.Prefs) }
	if strings.Join(got.Prefs.CustomLayers, ",") != "reality,wireguard" { t.Fatalf("custom layers=%#v", got.Prefs.CustomLayers) }

	meta, err := loadConnectionProfileSetupMeta(a); if err != nil { t.Fatal(err) }
	if meta.Entries[id].MultihopExitMode != "hysteria2" { t.Fatalf("setup meta=%#v", meta) }
	for _, path := range []string{connectionProfileStorePath(a), connectionProfileSetupMetaPath(a)} {
		raw, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
		text := string(raw)
		for _, secret := range []string{"HOME-SECRET", "ENTRY-SECRET", "EXIT-SECRET", "api_token", "private_key", "socks_password"} {
			if strings.Contains(text, secret) { t.Fatalf("%s leaked %q: %s", path, secret, text) }
		}
		info, err := os.Stat(path); if err != nil { t.Fatal(err) }
		if info.Mode().Perm() != 0o600 { t.Fatalf("%s mode=%o want 600", path, info.Mode().Perm()) }
	}
}

func TestConnectionProfileSetupRejectsBadOrExternalHopGraph(t *testing.T) {
	a := setupProfileTestApp(t)
	cases := []map[string]any{
		{"name":"same", "mode":"smart-auto", "multihop_enabled":true, "multihop_entry_id":"entry", "multihop_exit_id":"entry", "multihop_exit_mode":"shadowsocks"},
		{"name":"external", "mode":"smart-auto", "multihop_enabled":true, "multihop_entry_id":"entry", "multihop_exit_id":"external", "multihop_exit_mode":"shadowsocks"},
		{"name":"transport", "mode":"smart-auto", "multihop_enabled":true, "multihop_entry_id":"entry", "multihop_exit_id":"exit", "multihop_exit_mode":"made-up"},
	}
	for _, body := range cases {
		rr := postSetup(t, a, "/api/connection-profile/setup/save", body)
		if rr.Code >= 200 && rr.Code < 300 { t.Fatalf("bad graph unexpectedly accepted: %#v -> %s", body, rr.Body.String()) }
	}
}

func TestConnectionProfileSetupLoadReturnsExactExitTransport(t *testing.T) {
	a := setupProfileTestApp(t)
	saved := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
		"name":"Work", "mode":"smart-auto", "multihop_enabled":true, "multihop_entry_id":"entry", "multihop_exit_id":"exit", "multihop_exit_mode":"hysteria2",
	})
	if saved.Code != http.StatusOK { t.Fatalf("save status=%d %s", saved.Code, saved.Body.String()) }
	var savePayload map[string]any; if err := json.Unmarshal(saved.Body.Bytes(), &savePayload); err != nil { t.Fatal(err) }
	id := savePayload["profile"].(map[string]any)["id"].(string)

	loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id":id})
	if loaded.Code != http.StatusOK { t.Fatalf("load status=%d body=%s", loaded.Code, loaded.Body.String()) }
	var payload map[string]any; if err := json.Unmarshal(loaded.Body.Bytes(), &payload); err != nil { t.Fatal(err) }
	if payload["multihop_exit_mode"] != "hysteria2" || payload["multihop_entry_id"] != "entry" || payload["multihop_exit_id"] != "exit" { t.Fatalf("load lost setup: %#v", payload) }
	if payload["mode"] != "smart-auto" || payload["selected_node_id"] != "home" { t.Fatalf("load lost node/mode: %#v", payload) }
}
