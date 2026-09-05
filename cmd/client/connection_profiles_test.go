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

func TestConnectionProfileStoreRoundTripIsPrivateAndSecretFree(t *testing.T) {
	dir := t.TempDir()
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(dir, "routers.json")}}
	store := connectionProfileStore{Version: connectionProfileStoreVersion, Profiles: []connectionProfileRecord{{
		ID: "profile-one", Name: "Gaming", NodeID: "home-one", Mode: "smart-auto",
		Prefs:     &connectionProfilePreferences{IPv6Mode: "on", MTUPolicy: "auto", KillSwitchPolicy: "on-connect", DNSMode: "home", CustomLayers: []string{"reality", "wireguard"}},
		CreatedAt: "2026-08-20T00:00:00Z", UpdatedAt: "2026-08-20T00:00:00Z",
	}}}
	if err := persistConnectionProfileStore(a, store); err != nil {
		t.Fatal(err)
	}
	path := connectionProfileStorePath(a)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("connection profile store mode = %o, want 600", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"api_token", "private_key", "preshared_key", "socks_username", "socks_password", "password\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("connection profile store unexpectedly contains secret field %q: %s", forbidden, raw)
		}
	}
	loaded, err := loadConnectionProfileStore(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Profiles) != 1 || loaded.Profiles[0].Name != "Gaming" || loaded.Profiles[0].NodeID != "home-one" {
		t.Fatalf("unexpected round trip: %#v", loaded)
	}
}

func TestSnapshotConnectionPreferencesNeverCopiesNodeCredentials(t *testing.T) {
	p := common.RouterProfile{
		ID: "home-one", Name: "Home", NodeKind: "router-vpn", Endpoint: "203.0.113.10",
		RouterAPI: "http://10.77.0.1:8787", APIToken: "TOP-SECRET-API-TOKEN",
		SocksUsername: "private-user", SocksPassword: "private-password",
		BaseTunnel: "wg", IPv6Mode: "on", MTUPolicy: "auto", KillSwitchPolicy: "on-connect",
		DNSMode: "home", MultihopEnabled: true, MultihopEntryID: "entry", MultihopExitID: "exit",
	}
	prefs, err := snapshotConnectionPreferences(p, []string{"wireguard", "reality", "wireguard"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(prefs)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, secret := range []string{"TOP-SECRET-API-TOKEN", "private-user", "private-password", "api_token", "socks_username", "socks_password"} {
		if strings.Contains(text, secret) {
			t.Fatalf("snapshot leaked %q: %s", secret, text)
		}
	}
	if got := strings.Join(prefs.CustomLayers, ","); got != "reality,wireguard" {
		t.Fatalf("normalized custom layers = %q", got)
	}
}

func TestConnectionProfileInputNormalization(t *testing.T) {
	if got, err := normalizeConnectionProfileMode(" SMART-AUTO "); err != nil || got != "smart-auto" {
		t.Fatalf("mode=%q err=%v", got, err)
	}
	if _, err := normalizeConnectionProfileMode("smart auto"); err == nil {
		t.Fatal("mode containing spaces should be rejected")
	}
	layers, err := normalizeConnectionProfileLayers([]string{" WireGuard ", "reality", "wireguard", "xhttp"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(layers, ","); got != "reality,wireguard,xhttp" {
		t.Fatalf("layers=%q", got)
	}
	if _, err := normalizeConnectionProfileLayers([]string{"bad/layer"}); err == nil {
		t.Fatal("unsafe layer token should be rejected")
	}
}

func TestConnectionProfileLoadLegacyDNSInheritancePreservesLinkedNodePolicy(t *testing.T) {
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "routers.json")
	node := common.RouterProfile{
		ID: "home", NodeKind: "router-vpn", Endpoint: "203.0.113.10",
		HomeLANAccess: true, KillSwitchPolicy: "off", IPv6Mode: "on", BaseTunnel: "auto", MTUPolicy: "auto",
		DNSMode: "doh", DNSProtocol: "https", DNSHost: "1.1.1.1", DNSPort: 443,
		DNSServerName: "cloudflare-dns.com", DNSPath: "/dns-query",
	}
	a := &app{
		cfg:      common.ClientConfig{ProfilesFile: profilesPath},
		profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: "home", Profiles: []common.RouterProfile{node}},
		state:    state{Phase: "off", Mode: "off", RouterID: "home"},
	}
	legacyPrefs := &connectionProfilePreferences{
		HomeLANAccess: true, KillSwitchPolicy: "off", IPv6Mode: "on", BaseTunnel: "auto", MTUPolicy: "auto",
		DNSMode: "",
	}
	store := connectionProfileStore{Version: 1, Profiles: []connectionProfileRecord{{
		ID: "legacy-one", Name: "Legacy", NodeID: "home", Mode: "smart-auto", Prefs: legacyPrefs,
		CreatedAt: "2026-08-20T00:00:00Z", UpdatedAt: "2026-08-20T00:00:00Z",
	}}}
	if err := persistConnectionProfileStore(a, store); err != nil {
		t.Fatal(err)
	}
	// Rewrite the store version to legacy v1 after the canonical writer has
	// produced a valid private file, so Load exercises the real migration path.
	path := connectionProfileStorePath(a)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"version": 4`, `"version": 1`, 1))
	if err := atomicWritePrivate(path, raw); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/connection-profile/load", strings.NewReader(`{"id":"legacy-one"}`))
	rr := httptest.NewRecorder()
	a.loadConnectionProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy profile load status=%d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	got := a.profiles.Profiles[0]
	a.mu.Unlock()
	if got.DNSMode != node.DNSMode || got.DNSProtocol != node.DNSProtocol || got.DNSHost != node.DNSHost || got.DNSPort != node.DNSPort || got.DNSServerName != node.DNSServerName || got.DNSPath != node.DNSPath {
		t.Fatalf("legacy profile load overwrote linked-node DNS policy: got=%+v want=%+v", got, node)
	}
}

func TestConnectionProfileLoadPersistenceFailureRestoresRuntimeOptionState(t *testing.T) {
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "routers.json")
	if err := os.Mkdir(profilesPath, 0o700); err != nil {
		t.Fatal(err)
	}
	node := common.RouterProfile{ID: "home", NodeKind: "router-vpn", Endpoint: "203.0.113.10", MTUPolicy: "auto", DAITAEnabled: false, JumboTUN: false, SocksEnabled: false}
	a := &app{
		cfg:      common.ClientConfig{ProfilesFile: profilesPath},
		profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: "home", Profiles: []common.RouterProfile{node}},
		state:    state{Phase: "off", Mode: "off", RouterID: "home", DAITA: false, Jumbo: false, Socks: false},
	}
	prefs, err := snapshotConnectionPreferences(node, nil)
	if err != nil {
		t.Fatal(err)
	}
	prefs.DAITAEnabled = true
	prefs.JumboTUN = true
	prefs.SocksEnabled = true
	store := connectionProfileStore{Version: connectionProfileStoreVersion, Profiles: []connectionProfileRecord{{
		ID: "saved-one", Name: "Saved", NodeID: "home", Mode: "smart-auto", Prefs: prefs,
		CreatedAt: "2026-08-24T00:00:00Z", UpdatedAt: "2026-08-24T00:00:00Z",
	}}}
	if err := persistConnectionProfileStore(a, store); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/connection-profile/load", strings.NewReader(`{"id":"saved-one"}`))
	rr := httptest.NewRecorder()
	a.loadConnectionProfile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("load persistence failure status=%d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.DAITA || a.state.Jumbo || a.state.Socks {
		t.Fatalf("failed connection-profile load left option state changed: %+v", a.state)
	}
	if a.profiles.SelectedID != "home" || a.state.RouterID != "home" {
		t.Fatalf("failed connection-profile load changed selected identity: selected=%q router=%q", a.profiles.SelectedID, a.state.RouterID)
	}
	if a.profiles.Profiles[0].DAITAEnabled || a.profiles.Profiles[0].JumboTUN || a.profiles.Profiles[0].SocksEnabled {
		t.Fatalf("failed connection-profile load changed profile preferences in RAM: %+v", a.profiles.Profiles[0])
	}
}