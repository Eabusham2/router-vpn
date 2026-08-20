package main

import (
	"encoding/json"
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
		Prefs: &connectionProfilePreferences{IPv6Mode: "on", MTUPolicy: "auto", KillSwitchPolicy: "on-connect", DNSMode: "home", CustomLayers: []string{"reality", "wireguard"}},
		CreatedAt: "2026-08-20T00:00:00Z", UpdatedAt: "2026-08-20T00:00:00Z",
	}}}
	if err := persistConnectionProfileStore(a, store); err != nil { t.Fatal(err) }
	path := connectionProfileStorePath(a)
	info, err := os.Stat(path); if err != nil { t.Fatal(err) }
	if got := info.Mode().Perm(); got != 0o600 { t.Fatalf("connection profile store mode = %o, want 600", got) }
	raw, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"api_token", "private_key", "preshared_key", "socks_username", "socks_password", "password\""} {
		if strings.Contains(lower, forbidden) { t.Fatalf("connection profile store unexpectedly contains secret field %q: %s", forbidden, raw) }
	}
	loaded, err := loadConnectionProfileStore(a); if err != nil { t.Fatal(err) }
	if len(loaded.Profiles) != 1 || loaded.Profiles[0].Name != "Gaming" || loaded.Profiles[0].NodeID != "home-one" { t.Fatalf("unexpected round trip: %#v", loaded) }
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
	if err != nil { t.Fatal(err) }
	raw, err := json.Marshal(prefs); if err != nil { t.Fatal(err) }
	text := string(raw)
	for _, secret := range []string{"TOP-SECRET-API-TOKEN", "private-user", "private-password", "api_token", "socks_username", "socks_password"} {
		if strings.Contains(text, secret) { t.Fatalf("snapshot leaked %q: %s", secret, text) }
	}
	if got := strings.Join(prefs.CustomLayers, ","); got != "reality,wireguard" { t.Fatalf("normalized custom layers = %q", got) }
}

func TestConnectionProfileInputNormalization(t *testing.T) {
	if got, err := normalizeConnectionProfileMode(" SMART-AUTO "); err != nil || got != "smart-auto" { t.Fatalf("mode=%q err=%v", got, err) }
	if _, err := normalizeConnectionProfileMode("smart auto"); err == nil { t.Fatal("mode containing spaces should be rejected") }
	layers, err := normalizeConnectionProfileLayers([]string{" WireGuard ", "reality", "wireguard", "xhttp"}); if err != nil { t.Fatal(err) }
	if got := strings.Join(layers, ","); got != "reality,wireguard,xhttp" { t.Fatalf("layers=%q", got) }
	if _, err := normalizeConnectionProfileLayers([]string{"bad/layer"}); err == nil { t.Fatal("unsafe layer token should be rejected") }
}
