package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

const torImportObfs4Bridge = "Bridge obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abcdefghijklmnopqrstuvwxyz012345 iat-mode=0"
const torImportSnowflakeBridge = "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.example.net/ front=cdn.example.net ice=stun:stun.example.net:3478 utls-imitate=hellorandomizedalpn"

func torImportTestApp(t *testing.T, profilesFile string) *app {
	t.Helper()
	return &app{
		cfg: common.ClientConfig{ProfilesFile: profilesFile},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion},
		state: state{Mode: "off", Phase: "off", RouterID: "previous"},
	}
}

func existingTorImportProfile(id string) common.RouterProfile {
	return common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID:            id,
		Name:          "Old Tor",
		NodeKind:      "external",
		External: &common.ExternalNodeConfig{Protocol: "tor-bridge", TorBridge: &common.ExternalTorBridgeConfig{
			Transport: "obfs4",
			Bridges:   []string{torImportObfs4Bridge},
			SocksPort: 19050,
		}},
		DNSMode:          "rescue",
		DNSProtocol:      "https",
		DNSHost:          "1.1.1.1",
		DNSPort:          443,
		DNSServerName:    "cloudflare-dns.com",
		DNSPath:          "/dns-query",
		KillSwitchPolicy: "on-connect",
		KillSwitch:       true,
		IPv6Mode:         "on",
		MTUPolicy:        "auto",
		StartupMode:      "manual",
		PublicIP:         "198.51.100.70",
		UseCount:         9,
		LastUsedAt:       "2026-09-01T01:02:03Z",
	}
}

func TestTorBridgeImportDefaultsSingleObfs4Safely(t *testing.T) {
	a := torImportTestApp(t, filepath.Join(t.TempDir(), "routers.json"))
	body := `{"name":"Tor obfs4","transport":"obfs4","bridges":["` + torImportObfs4Bridge + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body))
	rr := httptest.NewRecorder()
	a.torBridgeImport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Tor obfs4 import status=%d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.profiles.Profiles) != 1 {
		t.Fatalf("saved Tor profiles=%d", len(a.profiles.Profiles))
	}
	p := a.profiles.Profiles[0]
	if p.KillSwitchPolicy != "on-connect" || p.DNSMode != "rescue" || p.DNSProtocol != "https" || p.DNSHost != "1.1.1.1" || p.DNSPort != 443 || p.DNSServerName != "cloudflare-dns.com" || p.DNSPath != "/dns-query" {
		t.Fatalf("unsafe Tor defaults: %+v", p)
	}
	if p.External == nil || p.External.TorBridge == nil || p.External.TorBridge.Transport != "obfs4" {
		t.Fatalf("Tor transport was not normalized: %+v", p.External)
	}
	response := rr.Body.String()
	for _, secret := range []string{"cert=", "0123456789ABCDEF0123456789ABCDEF01234567", "203.0.113.44:443"} {
		if strings.Contains(response, secret) {
			t.Fatalf("public Tor import response leaked private bridge material %q: %s", secret, response)
		}
	}
}

func TestTorBridgeImportRejectsDynamicStrictKillSwitch(t *testing.T) {
	a := torImportTestApp(t, filepath.Join(t.TempDir(), "routers.json"))
	body := `{"name":"Tor Snowflake","transport":"snowflake","kill_switch_policy":"always","bridges":["` + torImportSnowflakeBridge + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body))
	rr := httptest.NewRecorder()
	a.torBridgeImport(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "dynamic bootstrap egress") {
		t.Fatalf("dynamic strict Tor import = %d %q", rr.Code, rr.Body.String())
	}
	if len(a.profiles.Profiles) != 0 {
		t.Fatalf("rejected dynamic Tor profile was persisted: %+v", a.profiles.Profiles)
	}
}

func TestTorBridgeImportDefaultsDynamicTransportToKillSwitchOff(t *testing.T) {
	a := torImportTestApp(t, filepath.Join(t.TempDir(), "routers.json"))
	body := `{"name":"Tor Snowflake","transport":"snowflake","bridges":["` + torImportSnowflakeBridge + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body))
	rr := httptest.NewRecorder()
	a.torBridgeImport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Snowflake import status=%d body=%q", rr.Code, rr.Body.String())
	}
	if len(a.profiles.Profiles) != 1 || a.profiles.Profiles[0].KillSwitchPolicy != "off" {
		t.Fatalf("dynamic Tor profile did not default to kill switch off: %+v", a.profiles.Profiles)
	}
}

func TestTorBridgeImportPersistenceFailureRollsBackSelection(t *testing.T) {
	// A directory where the private profile JSON file must be causes persistence
	// to fail after in-memory adoption, exercising the shared import rollback.
	blockedPath := t.TempDir()
	a := torImportTestApp(t, blockedPath)
	a.profiles.SelectedID = "previous"
	body := `{"name":"Tor obfs4","transport":"obfs4","bridges":["` + torImportObfs4Bridge + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body))
	rr := httptest.NewRecorder()
	a.torBridgeImport(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected persistence failure, got %d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.profiles.Profiles) != 0 || a.profiles.SelectedID != "previous" || a.state.RouterID != "previous" {
		t.Fatalf("failed Tor import did not roll back identity/store: profiles=%+v selected=%q router=%q", a.profiles.Profiles, a.profiles.SelectedID, a.state.RouterID)
	}
}

func TestTorBridgeImportExistingIDUpdatesInPlace(t *testing.T) {
	a := torImportTestApp(t, filepath.Join(t.TempDir(), "routers.json"))
	old := existingTorImportProfile("tor-edit")
	a.profiles.Profiles = []common.RouterProfile{old}
	a.profiles.SelectedID = old.ID
	a.state.RouterID = old.ID
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	body := `{"id":"tor-edit","name":"Tor Snowflake","transport":"snowflake","bridges":["` + torImportSnowflakeBridge + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body))
	rr := httptest.NewRecorder()
	a.torBridgeImport(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"updated":true`) {
		t.Fatalf("Tor update status=%d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.profiles.Profiles) != 1 {
		t.Fatalf("Tor update duplicated node: %+v", a.profiles.Profiles)
	}
	p := a.profiles.Profiles[0]
	if p.ID != old.ID || p.Name != "Tor Snowflake" || p.External == nil || p.External.TorBridge == nil || p.External.TorBridge.Transport != "snowflake" {
		t.Fatalf("Tor update did not replace exact node: %+v", p)
	}
	if p.UseCount != old.UseCount || p.LastUsedAt != old.LastUsedAt {
		t.Fatalf("Tor update lost usage metadata: %+v", p)
	}
	if p.PublicIP != "" {
		t.Fatalf("Tor update retained stale observed public exit %q", p.PublicIP)
	}
	if a.profiles.SelectedID != old.ID || a.state.RouterID != old.ID {
		t.Fatalf("Tor update changed stable identity: selected=%q router=%q", a.profiles.SelectedID, a.state.RouterID)
	}
}

func TestTorBridgeImportUpdatePreservesUnrelatedSettingsAndClearsPathMeasurements(t *testing.T) {
	a := torImportTestApp(t, filepath.Join(t.TempDir(), "routers.json"))
	old := existingTorImportProfile("tor-policy")
	old.HomeLANAccess = true
	old.HomeLANCIDRs = []string{"192.168.50.0/24"}
	old.IPv6Mode = "off"
	old.StartupMode = "smart-auto"
	old.AutoConnect = true
	old.AutoRequireEncrypted = true
	old.AutoRequireObfuscation = true
	old.MTUPolicy = "manual"
	old.ManualMTU = 1280
	old.DiagnosticsEnabled = true
	old.DiagnosticsRetentionDays = 21
	old.ShareDiagnostics = true
	old.TelemetryEnabled = true
	old.Location = "Austin"
	old.Latitude = 30.2672
	old.Longitude = -97.7431
	old.DNSMode = "custom"
	old.DNSProtocol = "https"
	old.DNSHost = "9.9.9.9"
	old.DNSPort = 443
	old.DNSServerName = "dns.quad9.net"
	old.DNSPath = "/dns-query"
	old.PublicIP = "198.51.100.70"
	old.LatencySamples = 50
	old.LatencyMedianMs = 13.25
	old.EffectiveMTU = 1280
	old.EffectiveMTUSource = "retest"
	old.EffectiveMTUPathKey = "stale-path"
	old.EffectiveMTUNetworkFingerprint = "stale-network"
	old.EffectiveMTUProfileFingerprint = "stale-profile"
	old.EffectiveMTUMbps = 777
	old.FastestDNSHost = "9.9.9.9"
	old.FastestDNSName = "Quad9"
	old.FastestDNSLatencyMs = 9.5
	old.DNSResults = []common.DNSBenchmarkResult{{Name: "Quad9", Address: "9.9.9.9", LatencyMs: 9.5, Working: true}}
	a.profiles.Profiles = []common.RouterProfile{old}
	a.profiles.SelectedID = old.ID
	a.state.RouterID = old.ID
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	// Name/DNS/location are deliberately omitted. They are not part of the
	// bridge-line replacement, so updating the PT must preserve them.
	body := `{"id":"tor-policy","transport":"snowflake","bridges":["` + torImportSnowflakeBridge + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body))
	rr := httptest.NewRecorder()
	a.torBridgeImport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Tor policy-preserving update status=%d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.profiles.Profiles[0]
	if p.Name != old.Name || !p.HomeLANAccess || len(p.HomeLANCIDRs) != 1 || p.HomeLANCIDRs[0] != old.HomeLANCIDRs[0] || p.IPv6Mode != "off" || p.StartupMode != "smart-auto" || !p.AutoConnect || !p.AutoRequireEncrypted || !p.AutoRequireObfuscation {
		t.Fatalf("Tor update reset ordinary connection preferences: %+v", p)
	}
	if p.MTUPolicy != "manual" || p.ManualMTU != 1280 || !p.DiagnosticsEnabled || p.DiagnosticsRetentionDays != 21 || !p.ShareDiagnostics || !p.TelemetryEnabled {
		t.Fatalf("Tor update reset MTU/diagnostic preferences: %+v", p)
	}
	if p.Location != old.Location || p.Latitude != old.Latitude || p.Longitude != old.Longitude || p.DNSMode != old.DNSMode || p.DNSProtocol != old.DNSProtocol || p.DNSHost != old.DNSHost || p.DNSPort != old.DNSPort || p.DNSServerName != old.DNSServerName || p.DNSPath != old.DNSPath {
		t.Fatalf("Tor update reset location/DNS policy: %+v", p)
	}
	if p.External == nil || p.External.TorBridge == nil || p.External.TorBridge.Transport != "snowflake" || p.KillSwitchPolicy != "off" {
		t.Fatalf("Tor bridge/PT change was not adopted safely: %+v", p)
	}
	if p.PublicIP != "" || p.LatencySamples != 0 || p.LatencyMedianMs != 0 || p.EffectiveMTU != 0 || p.EffectiveMTUSource != "" || p.EffectiveMTUPathKey != "" || p.EffectiveMTUNetworkFingerprint != "" || p.EffectiveMTUProfileFingerprint != "" || p.EffectiveMTUMbps != 0 || p.FastestDNSHost != "" || p.FastestDNSName != "" || p.FastestDNSLatencyMs != 0 || len(p.DNSResults) != 0 {
		t.Fatalf("Tor update retained stale path-dependent measurements: %+v", p)
	}
}

func TestTorBridgeImportExistingNonTorIDRefusesReplacement(t *testing.T) {
	a := torImportTestApp(t, filepath.Join(t.TempDir(), "routers.json"))
	existing := common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID:            "not-tor",
		Name:          "SOCKS node",
		NodeKind:      "external",
		External:      &common.ExternalNodeConfig{Protocol: "socks5"},
	}
	a.profiles.Profiles = []common.RouterProfile{existing}
	body := `{"id":"not-tor","name":"Tor obfs4","transport":"obfs4","bridges":["` + torImportObfs4Bridge + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body))
	rr := httptest.NewRecorder()
	a.torBridgeImport(rr, req)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "non-Tor node") {
		t.Fatalf("non-Tor ID collision = %d %q", rr.Code, rr.Body.String())
	}
	if len(a.profiles.Profiles) != 1 || a.profiles.Profiles[0].External.Protocol != "socks5" {
		t.Fatalf("non-Tor profile was replaced: %+v", a.profiles.Profiles)
	}
}

func TestTorBridgeImportUpdatePersistenceFailureRollsBackExistingNode(t *testing.T) {
	blockedPath := t.TempDir()
	a := torImportTestApp(t, blockedPath)
	old := existingTorImportProfile("tor-edit")
	a.profiles.Profiles = []common.RouterProfile{old}
	a.profiles.SelectedID = old.ID
	a.state.RouterID = old.ID
	body := `{"id":"tor-edit","name":"Tor Snowflake","transport":"snowflake","bridges":["` + torImportSnowflakeBridge + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body))
	rr := httptest.NewRecorder()
	a.torBridgeImport(rr, req)
	if rr.Code < 400 {
		t.Fatalf("expected update persistence failure, got %d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.profiles.Profiles) != 1 {
		t.Fatalf("failed Tor update changed store size: %+v", a.profiles.Profiles)
	}
	p := a.profiles.Profiles[0]
	if p.ID != old.ID || p.Name != old.Name || p.External == nil || p.External.TorBridge == nil || p.External.TorBridge.Transport != "obfs4" || p.PublicIP != old.PublicIP || p.UseCount != old.UseCount || p.LastUsedAt != old.LastUsedAt {
		t.Fatalf("failed Tor update did not restore previous node: got=%+v old=%+v", p, old)
	}
}
