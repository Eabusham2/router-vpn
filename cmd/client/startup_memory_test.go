package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func startupMemoryProfile() common.RouterProfile {
	return common.RouterProfile{
		ID: "home", Name: "Home", Endpoint: "198.51.100.10", RouterAPI: "http://10.77.0.1:8787",
		NodeProofID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PathProbeURL: "http://10.77.0.1:8787/health", BaseTunnel: "wg", DNSMode: "home", DNSProtocol: "udp",
		DNSHost: "10.77.0.1", DNSPort: 53, KillSwitchPolicy: "strict", MTUPolicy: "auto",
	}
}

func TestStartupProfileTokenTracksPathPolicyButNotMeasurementFields(t *testing.T) {
	base := startupMemoryProfile()
	original := startupProfileToken(base)
	if !validStartupProfileToken(original) {
		t.Fatalf("startup token is not one SHA-256 digest: %q", original)
	}

	measurementOnly := base
	measurementOnly.PublicIP = "203.0.113.99"
	measurementOnly.LatencyMedianMs = 15.5
	measurementOnly.LatencyP90Ms = 21.0
	measurementOnly.FastestDNSLatencyMs = 7.2
	if got := startupProfileToken(measurementOnly); got != original {
		t.Fatalf("measurement-owned fields changed last-good identity: got %s want %s", got, original)
	}

	for name, mutate := range map[string]func(*common.RouterProfile){
		"endpoint": func(p *common.RouterProfile) { p.Endpoint = "198.51.100.11" },
		"base": func(p *common.RouterProfile) { p.BaseTunnel = "awg" },
		"dns": func(p *common.RouterProfile) { p.DNSHost = "1.1.1.1" },
		"kill-switch": func(p *common.RouterProfile) { p.KillSwitchPolicy = "off" },
		"encrypted-auto": func(p *common.RouterProfile) { p.AutoRequireEncrypted = true },
		"obfuscated-auto": func(p *common.RouterProfile) { p.AutoRequireObfuscation = true },
	} {
		changed := base
		mutate(&changed)
		if got := startupProfileToken(changed); got == original {
			t.Fatalf("%s policy change did not invalidate last-good profile token", name)
		}
	}
}

func TestStartupSelectionRequiresProfileTokenAndRejectsLegacyState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "startup.json")
	a := &app{cfg: common.ClientConfig{StateFile: path}}

	legacy := startupSelection{RouterID: "home", RuntimeMode: "wg", Base: "wg", UpdatedAt: time.Now().UTC()}
	if err := a.saveStartupSelection(legacy); err == nil {
		t.Fatal("last-good state without a profile token was accepted")
	}

	legacyBody, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacyBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.loadStartupSelection(); err == nil {
		t.Fatal("legacy unbound last-good state was trusted")
	}
}

func TestStartupSelectionRoundTripsBoundProfileToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "startup.json")
	a := &app{cfg: common.ClientConfig{StateFile: path}}
	profile := startupMemoryProfile()
	want := startupSelection{
		RouterID: "home", RuntimeMode: "wg", LogicalMode: "smart-auto", Base: "wg",
		ProfileToken: startupProfileToken(profile), UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := a.saveStartupSelection(want); err != nil {
		t.Fatal(err)
	}
	got, err := a.loadStartupSelection()
	if err != nil {
		t.Fatal(err)
	}
	if got.RouterID != want.RouterID || got.RuntimeMode != want.RuntimeMode || got.LogicalMode != want.LogicalMode || got.Base != want.Base || got.ProfileToken != want.ProfileToken {
		t.Fatalf("last-good round trip mismatch: got %+v want %+v", got, want)
	}
}
