package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

const clientTorBridge = "obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abcdefghijklmnopqrstuvwxyz iat-mode=0"
const clientSnowflakeBridge = "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.example.net/ front=cdn.example.net ice=stun:stun.example.net:3478"
const clientWebTunnelBridge = "webtunnel 10.0.0.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF url=https://bridge.example.net/secret ver=0.0.1"

func clientTorProfile(bridges ...string) common.RouterProfile {
	return common.RouterProfile{ID: "tor", Name: "Tor", NodeKind: "external", External: &common.ExternalNodeConfig{
		Protocol: "tor-bridge", TorBridge: &common.ExternalTorBridgeConfig{Bridges: append([]string(nil), bridges...)},
	}}
}

func TestTorBridgeRuntimeNormalizesExactTransportSet(t *testing.T) {
	p := clientTorProfile(clientTorBridge)
	normalized, cfg, transports, host, err := torBridgeProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.External == nil || normalized.External.Protocol != "tor-bridge" || cfg.SocksPort != common.ExternalTorDefaultSocksPort || host != "203.0.113.44" {
		t.Fatalf("Tor bridge runtime normalization wrong: profile=%+v cfg=%+v host=%q", normalized, cfg, host)
	}
	if cfg.Transport != "obfs4" || len(transports) != 1 || transports[0] != "obfs4" {
		t.Fatalf("Tor runtime transport set = cfg=%q set=%v", cfg.Transport, transports)
	}
}

func TestTorBridgeRuntimeAcceptsCustomMixedTransportSet(t *testing.T) {
	p := clientTorProfile(clientTorBridge, clientWebTunnelBridge)
	p.External.TorBridge.Transport = "custom"
	_, cfg, transports, host, err := torBridgeProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Transport != "custom" || host != "203.0.113.44" || len(transports) != 2 || transports[0] != "obfs4" || transports[1] != "webtunnel" {
		t.Fatalf("custom Tor runtime set wrong: cfg=%q transports=%v host=%q", cfg.Transport, transports, host)
	}
}

func installFakeExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTorBridgeTransportBinaryPrefersLyrebird(t *testing.T) {
	dir := t.TempDir()
	lyrebird := installFakeExecutable(t, dir, "lyrebird")
	installFakeExecutable(t, dir, "obfs4proxy")
	t.Setenv("PATH", dir)
	for _, set := range [][]string{{"obfs4"}, {"meek_lite"}, {"snowflake"}, {"webtunnel"}, {"obfs4", "snowflake", "webtunnel"}} {
		got, err := torBridgeTransportBinary(set)
		if err != nil {
			t.Fatalf("Lyrebird set %v rejected: %v", set, err)
		}
		if got != lyrebird {
			t.Fatalf("set %v chose %q, want lyrebird %q", set, got, lyrebird)
		}
	}
}

func TestTorBridgeTransportBinaryScopesLegacyFallback(t *testing.T) {
	dir := t.TempDir()
	legacy := installFakeExecutable(t, dir, "obfs4proxy")
	t.Setenv("PATH", dir)
	if got, err := torBridgeTransportBinary([]string{"obfs4", "meek_lite"}); err != nil || got != legacy {
		t.Fatalf("legacy obfs4/meek fallback: got=%q err=%v", got, err)
	}
	for _, set := range [][]string{{"snowflake"}, {"webtunnel"}, {"obfs4", "snowflake"}} {
		if _, err := torBridgeTransportBinary(set); err == nil || !strings.Contains(err.Error(), "lyrebird") {
			t.Fatalf("modern PT set %v did not fail closed without Lyrebird: %v", set, err)
		}
	}
}

func TestTorBridgeCapabilityIsTruthful(t *testing.T) {
	cap := torBridgeRuntimeCapability()
	if cap.Protocol != "tor-bridge" || !cap.Implemented {
		t.Fatalf("Tor bridge capability missing: %#v", cap)
	}
	if !cap.Supported && strings.TrimSpace(cap.Reason) == "" {
		t.Fatalf("unsupported Tor bridge capability has no reason: %#v", cap)
	}
	caps := externalProfileProtocolCapabilities()
	found := false
	for _, item := range caps {
		if item.Protocol == "tor-bridge" {
			found = true
			if !item.Implemented {
				t.Fatalf("Tor bridge external capability is not marked implemented: %#v", item)
			}
		}
	}
	if !found {
		t.Fatal("Tor bridge missing from external profile capabilities")
	}
}

func TestTorDynamicExitMustBePublic(t *testing.T) {
	for _, bad := range []string{"", "not-ip", "127.0.0.1", "10.0.0.1", "::1", "fd00::1"} {
		if _, err := publicTorExit(bad); err == nil {
			t.Fatalf("invalid Tor exit %q was accepted", bad)
		}
	}
	if got, err := publicTorExit("8.8.8.8"); err != nil || got != "8.8.8.8" {
		t.Fatalf("public Tor exit rejected: got=%q err=%v", got, err)
	}
}

func TestTorBridgeLauncherRequiresBootstrapAndOwnedCleanup(t *testing.T) {
	body, err := os.ReadFile("../../modes/native-tor-bridge.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, marker := range []string{
		"Bootstrapped 100%",
		"Tor process start is not connectivity",
		"runtime-pids.py",
		"record \"$ROOT\" \"$PID_MODE\" \"$tor_pid\"",
		"record \"$ROOT\" \"$PID_MODE\" \"$sing_pid\"",
		"kill-switch-platform.py",
		"HOMEVPN_ENDPOINT=\"$BRIDGE_ENDPOINT\"",
		"Tor bridge process exited; tearing down full-device path",
		"cleanup-private-runtime.py",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("Tor bridge launcher lost %q", marker)
		}
	}
}

func TestTorBridgeControllerRequiresDynamicTorProofBeforeConnected(t *testing.T) {
	body, err := os.ReadFile("tor_bridge_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	proof := strings.Index(source, "actualIP, proofErr := a.proveTorBridgeExit()")
	connected := strings.Index(source, "a.state.Connected = true")
	persist := strings.Index(source, "persistErr := a.persistProfilesLocked()")
	if proof < 0 || connected < 0 || persist < 0 || !(proof < connected && connected < persist) {
		t.Fatalf("Tor bridge Connected/persistence ordering is not proof -> connected -> durable adoption")
	}
	for _, marker := range []string{
		"beginConnectionOperation()",
		"Tor bridge public-exit proof failed",
		"a.stopOwnedConnectionRuntime(cmd)",
		"a.rollbackProfilesLocked(previousStore)",
		"tor-project-is-tor-passed",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("Tor bridge transaction lost %q", marker)
		}
	}
}

func TestTorBridgeRuntimeSourceKeepsStrictDynamicBootstrapBoundary(t *testing.T) {
	body, err := os.ReadFile("tor_bridge_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, marker := range []string{
		"strictLiteralObfs4",
		"multiple or dynamic/CDN/WebRTC bootstrap egress",
		"set this profile kill switch Off or use one obfs4 bridge",
		"ClientTransportPlugin \" + strings.Join(transports, \",\")",
		"HOMEVPN_TOR_PLUGIN_TRANSPORTS=",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("Tor runtime lost %q", marker)
		}
	}
}
