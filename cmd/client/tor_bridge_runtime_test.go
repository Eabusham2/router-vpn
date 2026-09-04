package main

import (
	"os"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

const clientTorBridge = "obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abcdefghijklmnopqrstuvwxyz iat-mode=0"

func clientTorProfile(bridges ...string) common.RouterProfile {
	return common.RouterProfile{ID: "tor", Name: "Tor", NodeKind: "external", External: &common.ExternalNodeConfig{
		Protocol: "tor-bridge", TorBridge: &common.ExternalTorBridgeConfig{Bridges: append([]string(nil), bridges...)},
	}}
}

func TestTorBridgeRuntimeRequiresExactlyOneStrictBridge(t *testing.T) {
	p := clientTorProfile(clientTorBridge)
	normalized, cfg, host, err := torBridgeProfile(p)
	if err != nil { t.Fatal(err) }
	if normalized.External == nil || normalized.External.Protocol != "tor-bridge" || cfg.SocksPort != common.ExternalTorDefaultSocksPort || host != "203.0.113.44" {
		t.Fatalf("Tor bridge runtime normalization wrong: profile=%+v cfg=%+v host=%q", normalized, cfg, host)
	}
	p = clientTorProfile(clientTorBridge, "obfs4 198.51.100.45:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF cert=abcdefghijklmnopqrstuvwxyz iat-mode=0")
	if _, _, _, err := torBridgeProfile(p); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("multi-bridge strict runtime must fail closed until multi-endpoint firewall ownership exists: %v", err)
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
			if !item.Implemented { t.Fatalf("Tor bridge external capability is not marked implemented: %#v", item) }
		}
	}
	if !found { t.Fatal("Tor bridge missing from external profile capabilities") }
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
	if err != nil { t.Fatal(err) }
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
		if !strings.Contains(source, marker) { t.Fatalf("Tor bridge launcher lost %q", marker) }
	}
}

func TestTorBridgeControllerRequiresDynamicTorProofBeforeConnected(t *testing.T) {
	body, err := os.ReadFile("tor_bridge_routes.go")
	if err != nil { t.Fatal(err) }
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
		if !strings.Contains(source, marker) { t.Fatalf("Tor bridge transaction lost %q", marker) }
	}
}
