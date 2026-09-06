package main

import (
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func testMode(id string, layers ...string) common.Mode { return common.Mode{ID: id, Layers: layers, AutoEligible: true} }

func TestAutoRequirementsDefaultOffAllowsPlainEligibleCandidate(t *testing.T) {
	ok, reason := modeMeetsAutoRequirements(testMode("plain", "tcp"), common.RouterProfile{})
	if !ok || reason != "" { t.Fatalf("default-off requirements unexpectedly filtered candidate: ok=%v reason=%q", ok, reason) }
}

func TestStartLayerFiltersAUTOToProvedCompositionPaths(t *testing.T) {
	for _, startLayer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		p := common.RouterProfile{StartLayer: startLayer}
		for _, id := range []string{"shadowsocks", "hysteria2", "naive-h2", "naive-h3"} {
			if ok, reason := modeMeetsAutoRequirements(testMode(id, "tls"), p); !ok {
				t.Fatalf("%s with %s should remain eligible: %s", id, startLayer, reason)
			}
		}
		for _, id := range []string{"wg", "awg2-fast", "reality-vision", "max"} {
			if ok, reason := modeMeetsAutoRequirements(testMode(id, "wireguard"), p); ok || !strings.Contains(reason, "Start Layer") {
				t.Fatalf("%s with %s should be start-layer filtered: ok=%v reason=%q", id, startLayer, ok, reason)
			}
		}
	}
}

func TestStartLayerRejectsInvalidPreferenceBeforeAUTO(t *testing.T) {
	ok, reason := modeMeetsAutoRequirements(testMode("shadowsocks", "shadowsocks2022"), common.RouterProfile{StartLayer: "xor"})
	if ok || !strings.Contains(reason, "invalid Start Layer preference") {
		t.Fatalf("invalid standalone XOR preference was not rejected: ok=%v reason=%q", ok, reason)
	}
}

func TestRequireEncryptedAllowsEncryptedTunnelLayers(t *testing.T) {
	p := common.RouterProfile{AutoRequireEncrypted: true}
	for _, mode := range []common.Mode{
		testMode("wg", "wireguard"),
		testMode("awg", "amneziawg2", "light-obfuscation"),
		testMode("reality", "vless", "reality", "xtls-vision"),
		testMode("hy2", "hysteria2", "quic", "salamander"),
		testMode("ss", "shadowsocks2022"),
	} {
		if ok, reason := modeMeetsAutoRequirements(mode, p); !ok { t.Fatalf("%s should satisfy encryption requirement: %s", mode.ID, reason) }
	}
}

func TestRequireEncryptedRejectsUnrecognizedPlainTransport(t *testing.T) {
	ok, reason := modeMeetsAutoRequirements(testMode("plain", "tcp", "http"), common.RouterProfile{AutoRequireEncrypted: true})
	if ok || !strings.Contains(reason, "Require encrypted") { t.Fatalf("expected encrypted filter rejection, got ok=%v reason=%q", ok, reason) }
}

func TestRequireObfuscationRejectsPlainWireGuard(t *testing.T) {
	ok, reason := modeMeetsAutoRequirements(testMode("wg", "wireguard"), common.RouterProfile{AutoRequireObfuscation: true})
	if ok || !strings.Contains(reason, "Require obfuscation") { t.Fatalf("expected WG obfuscation rejection, got ok=%v reason=%q", ok, reason) }
}

func TestRequireObfuscationAllowsCamouflagedCandidates(t *testing.T) {
	p := common.RouterProfile{AutoRequireObfuscation: true}
	for _, mode := range []common.Mode{
		testMode("awg-fast", "amneziawg2", "light-obfuscation"),
		testMode("awg-strong", "amneziawg2", "strong-obfuscation"),
		testMode("reality", "vless", "reality", "utls-chrome"),
		testMode("hy2", "hysteria2", "quic", "salamander"),
		testMode("xhttp", "vless-pq", "reality", "xhttp", "finalmask"),
	} {
		if ok, reason := modeMeetsAutoRequirements(mode, p); !ok { t.Fatalf("%s should satisfy obfuscation requirement: %s", mode.ID, reason) }
	}
}

func TestBothAutoRequirementsNeedBothProperties(t *testing.T) {
	p := common.RouterProfile{AutoRequireEncrypted: true, AutoRequireObfuscation: true}
	if ok, _ := modeMeetsAutoRequirements(testMode("wg", "wireguard"), p); ok { t.Fatal("plain WireGuard should fail combined requirements") }
	if ok, reason := modeMeetsAutoRequirements(testMode("reality", "vless", "reality", "utls-chrome"), p); !ok { t.Fatalf("REALITY should satisfy both requirements: %s", reason) }
}
