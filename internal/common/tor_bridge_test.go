package common

import (
	"strings"
	"testing"
)

const validObfs4Bridge = "Bridge obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abcdefghijklmnopqrstuvwxyz012345 iat-mode=0"

func torProfile(protocol string, bridges ...string) RouterProfile {
	return RouterProfile{ID: "tor", Name: "Tor Bridge", NodeKind: "external", External: &ExternalNodeConfig{
		Protocol: protocol,
		TorBridge: &ExternalTorBridgeConfig{Bridges: append([]string(nil), bridges...)},
	}}
}

func TestTorBridgeProfileNormalizesAliasWithoutFixedExit(t *testing.T) {
	for _, alias := range []string{"tor", "tor_bridge", "tor-bridge"} {
		p := torProfile(alias, validObfs4Bridge)
		if err := NormalizeRouterProfile(&p); err != nil {
			t.Fatalf("%s rejected: %v", alias, err)
		}
		if p.External == nil || p.External.Protocol != "tor-bridge" || p.External.TorBridge == nil {
			t.Fatalf("%s did not normalize to Tor bridge: %+v", alias, p)
		}
		if p.External.ExpectedPublicIP != "" {
			t.Fatalf("Tor bridge fabricated a fixed exit IP: %q", p.External.ExpectedPublicIP)
		}
		if p.Endpoint != "203.0.113.44" {
			t.Fatalf("Tor catalog endpoint should be the bridge relay, got %q", p.Endpoint)
		}
		if p.External.TorBridge.SocksPort != ExternalTorDefaultSocksPort {
			t.Fatalf("Tor SOCKS default = %d", p.External.TorBridge.SocksPort)
		}
		if got := p.External.TorBridge.Bridges[0]; strings.HasPrefix(got, "Bridge ") || !strings.HasPrefix(got, "obfs4 203.0.113.44:443 ") {
			t.Fatalf("Tor bridge line was not normalized: %q", got)
		}
	}
}

func TestTorBridgeRejectsFixedExpectedExit(t *testing.T) {
	p := torProfile("tor-bridge", validObfs4Bridge)
	p.External.ExpectedPublicIP = "198.51.100.10"
	if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "dynamic circuit exit") {
		t.Fatalf("expected dynamic-exit rejection, got %v", err)
	}
}

func TestTorBridgeRejectsUnsafeOrUnsupportedBridgeLines(t *testing.T) {
	bad := []struct {
		line, want string
	}{
		{"obfs4 10.0.0.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x", "public literal"},
		{"obfs4 203.0.113.44:443 BADFINGERPRINT cert=x", "40 hexadecimal"},
		{"obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 iat-mode=0", "requires cert"},
		{"snowflake 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x", "requires an obfs4"},
		{"obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x exec=/tmp/evil", "unsupported"},
		{"obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x\nSocksPort 0.0.0.0:9999", "control character"},
	}
	for _, tc := range bad {
		p := torProfile("tor-bridge", tc.line)
		if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
			t.Fatalf("bridge %q: wanted %q rejection, got %v", tc.line, tc.want, err)
		}
	}
}

func TestTorBridgeRejectsDuplicateAndReservedSocksPort(t *testing.T) {
	p := torProfile("tor-bridge", validObfs4Bridge, validObfs4Bridge)
	if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate bridge was accepted: %v", err)
	}
	for _, port := range []int{80, 8788, 1098, 1099, 70000} {
		p = torProfile("tor-bridge", validObfs4Bridge)
		p.External.TorBridge.SocksPort = port
		if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "SOCKS port") {
			t.Fatalf("unsafe Tor SOCKS port %d was accepted: %v", port, err)
		}
	}
}

func TestTorBridgeRejectsMixedProtocolBlocks(t *testing.T) {
	p := torProfile("tor-bridge", validObfs4Bridge)
	p.External.SOCKS5 = &ExternalSOCKS5Config{Host: "proxy.example.com", Port: 1080}
	if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "exactly one protocol block") {
		t.Fatalf("Tor plus SOCKS5 block was accepted: %v", err)
	}
}
