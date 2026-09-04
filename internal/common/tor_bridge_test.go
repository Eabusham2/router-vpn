package common

import (
	"strings"
	"testing"
)

const validObfs4Bridge = "Bridge obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abcdefghijklmnopqrstuvwxyz012345 iat-mode=0"
const validMeekBridge = "Bridge meek_lite 0.0.2.0:2 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"
const validModernMeekBridge = "Bridge meek_lite 192.0.2.20:80 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com utls=HelloRandomizedALPN"
const validSnowflakeBridge = "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.example.net/ front=cdn.example.net ice=stun:stun.example.net:3478 utls-imitate=hellorandomizedalpn"
const validWebTunnelBridge = "Bridge webtunnel 10.0.0.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF url=https://bridge.example.net/secret ver=0.0.1"

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
		if p.External.TorBridge.Transport != "obfs4" {
			t.Fatalf("Tor transport = %q", p.External.TorBridge.Transport)
		}
		if got := p.External.TorBridge.Bridges[0]; strings.HasPrefix(got, "Bridge ") || !strings.HasPrefix(got, "obfs4 203.0.113.44:443 ") {
			t.Fatalf("Tor bridge line was not normalized: %q", got)
		}
	}
}

func TestTorBridgeSupportsCircumventionTransportFamilies(t *testing.T) {
	cases := []struct {
		name, line, transport, endpoint string
	}{
		{"obfs4", validObfs4Bridge, "obfs4", "203.0.113.44"},
		{"meek alias", strings.Replace(validMeekBridge, "meek_lite", "meek", 1), "meek_lite", "0.0.2.0"},
		{"modern meek no fingerprint", validModernMeekBridge, "meek_lite", "192.0.2.20"},
		{"snowflake", validSnowflakeBridge, "snowflake", "192.0.2.3"},
		{"webtunnel", validWebTunnelBridge, "webtunnel", "10.0.0.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := torProfile("tor-bridge", tc.line)
			if err := NormalizeRouterProfile(&p); err != nil {
				t.Fatalf("normalize %s: %v", tc.name, err)
			}
			if p.External.TorBridge.Transport != tc.transport {
				t.Fatalf("transport=%q want %q", p.External.TorBridge.Transport, tc.transport)
			}
			if p.Endpoint != tc.endpoint {
				t.Fatalf("endpoint=%q want %q", p.Endpoint, tc.endpoint)
			}
			if !strings.HasPrefix(p.External.TorBridge.Bridges[0], tc.transport+" ") {
				t.Fatalf("normalized line=%q", p.External.TorBridge.Bridges[0])
			}
		})
	}
}

func TestTorBridgeCustomAndAutoAllowRecognizedMixedPTSets(t *testing.T) {
	for _, selector := range []string{"custom", "auto"} {
		p := torProfile("tor-bridge", validObfs4Bridge, validWebTunnelBridge, validModernMeekBridge)
		p.External.TorBridge.Transport = selector
		if err := NormalizeRouterProfile(&p); err != nil {
			t.Fatalf("%s mixed recognized PT set rejected: %v", selector, err)
		}
		if p.External.TorBridge.Transport != "custom" {
			t.Fatalf("%s normalized transport=%q, want custom", selector, p.External.TorBridge.Transport)
		}
		if got, err := TorBridgeTransport(p.External.TorBridge); err != nil || got != "custom" {
			t.Fatalf("%s TorBridgeTransport=%q err=%v", selector, got, err)
		}
		if len(p.External.TorBridge.Bridges) != 3 || !strings.HasPrefix(p.External.TorBridge.Bridges[1], "webtunnel ") || !strings.HasPrefix(p.External.TorBridge.Bridges[2], "meek_lite ") {
			t.Fatalf("custom PT lines changed unexpectedly: %#v", p.External.TorBridge.Bridges)
		}
	}
}

func TestTorBridgeTransportSelectorRejectsMismatchAndUnmarkedMixedProfiles(t *testing.T) {
	p := torProfile("tor-bridge", validObfs4Bridge)
	p.External.TorBridge.Transport = "snowflake"
	if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("transport mismatch accepted: %v", err)
	}
	p = torProfile("tor-bridge", validObfs4Bridge, validWebTunnelBridge)
	if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "unless transport=custom") {
		t.Fatalf("unmarked mixed PT profile accepted: %v", err)
	}
}

func TestTorBridgeRejectsCustomTransportInjection(t *testing.T) {
	for _, line := range []string{
		"Bridge custom 203.0.113.9:443 0123456789ABCDEF0123456789ABCDEF01234567 command=/tmp/evil",
		"ClientTransportPlugin snowflake exec /tmp/evil",
		"Bridge obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x\nClientTransportPlugin obfs4 exec /tmp/evil",
	} {
		p := torProfile("tor-bridge", line)
		p.External.TorBridge.Transport = "custom"
		if err := NormalizeRouterProfile(&p); err == nil {
			t.Fatalf("Tor custom injection line was accepted: %q", line)
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
	fp := "0123456789ABCDEF0123456789ABCDEF01234567"
	bad := []struct {
		line, want string
	}{
		{"obfs4 10.0.0.1:443 " + fp + " cert=x", "public literal"},
		{"obfs4 203.0.113.44:443 BADFINGERPRINT cert=x", "40 hexadecimal"},
		{"obfs4 203.0.113.44:443 " + fp + " iat-mode=0", "requires a bounded cert"},
		{"meek_lite 0.0.2.0:2 url=http://blocked.example/ front=front.example", "safe url"},
		{"snowflake 192.0.2.3:80 " + fp + " fingerprint=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://broker.example/ front=front.example ice=stun:stun.example:3478", "matching"},
		{"webtunnel 10.0.0.2:443 " + fp + " url=http://bridge.example/path", "safe url"},
		{"snowflake 192.0.2.3:80 " + fp + " fingerprint=" + fp + " url=https://broker.example/ front=front.example ice=stun:stun.example:3478 exec=/tmp/evil", "unsupported"},
		{"obfs4 203.0.113.44:443 " + fp + " cert=x\nSocksPort 0.0.0.0:9999", "control character"},
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
