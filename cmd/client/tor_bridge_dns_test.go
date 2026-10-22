package main

import (
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func torDNSPolicy(mode, protocol string) common.RouterProfile {
	p := common.RouterProfile{
		ID: "tor-dns", Name: "Tor DNS", NodeKind: "external",
		DNSMode: mode, DNSProtocol: protocol, DNSHost: "1.1.1.1", DNSPort: 53,
		DNSServerName: "cloudflare-dns.com", DNSPath: "/dns-query", FastestDNSHost: "1.1.1.1",
	}
	return p
}

func TestTorBridgeDNSAllowsTCPCompatibleTransports(t *testing.T) {
	cases := []struct{ mode, protocol, wantType string }{
		{"custom", "tcp", "tcp"},
		{"dot", "tls", "tls"},
		{"doh", "https", "https"},
		{"rescue", "https", "https"},
	}
	for _, tc := range cases {
		p := torDNSPolicy(tc.mode, tc.protocol)
		if tc.mode == "dot" {
			p.DNSPort = 853
		}
		if tc.mode == "doh" || tc.mode == "rescue" {
			p.DNSPort = 443
		}
		server, err := selectedTorBridgeDNS(p)
		if err != nil {
			t.Fatalf("%s/%s rejected: %v", tc.mode, tc.protocol, err)
		}
		if got, _ := server["type"].(string); got != tc.wantType {
			t.Fatalf("%s/%s type=%q want %q", tc.mode, tc.protocol, got, tc.wantType)
		}
		if got, _ := server["detour"].(string); got != "custom-exit" {
			t.Fatalf("%s/%s DNS escaped Tor detour: %q", tc.mode, tc.protocol, got)
		}
	}
}

func TestTorBridgeDNSRejectsDatagramTransports(t *testing.T) {
	cases := []struct {
		name    string
		profile common.RouterProfile
		want    string
	}{
		{"custom udp", torDNSPolicy("custom", "udp"), "cannot use UDP"},
		{"fastest udp", torDNSPolicy("fastest", "udp"), "cannot use UDP"},
		{"doh3", torDNSPolicy("doh3", "h3"), "cannot use DoH3/QUIC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "doh3" {
				tc.profile.DNSPort = 443
			}
			_, err := selectedTorBridgeDNS(tc.profile)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestTorBridgeDefaultDNSRequiresExplicitAlternativeForDirectPath(t *testing.T) {
	p := common.RouterProfile{ID: "tor", NodeKind: "external", External: &common.ExternalNodeConfig{
		Protocol: "tor-bridge", TorBridge: &common.ExternalTorBridgeConfig{Bridges: []string{clientTorBridge}},
	}}
	policy, err := externalRuntimePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if policy.DNSMode != "home" || policy.DNSHost != "" {
		t.Fatal("Tor substituted an unselected public resolver")
	}
	if _, err := selectedTorBridgeDNS(policy); err == nil {
		t.Fatal("direct Tor fabricated a route to Home AdGuard")
	}
	// Rescue remains available when the user explicitly selects it.
	policy.DNSMode, policy.DNSProtocol, policy.DNSPort = "rescue", "https", 443
	server, err := selectedTorBridgeDNS(policy)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := server["type"].(string); got != "https" {
		t.Fatalf("default Tor DNS type=%q", got)
	}
}
