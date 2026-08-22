package main

import (
	"testing"

	"router-vpn/internal/common"
)

func TestApplyProfileDefaultsLeavesExternalControlPlaneEmpty(t *testing.T) {
	p := common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID:            "external-one",
		Name:          "External SOCKS exit",
		NodeKind:      "external",
		External: &common.ExternalNodeConfig{
			Protocol:         "socks5",
			ExpectedPublicIP: "203.0.113.44",
			SOCKS5: &common.ExternalSOCKS5Config{
				Host: "exit.example",
				Port: 1080,
			},
		},
	}
	if err := common.NormalizeRouterProfile(&p); err != nil {
		t.Fatal(err)
	}
	applyProfileDefaults(&p)
	if p.RouterAPI != "" || p.APIToken != "" || p.AdGuardIPv4 != "" || p.AdGuardIPv6 != "" ||
		p.SocksHost != "" || p.SocksPort != 0 || p.DAITAHost != "" || p.DAITAPort != 0 ||
		p.DAITARateKbps != 0 || p.BaseTunnel != "" || p.PathProbeURL != "" || p.DNSMode != "" ||
		p.DNSHost != "" || p.DNSPort != 0 {
		t.Fatalf("external profile inherited home Router VPN defaults: %+v", p)
	}
	if p.Location != p.Name {
		t.Fatalf("display location default should remain harmless: got %q want %q", p.Location, p.Name)
	}
}

func TestApplyProfileDefaultsStillInitializesRouterVPNNode(t *testing.T) {
	p := common.RouterProfile{ID: "home", Name: "Home Router", NodeKind: "router-vpn"}
	applyProfileDefaults(&p)
	if p.RouterAPI != "http://10.77.0.1:8787" || p.AdGuardIPv4 != "10.77.0.1" ||
		p.SocksHost != "10.77.0.1" || p.SocksPort != 1080 || p.DAITAPort != 45999 ||
		p.DAITARateKbps != 192 || p.BaseTunnel != "wg" || p.DNSMode != "home" ||
		p.PathProbeURL != "http://10.77.0.1:8787/health" {
		t.Fatalf("router-vpn defaults regressed: %+v", p)
	}
}
