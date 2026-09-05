package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeSavedPreferences(t *testing.T, raw string) (connectionProfilePreferences, error) {
	t.Helper()
	var p connectionProfilePreferences
	err := json.Unmarshal([]byte(raw), &p)
	return p, err
}

func TestConnectionProfilePreferencesLegacyDefaultsAreExplicit(t *testing.T) {
	p, err := decodeSavedPreferences(t, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HomeLANAccess || p.KillSwitchPolicy != "off" || p.IPv6Mode != "on" || p.BaseTunnel != "auto" || p.MTUPolicy != "auto" {
		t.Fatalf("legacy defaults were not normalized: %+v", p)
	}
}

func TestConnectionProfilePreferencesRejectUnknownAndInvalidPolicy(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown-secret": `{"api_token":"must-not-survive"}`,
		"bad-kill":       `{"kill_switch_policy":"maybe"}`,
		"bad-mtu":        `{"mtu_policy":"manual","manual_mtu":100}`,
		"bad-dns":        `{"dns_mode":"not-a-dns-mode"}`,
		"bad-dns-host":   `{"dns_mode":"custom","dns_protocol":"udp","dns_host":"bad host","dns_port":53}`,
		"bad-hop":        `{"multihop_enabled":true,"multihop_entry_id":"same","multihop_exit_id":"same"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSavedPreferences(t, raw); err == nil {
				t.Fatalf("invalid preferences accepted: %s", raw)
			}
		})
	}
}

func TestConnectionProfilePreferencesNormalizeSavedDNSAndLayers(t *testing.T) {
	p, err := decodeSavedPreferences(t, `{"dns_mode":"DoH","dns_host":"1.1.1.1","dns_port":0,"dns_server_name":"cloudflare-dns.com","dns_path":"","custom_layers":["WireGuard","reality","wireguard"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.DNSMode != "doh" || p.DNSProtocol != "https" || p.DNSPort != 443 || p.DNSPath != "/dns-query" {
		t.Fatalf("DNS was not normalized: %+v", p)
	}
	if strings.Join(p.CustomLayers, ",") != "reality,wireguard" {
		t.Fatalf("layers were not normalized: %#v", p.CustomLayers)
	}
}

func TestConnectionProfilePreferencesLegacyUnspecifiedDNSStaysUnspecified(t *testing.T) {
	p, err := decodeSavedPreferences(t, `{"ipv6_mode":"on"}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.DNSMode != "" || p.DNSHost != "" || p.DNSPort != 0 {
		t.Fatalf("legacy unspecified DNS was invented: %+v", p)
	}
}
