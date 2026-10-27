package mobiletor

import (
	"strings"
	"testing"
)

func TestDesktopExternalEntryDNSSelectionMatchesCompiledPolicyWithoutRouterAuthority(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		for _, transport := range []string{"tcp", "tls", "https"} {
			t.Run(protocol+"/"+transport, func(t *testing.T) {
				profile, graph := desktopOrdinaryEntryFixture(t, protocol)
				entry, err := NewDesktopExternalPredecessor(protocol, torHostEncode(t, profile), torHostEncode(t, graph), strings.Repeat("a", 64))
				if err != nil {
					t.Fatal(err)
				}
				exit := desktopOrdinaryTorExit(entry)
				exit["dns_mode"], exit["dns_protocol"], exit["dns_host"] = "custom", transport, "9.9.9.9"
				exit["dns_port"], exit["dns_server_name"], exit["dns_path"] = 5353, "selected.example", "/selected?path=tor"
				for _, idle := range []bool{true, false} {
					selected, err := SelectDesktopBridgeDNS(torHostEncode(t, exit), entry.Profile(), idle)
					compiled, compileErr := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, "linux", entry)
					if err != nil || compileErr != nil || selected != compiled.Metadata().DNS || selected.Transport != transport || selected.Port != 5353 || compiled.Metadata().EntryProofKind != ExternalPredecessorProofKind {
						t.Fatal("ordinary editor DNS differs from the actual captured Tor policy", selected, err, compileErr)
					}
				}
			})
		}
	}
}

func TestDesktopExternalEntryDNSRejectsMixedSourcesAndUnownedHome(t *testing.T) {
	for _, fault := range []string{"home", "missing-dns", "udp", "h3", "entry-id", "exit-id", "same-node", "entry-mode", "protocol", "missing-public-ip", "private-public-ip", "mapped-public-ip", "other-transport", "empty-transport", "router-api", "router-token", "router-proof", "server", "compare"} {
		t.Run(fault, func(t *testing.T) {
			profile, graph := desktopOrdinaryEntryFixture(t, "shadowsocks")
			entry, err := NewDesktopExternalPredecessor("shadowsocks", torHostEncode(t, profile), torHostEncode(t, graph), strings.Repeat("a", 64))
			if err != nil {
				t.Fatal(err)
			}
			exit := desktopOrdinaryTorExit(entry)
			external := profile["external"].(map[string]any)
			switch fault {
			case "home":
				exit["dns_mode"], exit["dns_host"] = "home", "10.80.0.53"
			case "missing-dns":
				delete(exit, "dns_mode")
			case "udp", "h3":
				exit["dns_protocol"] = fault
			case "entry-id":
				profile["id"] = "another-entry"
			case "exit-id":
				exit["multihop_exit_id"] = "another-exit"
			case "same-node":
				exit["id"], exit["multihop_exit_id"] = entry.ID(), entry.ID()
			case "entry-mode":
				exit["multihop_entry_mode"] = "hysteria2"
			case "protocol":
				external["protocol"] = "foreign"
			case "missing-public-ip":
				delete(external, "expected_public_ip")
			case "private-public-ip":
				external["expected_public_ip"] = "192.168.50.1"
			case "mapped-public-ip":
				external["expected_public_ip"] = "::ffff:203.0.113.8"
			case "other-transport":
				external["socks5"] = map[string]any{"host": "198.51.100.9", "port": 1080}
			case "empty-transport":
				external["shadowsocks"] = map[string]any{}
			case "router-api":
				profile["router_api"] = "http://10.80.0.1:8787"
			case "router-token":
				profile["api_token"] = "private-token"
			case "router-proof":
				profile["node_proof_id"] = strings.Repeat("a", 64)
			case "server", "compare":
				exit["multihop_execution"] = fault
			}
			for _, idle := range []bool{false, true} {
				if _, err := SelectDesktopBridgeDNS(torHostEncode(t, exit), torHostEncode(t, profile), idle); err == nil {
					t.Fatal("ordinary DNS selection acquired another source or private Home authority", fault, idle)
				}
			}
		})
	}
}
