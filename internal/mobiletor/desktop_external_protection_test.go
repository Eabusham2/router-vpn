package mobiletor

import (
	"encoding/base64"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func TestDesktopExternalStrictProtectionKeepsCapturedStartLayerSockets(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				profile, graph := desktopOrdinaryEntryFixture(t, protocol)
				profile["start_layer"] = layer
				profile["external"].(map[string]any)["start_layer"] = map[string]any{
					"mode": layer, "api": "http://10.93.0.1:8787",
					"transport": map[string]any{"type": "shadowsocks", "tag": "private-start-layer", "server": "198.51.100.20", "server_port": 8388,
						"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("l", 32)))},
				}
				entry, err := NewDesktopExternalPredecessor(protocol, torHostEncode(t, profile), torHostEncode(t, graph), strings.Repeat("a", 64))
				if err != nil {
					t.Fatal(err)
				}
				exit := desktopOrdinaryTorExit(entry)
				exit["kill_switch_policy"] = "always"
				_, plan, _, err := desktopBridgeProfile(torHostEncode(t, exit))
				if err != nil {
					t.Fatal(err)
				}
				egress, err := entry.PhysicalEgress(plan)
				port, network := 8388, "tcp"
				if layer == "aes-256-gcm+xor-whitening" {
					port = 8389
				}
				if protocol == "hysteria2" {
					network = "udp"
				}
				want := []mobilemultihop.PhysicalEgress{{Host: "198.51.100.20", Port: port, Network: network}}
				if err != nil || !reflect.DeepEqual(egress, want) {
					t.Fatal("strict wrapper opened an inner protocol, proof API or DNS socket", egress, want, err)
				}
				exit["desktop_physical_egress"] = egress
				policy, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, "linux", entry)
				if err != nil || policy.Predecessor().Profile() != entry.Profile() || policy.Predecessor().Config() != entry.Config() {
					t.Fatal("strict admission discarded captured Start Layer credentials or graph", err)
				}
			})
		}
	}
}

func TestDesktopExternalStrictProtectionRequiresExactPhysicalGraph(t *testing.T) {
	plans := [][]string{{obfs4Bridge}, {meekBridge}, {desktopProtectionWebTunnelBridge}, {desktopProtectionSnowflakeBridge}, {obfs4Bridge, meekBridge, desktopProtectionWebTunnelBridge, desktopProtectionSnowflakeBridge}}
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		profile, graph := desktopOrdinaryEntryFixture(t, protocol)
		entry, err := NewDesktopExternalPredecessor(protocol, torHostEncode(t, profile), torHostEncode(t, graph), strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		for _, bridges := range plans {
			for _, target := range []string{"linux", "darwin", "windows"} {
				for _, kill := range []string{"on-connect", "always"} {
					t.Run(protocol+"/"+strings.Fields(bridges[len(bridges)-1])[0]+"/"+target+"/"+kill, func(t *testing.T) {
						exit := desktopOrdinaryTorExit(entry)
						exit["kill_switch_policy"] = kill
						block := exit["external"].(map[string]any)["tor_bridge"].(map[string]any)
						block["transport"], block["bridges"] = "custom", bridges
						_, plan, _, err := desktopBridgeProfile(torHostEncode(t, exit))
						if err != nil {
							t.Fatal(err)
						}
						egress, err := entry.PhysicalEgress(plan)
						if strings.Fields(bridges[len(bridges)-1])[0] == "snowflake" && (protocol == "socks5" || protocol == "http-connect" || protocol == "https-connect") {
							// Even a plausible fixed TCP projection cannot authorize
							// Snowflake's datagrams through these imported transports.
							exit["desktop_physical_egress"] = []mobilemultihop.PhysicalEgress{{Host: "198.51.100.20", Port: 8443, Network: "tcp"}}
							if err == nil {
								t.Fatal("unsupported datagrams gained a fixed physical projection")
							}
							if policy, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, target, entry); err == nil || policy != nil {
								t.Fatal("strict Snowflake borrowed an unowned UDP association")
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						exit["desktop_physical_egress"] = egress
						source := torHostEncode(t, exit)
						directory := t.TempDir()
						inputs, err := NewDesktopBridgeCaptureWithPredecessor(source, desktopSession, desktopIsolation, target, filepath.Join(directory, "tor"), filepath.Join(directory, "session"), entry)
						if err != nil {
							t.Fatal("strict typed ordinary capture did not reconstruct", err)
						}
						policy := inputs.Policy()
						meta, adopted := policy.Metadata(), policy.Predecessor()
						if meta.KillSwitchPolicy != kill || meta.EntryProofKind != ExternalPredecessorProofKind || meta.EntrySHA256 != entry.Fingerprint() ||
							meta.EntryID != entry.ID() || meta.EntryMode != protocol || meta.DNSDetour != ProfileOutboundTag ||
							!adopted.IsExternal() || adopted.IsRouter() || adopted.Proof() != nil || policy.Profile() != source {
							t.Fatal("strict ordinary path changed policy or acquired private Router authority", meta)
						}
						actual, err := adopted.PhysicalEgress(plan)
						if err != nil || !reflect.DeepEqual(actual, egress) {
							t.Fatal("reconstruction changed the physical graph", actual, egress, err)
						}
					})
				}
			}
		}
	}
}

func TestDesktopExternalStrictProtectionRejectsMissingOrForeignAuthority(t *testing.T) {
	profile, graph := desktopOrdinaryEntryFixture(t, "shadowsocks")
	entry, err := NewDesktopExternalPredecessor("shadowsocks", torHostEncode(t, profile), torHostEncode(t, graph), strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing-projection", "nil-projection", "empty-projection", "changed-port", "extra-proof-exception", "kind-label", "missing-proof", "home", "server", "compare", "entry-id", "entry-mode", "changed-profile", "changed-config"} {
		t.Run(fault, func(t *testing.T) {
			owner := *entry
			exit := desktopOrdinaryTorExit(&owner)
			exit["kill_switch_policy"] = "always"
			_, plan, _, err := desktopBridgeProfile(torHostEncode(t, exit))
			if err != nil {
				t.Fatal(err)
			}
			egress, err := owner.PhysicalEgress(plan)
			if err != nil {
				t.Fatal(err)
			}
			exit["desktop_physical_egress"] = egress
			switch fault {
			case "missing-projection":
				delete(exit, "desktop_physical_egress")
			case "nil-projection":
				exit["desktop_physical_egress"] = nil
			case "empty-projection":
				exit["desktop_physical_egress"] = []mobilemultihop.PhysicalEgress{}
			case "changed-port":
				egress[0].Port++
			case "extra-proof-exception":
				exit["desktop_physical_egress"] = append(egress, mobilemultihop.PhysicalEgress{Host: "1.1.1.1", Port: 443, Network: "tcp"})
			case "kind-label":
				owner.kind = RouterPredecessorProofKind
			case "missing-proof":
				owner.external = nil
			case "home":
				exit["dns_mode"], exit["adguard_ipv4"] = "home", "10.77.0.53"
			case "server", "compare":
				exit["multihop_execution"] = fault
			case "entry-id":
				exit["multihop_entry_id"] = "another-entry"
			case "entry-mode":
				exit["multihop_entry_mode"] = "socks5"
			case "changed-profile":
				owner.profile = strings.Replace(owner.profile, "203.0.113.88", "203.0.113.99", 1)
			case "changed-config":
				owner.config = strings.Replace(owner.config, "198.51.100.20", "198.51.100.99", 1)
			}
			if policy, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, "linux", &owner); err == nil || policy != nil {
				t.Fatal("strict ordinary path acquired missing or foreign authority", fault)
			}
		})
	}
}
