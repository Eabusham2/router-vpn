package mobiletor

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

func desktopOrdinaryEntryFixture(t *testing.T, protocol string) (map[string]any, map[string]any) {
	t.Helper()
	base := protocol
	if protocol == "amneziawg" || protocol == "openvpn" {
		base = "wireguard"
	}
	profile, graph := externalTorPredecessorFixture(t, base)
	if protocol == base {
		return profile, graph
	}
	external := profile["external"].(map[string]any)
	delete(external, "wireguard")
	external["protocol"] = protocol
	var endpoint map[string]any
	if protocol == "openvpn" {
		config := "client\ndev tun\nremote 198.51.100.20 1194 udp\nremote 2001:db8::24 443 tcp\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint " + strings.Repeat("ab", 32) + "\ntun-mtu 1380\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
		compiled, err := nativeopenvpn.CompileEndpoint(config, "selected-user", "selected-secret", mobilemultihop.ExternalFinalTag, "")
		if err != nil {
			t.Fatal(err)
		}
		endpoint, _ = profileObject(compiled, 4<<20)
		external["openvpn"] = map[string]any{"config": config, "username": "selected-user", "password": "selected-secret"}
	} else {
		key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
		peer := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
		config := "[Interface]\nAddress=10.93.0.2/32,fd93::2/128\nPrivateKey=" + key + "\nMTU=1380\n" +
			"Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n" +
			"[Peer]\nPublicKey=" + peer + "\nPresharedKey=" + key + "\nEndpoint=198.51.100.20:8443\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n"
		compiled, err := mobilemultihop.CompileAmneziaProfile(config, strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		object, _ := profileObject(compiled, 4<<20)
		endpoint = object["endpoint"].(map[string]any)
		endpoint["tag"] = mobilemultihop.ExternalFinalTag
		remote := endpoint["peers"].([]any)[0].(map[string]any)
		port, _ := strconv.Atoi(string(remote["port"].(json.Number)))
		external["amneziawg"] = map[string]any{"private_key": key, "addresses": endpoint["address"], "peer_public_key": peer,
			"preshared_key": key, "endpoint": net.JoinHostPort(remote["address"].(string), strconv.Itoa(port)), "allowed_ips": remote["allowed_ips"],
			"mtu": endpoint["mtu"], "persistent_keepalive_interval": remote["persistent_keepalive_interval"], "parameters": endpoint["amnezia"]}
	}
	graph["endpoints"], graph["outbounds"] = []any{endpoint}, []any{}
	return profile, graph
}

func desktopOrdinaryTorExit(entry *DesktopPredecessor) map[string]any {
	profile := desktopProfile()
	profile["kill_switch_policy"], profile["kill_switch"] = "off", false
	profile["multihop_enabled"], profile["multihop_entry_id"], profile["multihop_exit_id"] = true, entry.ID(), profile["id"]
	profile["multihop_entry_mode"], profile["multihop_exit_mode"], profile["multihop_execution"] = entry.Mode(), "tor-bridge", "local"
	return profile
}

func TestDesktopExternalPredecessorComposesAndReconstructsExactTypedSource(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		for _, dns := range []string{"tcp", "dot", "doh"} {
			for _, target := range []string{"linux", "darwin", "windows"} {
				t.Run(protocol+"/"+dns+"/"+target, func(t *testing.T) {
					profile, graph := desktopOrdinaryEntryFixture(t, protocol)
					profile["dns_protocol"] = dns
					if dns != "tcp" {
						profile["dns_server_name"] = "chosen.example"
					}
					if dns == "doh" {
						profile["dns_path"] = "/chosen-query"
					}
					source, original := torHostEncode(t, profile), torHostEncode(t, graph)
					entry, err := NewDesktopExternalPredecessor(protocol, source, original, strings.Repeat("a", 64))
					if err != nil {
						t.Fatal(err)
					}
					if !entry.IsExternal() || entry.IsRouter() || entry.Proof() != nil || entry.Kind() != ExternalPredecessorProofKind || entry.ID() != "ordinary-entry" {
						t.Fatal("ordinary entry borrowed Router authority")
					}
					exit := desktopOrdinaryTorExit(entry)
					exit["dns_protocol"], exit["dns_server_name"], exit["dns_path"] = dns, profile["dns_server_name"], profile["dns_path"]
					// Absence and null are distinct in the strict source parser.
					if profile["dns_server_name"] == nil {
						delete(exit, "dns_server_name")
					}
					if profile["dns_path"] == nil {
						delete(exit, "dns_path")
					}
					_, plan, _, err := desktopBridgeProfile(torHostEncode(t, exit))
					if err != nil {
						t.Fatal(err)
					}
					egress, err := entry.PhysicalEgress(plan)
					if err != nil {
						t.Fatal(err)
					}
					exit["desktop_physical_egress"] = egress
					path := t.TempDir()
					inputs, err := NewDesktopBridgeCaptureWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, target, filepath.Join(path, "tor"), filepath.Join(path, "session"), entry)
					if err != nil {
						t.Fatal(err)
					}
					adopted := inputs.Policy().Predecessor()
					if !adopted.IsExternal() || adopted.IsRouter() || adopted.Fingerprint() != entry.Fingerprint() || adopted.Config() != entry.Config() || adopted.external.SourceConfig() != original {
						t.Fatal("native reconstruction changed transport identity")
					}
					meta := inputs.Policy().Metadata()
					if meta.EntryProofKind != ExternalPredecessorProofKind || meta.EntrySHA256 != entry.Fingerprint() || meta.EntryMode != protocol || meta.DNSDetour != ProfileOutboundTag || meta.KillSwitchPolicy != "off" {
						t.Fatal("external metadata has another proof or DNS authority", meta)
					}
					compiled, _ := profileObject(inputs.Policy().Config(), 4<<20)
					selected := torHostTagged(t, compiled["dns"].(map[string]any)["servers"], profileDNS)
					bootstrap := torHostTagged(t, compiled["dns"].(map[string]any)["servers"], bootstrapDNS)
					if selected["detour"] != ProfileOutboundTag || bootstrap["detour"] != entry.Tag() || selected["server"] != "9.9.9.9" || selected["server_port"] != json.Number("5353") {
						t.Fatal("selected DNS or PT bootstrap escaped its exact owner")
					}
					capture := inputs.Capture()
					if capture.Predecessor.Schema != 2 || capture.Predecessor.EntryKind != ExternalPredecessorProofKind || string(capture.Predecessor.SourceConfig) != original {
						t.Fatal("missing independent source capture")
					}
					capture.Predecessor.SourceConfig[0] = 'x'
					if string(inputs.Capture().Predecessor.SourceConfig) != original || source != torHostEncode(t, profile) || original != torHostEncode(t, graph) {
						t.Fatal("mutable alias changed private capture")
					}
				})
			}
		}
	}
}

func TestDesktopExternalPredecessorCaptureRejectsCrossKindSourceAndPolicy(t *testing.T) {
	profile, graph := desktopOrdinaryEntryFixture(t, "shadowsocks")
	entry, err := NewDesktopExternalPredecessor("shadowsocks", torHostEncode(t, profile), torHostEncode(t, graph), strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	exit := desktopOrdinaryTorExit(entry)
	for _, defect := range []string{"old-schema", "missing-kind", "router-kind", "unknown-kind", "missing-source", "changed-source", "changed-config", "borrowed-profile", "wrong-mode", "unknown-field", "null-source", "duplicate-key"} {
		t.Run(defect, func(t *testing.T) {
			object, _ := profileObject(torHostEncode(t, entry.Capture()), 8<<20)
			switch defect {
			case "old-schema":
				object["schema"] = 1
			case "missing-kind":
				delete(object, "entry_kind")
			case "router-kind":
				object["entry_kind"] = RouterPredecessorProofKind
			case "unknown-kind":
				object["entry_kind"] = "http-reachability"
			case "missing-source":
				delete(object, "source_config")
			case "changed-source":
				object["source_config"].(map[string]any)["outbounds"].([]any)[0].(map[string]any)["password"] = strings.Repeat("b", 44)
			case "changed-config":
				object["config"].(map[string]any)["route"].(map[string]any)["final"] = "direct"
			case "borrowed-profile":
				object["profile"].(map[string]any)["router_api"] = "http://10.77.0.1:8787"
			case "wrong-mode":
				object["entry_mode"] = "wireguard"
			case "unknown-field":
				object["unowned"] = true
			case "null-source":
				object["source_config"] = nil
			}
			raw := torHostEncode(t, object)
			if defect == "duplicate-key" {
				raw = `{"entry_kind":"external-public-ip",` + raw[1:]
			}
			if captured, err := decodeDesktopPredecessor([]byte(raw)); err == nil || captured != nil {
				t.Fatal("foreign capture admitted", defect)
			}
		})
	}
	for _, field := range []string{"kill_switch_policy", "dns_mode"} {
		changed := desktopOrdinaryTorExit(entry)
		if field == "kill_switch_policy" {
			changed[field] = "always"
		} else {
			changed[field] = "home"
			changed["adguard_ipv4"] = "10.77.0.53"
		}
		if _, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, changed), desktopSession, desktopIsolation, "linux", entry); err == nil {
			t.Fatal("ordinary provider gained private Router authority", field)
		}
	}
	policy, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, "linux", entry)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	proof := DesktopBridgeEntryProof{EntryID: entry.ID(), EntrySHA256: entry.Fingerprint(), EntryKind: ExternalPredecessorProofKind, CheckedAt: now}
	if !policy.Metadata().ValidEntryProof(&proof, now, now) {
		t.Fatal("exact typed proof rejected")
	}
	for _, kind := range []PredecessorProofKind{"", RouterPredecessorProofKind, "reachability"} {
		copy := proof
		copy.EntryKind = kind
		if policy.Metadata().ValidEntryProof(&copy, now, now) {
			t.Fatal("another proof kind accepted", kind)
		}
	}
	copy := *entry
	copy.kind = RouterPredecessorProofKind
	if copy.IsRouter() || copy.entryProof() != nil {
		t.Fatal("kind label alone gained Router authority")
	}
	if _, err := CompileProfileWithPredecessor(torHostEncode(t, exit), desktopSession, entry.Config(), entry.Profile()); err == nil {
		t.Fatal("untyped legacy API admitted ordinary proof")
	}
	if reflect.DeepEqual(entry.Capture().SourceConfig, entry.Capture().Config) {
		t.Fatal("fixture omitted the real policy compiler")
	}
}

func TestDesktopExternalPredecessorPhysicalProjectionAndPTTransportStayExact(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		profile, graph := desktopOrdinaryEntryFixture(t, protocol)
		entry, err := NewDesktopExternalPredecessor(protocol, torHostEncode(t, profile), torHostEncode(t, graph), strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range []string{obfs4Bridge, meekBridge, desktopProtectionWebTunnelBridge, desktopProtectionSnowflakeBridge} {
			t.Run(protocol+"/"+strings.Fields(line)[0], func(t *testing.T) {
				exit := desktopOrdinaryTorExit(entry)
				block := exit["external"].(map[string]any)["tor_bridge"].(map[string]any)
				block["transport"], block["bridges"] = "custom", []string{line}
				policy, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, "linux", entry)
				if line == desktopProtectionSnowflakeBridge && (protocol == "socks5" || protocol == "http-connect" || protocol == "https-connect") {
					if err == nil || policy != nil {
						t.Fatal("Snowflake gained an unowned UDP association")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				plan, _ := policy.Plan()
				egress, err := entry.PhysicalEgress(plan)
				if err != nil {
					t.Fatal(err)
				}
				for _, defect := range []string{"port", "network", "host", "extra", "missing", "unknown", "type", "duplicate"} {
					t.Run(defect, func(t *testing.T) {
						rows := mustProtectionObject(t, egress).([]any)
						first := rows[0].(map[string]any)
						switch defect {
						case "port":
							first["port"] = json.Number("12345")
						case "network":
							if first["network"] == "udp" {
								first["network"] = "tcp"
							} else {
								first["network"] = "udp"
							}
						case "host":
							first["host"] = "203.0.113.200"
						case "extra":
							rows = append(rows, map[string]any{"host": "203.0.113.200", "port": json.Number("443"), "network": "tcp"})
						case "missing":
							rows = rows[1:]
						case "unknown":
							first["unowned"] = true
						case "type":
							first["port"] = "443"
						case "duplicate":
							rows = append(rows, first)
						}
						exit["desktop_physical_egress"] = rows
						if result, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, "linux", entry); err == nil || result != nil {
							t.Fatal("changed physical projection admitted", defect)
						}
					})
				}
			})
		}
	}
}
