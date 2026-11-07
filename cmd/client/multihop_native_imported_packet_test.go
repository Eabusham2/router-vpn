package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
)

func desktopImportedPacketSource(t *testing.T, entry *common.RouterProfile) *common.ExternalWireGuardConfig {
	t.Helper()
	if entry.External.Protocol == "amneziawg" {
		return &entry.External.AmneziaWG.ExternalWireGuardConfig
	}
	if entry.External.Protocol != "wireguard" || entry.External.WireGuard == nil {
		t.Fatal("not an original packet import")
	}
	return entry.External.WireGuard
}

func desktopImportedPacketFixture(t *testing.T, protocol, finalMode, entryLayer, finalLayer string) (string, multihopSelection) {
	t.Helper()
	root, selected := desktopImportedFixture(t, protocol, finalMode)
	packet := desktopImportedPacketSource(t, &selected.Entry)
	packet.PresharedKey, packet.PersistentKeepalive = testWGKey('k'), 23
	selected.Entry.StartLayer, selected.Exit.StartLayer = entryLayer, finalLayer
	if entryLayer != "off" {
		selected.Entry.External.StartLayer = &common.ExternalStartLayer{Mode: entryLayer, API: "http://10.93.0.1:8787",
			Transport: map[string]any{"type": "shadowsocks", "tag": "saved-layer", "server": selected.Entry.Endpoint,
				"server_port": float64(8389), "method": "2022-blake3-aes-256-gcm", "password": testWGKey('l')}}
	}
	selected.Control = cloneRouterProfile(selected.Exit)
	return root, selected
}

func desktopImportedGraphNode(t *testing.T, graph map[string]any, tag string) map[string]any {
	t.Helper()
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := graph[family].([]any)
		for _, raw := range rows {
			if node, ok := raw.(map[string]any); ok && node["tag"] == tag {
				return node
			}
		}
	}
	t.Fatal("missing original graph node", tag)
	return nil
}

func TestDesktopImportedPacketGraphs(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, mode := range []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong", "reality-vision"} {
			for _, entryLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, finalLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(protocol+"/"+mode+"/"+entryLayer+"/"+finalLayer, func(t *testing.T) {
						root, original := desktopImportedPacketFixture(t, protocol, mode, entryLayer, finalLayer)
						before := mustImportedJSON(t, original)
						packet := desktopImportedPacketSource(t, &original.Entry)
						selected, err := captureNativeMultihopSelection(context.Background(), root, original, []string{mode}, nil)
						if err != nil {
							t.Fatal(err)
						}
						launch, err := compileRetainedNativeMultihopLaunch(selected, nil)
						if err != nil {
							t.Fatal(err)
						}
						graph := retainedGraph(t, launch.config)
						entry := desktopImportedGraphNode(t, graph, "entry-wg")
						peer := entry["peers"].([]any)[0].(map[string]any)
						addresses, _ := json.Marshal(packet.Addresses)
						allowed, _ := json.Marshal(packet.AllowedIPs)
						if string(before) != string(mustImportedJSON(t, original)) || selected.Native.validate(selected) != nil ||
							entry["private_key"] != packet.PrivateKey || entry["mtu"] != float64(packet.MTU) ||
							string(mustImportedJSON(t, entry["address"])) != string(addresses) || peer["public_key"] != packet.PeerPublicKey ||
							peer["pre_shared_key"] != packet.PresharedKey || peer["persistent_keepalive_interval"] != float64(packet.PersistentKeepalive) ||
							string(mustImportedJSON(t, peer["allowed_ips"])) != string(allowed) || entry["system"] == true {
							t.Fatal("desktop capture changed original packet keys, addresses, peer, MTU or userspace ownership")
						}
						if protocol == "amneziawg" {
							if string(mustImportedJSON(t, entry["amnezia"])) != string(mustImportedJSON(t, original.Entry.External.AmneziaWG.Parameters)) {
								t.Fatal("original AWG obfuscation fields changed")
							}
						}
						_, portText, _ := net.SplitHostPort(packet.Endpoint)
						port, _ := strconv.Atoi(portText)
						if entryLayer != "off" {
							port = 8389
							if peer["address"] != "10.93.0.1" || entry["detour"] == nil {
								t.Fatal("entry layer lost its original private inside service")
							}
						}
						if len(launch.nodePhysicalEgress) != 1 || launch.nodePhysicalEgress[0].Host != original.Entry.Endpoint ||
							launch.nodePhysicalEgress[0].Port != port || launch.nodePhysicalEgress[0].Network != "udp" {
							t.Fatal("packet path opened a nonphysical peer, proof destination or TCP socket", launch.nodePhysicalEgress)
						}
						dns := graph["dns"].(map[string]any)
						servers := dns["servers"].([]any)
						if len(servers) != 1 || servers[0].(map[string]any)["server"] != original.Exit.AdGuardIPv4 || servers[0].(map[string]any)["detour"] != "proxy" ||
							strings.Contains(string(mustImportedJSON(t, dns)), "1.1.1.1") || strings.Contains(string(launch.config), "entry-private") || len(graph["inbounds"].([]any)) != 3 {
							t.Fatal("packet entry acquired final DNS, paired proof or another system tunnel")
						}
						selected.restoreMTU = 1280
						restored, err := compileRetainedNativeMultihopLaunch(selected, nil)
						if err != nil || !reflect.DeepEqual(launch.nodePhysicalEgress, restored.nodePhysicalEgress) ||
							!reflect.DeepEqual(entry, desktopImportedGraphNode(t, retainedGraph(t, restored.config), "entry-wg")) {
							t.Fatal("restoration rewrote the captured packet owner", err)
						}
						if _, err := mobilemtu.NewPlan(string(restored.config), 1280); err != nil {
							t.Fatal("restored packet envelope is not bounded", err)
						}
						selected.restoreMTU = 9000
						if _, err := compileRetainedNativeMultihopLaunch(selected, nil); err == nil {
							t.Fatal("restoration expanded the original packet envelope")
						}
						if directory := os.Getenv("ROUTERVPN_IMPORTED_DESKTOP_PACKET_FIXTURES"); directory != "" {
							name := protocol + "--" + mode + "--" + entryLayer + "--" + finalLayer + ".json"
							if err := os.WriteFile(filepath.Join(directory, name), launch.config, 0600); err != nil {
								t.Fatal("required original packet graph was not emitted", err)
							}
						}
					})
				}
			}
		}
	}
}

func TestDesktopImportedPacketProfiles(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		t.Run(protocol, func(t *testing.T) { desktopImportedSavedProfileAddLoadUpdateDelete(t, protocol, "wg") })
	}
}

func TestDesktopImportedPacketProof(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		t.Run(protocol, func(t *testing.T) { desktopImportedEntryPublicProofWrongIdentityCancelAndReplacement(t, protocol) })
	}
}

func TestDesktopImportedPacketSourceOwnership(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		root, original := desktopImportedPacketFixture(t, protocol, "wg", "aes-256-gcm", "aes-256-gcm+xor-whitening")
		selected, err := captureNativeMultihopSelection(context.Background(), root, original, []string{original.ExitMode}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, fault := range []string{"private-key", "peer-key", "psk", "address", "allowed-ips", "endpoint", "keepalive", "packet-mtu", "parameters", "public-exit", "final-token", "final-dns", "entry-layer", "final-layer"} {
			t.Run(protocol+"/"+fault, func(t *testing.T) {
				changed := selected
				changed.Entry, changed.Exit = cloneRouterProfile(selected.Entry), cloneRouterProfile(selected.Exit)
				packet := desktopImportedPacketSource(t, &changed.Entry)
				switch fault {
				case "private-key":
					packet.PrivateKey = testWGKey('z')
				case "peer-key":
					packet.PeerPublicKey = testWGKey('z')
				case "psk":
					packet.PresharedKey = testWGKey('z')
				case "address":
					packet.Addresses[0] = "10.94.0.2/32"
				case "allowed-ips":
					packet.AllowedIPs = []string{"192.0.2.0/24"}
				case "endpoint":
					packet.Endpoint = "198.51.100.99:51820"
				case "keepalive":
					packet.PersistentKeepalive++
				case "packet-mtu":
					packet.MTU--
				case "parameters":
					if protocol == "amneziawg" {
						changed.Entry.External.AmneziaWG.Parameters["s4"] = "41"
					} else {
						packet.DNS = []string{"203.0.113.9"}
					}
				case "public-exit":
					changed.Entry.External.ExpectedPublicIP = "203.0.113.99"
				case "final-token":
					changed.Exit.APIToken += "replaced"
				case "final-dns":
					changed.Exit.DNSHost = "203.0.113.99"
				case "entry-layer":
					changed.Entry.External.StartLayer.Transport["password"] = testWGKey('z')
				case "final-layer":
					changed.Exit.StartLayer = "off"
				}
				if selected.Native.validate(changed) == nil {
					t.Fatal("replaced original source retained packet authority", fault)
				}
				if _, err := compileRetainedNativeMultihopLaunch(changed, nil); err == nil {
					t.Fatal("replaced source reached retained native launch", fault)
				}
				if selected.Native.validate(selected) != nil {
					t.Fatal("replacement mutated the captured original")
				}
			})
		}
	}
}

func TestDesktopImportedPacketLimits(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, fault := range []string{"cancel", "undersized-entry", "fixed-overflow", "missing-layer", "server", "auto", "wrong-entry-mode", "openvpn"} {
			t.Run(protocol+"/"+fault, func(t *testing.T) {
				root, selected := desktopImportedPacketFixture(t, protocol, "awg2-strong", "off", "aes-256-gcm")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch fault {
				case "cancel":
					cancel()
				case "undersized-entry":
					desktopImportedPacketSource(t, &selected.Entry).MTU = 1280
				case "fixed-overflow":
					selected.Exit.MTUPolicy, selected.Exit.ManualMTU = "manual", 1499
					selected.Control = cloneRouterProfile(selected.Exit)
				case "missing-layer":
					selected.Entry.StartLayer = "aes-256-gcm"
				default:
					request := multihopConnectRequest{EntryID: selected.Entry.ID, ExitID: selected.Exit.ID, EntryMode: protocol, ExitMode: selected.ExitMode, Execution: "local"}
					switch fault {
					case "server", "auto":
						request.Execution = fault
					case "wrong-entry-mode":
						request.EntryMode = "wg"
					case "openvpn":
						selected.Entry.External.Protocol, request.EntryMode = "openvpn", "openvpn"
					}
					if _, err := resolveNativeMultihopSelection(selected.Control, []common.RouterProfile{selected.Entry, selected.Exit}, request); err == nil {
						t.Fatal("unowned packet selection reached compilation", fault)
					}
					return
				}
				before := cloneRouterProfile(selected.Entry)
				if _, err := captureNativeMultihopSelection(ctx, root, selected, []string{selected.ExitMode}, nil); err == nil {
					t.Fatal("packet source escaped cancellation, layer or complete envelope bound", fault)
				}
				if !reflect.DeepEqual(before, selected.Entry) {
					t.Fatal("rejected packet path rewrote saved policy", fault)
				}
			})
		}
	}
}

func TestDesktopImportedPacketSelectedDNS(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, mode := range []string{"home", "dot", "doh"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				root, selected := desktopImportedPacketFixture(t, protocol, "shadowsocks", "aes-256-gcm+xor-whitening", "aes-256-gcm")
				if mode != "home" {
					selected.Exit.DNSMode, selected.Exit.DNSHost, selected.Exit.DNSServerName = mode, "203.0.113.53", "selected-resolver.example"
					selected.Exit.DNSPort, selected.Exit.DNSPath = 8853, "/original-query"
				}
				selected.Control = cloneRouterProfile(selected.Exit)
				captured, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{selected.ExitMode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				launch, err := compileRetainedNativeMultihopLaunch(captured, nil)
				if err != nil {
					t.Fatal(err)
				}
				wanted, err := expectedDNSSelection(selected.Exit)
				if err != nil || verifySingBoxDNSConfigBytes(launch.config, wanted) != nil {
					t.Fatal("packet entry substituted original final DNS transport, TLS, path or port", err)
				}
				if len(launch.nodePhysicalEgress) != 1 || launch.nodePhysicalEgress[0].Host != selected.Entry.Endpoint {
					t.Fatal("final DNS gained physical bypass")
				}
			})
		}
	}
}
