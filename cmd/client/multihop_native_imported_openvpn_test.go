package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
)

func desktopImportedOpenVPNProfileFixture(t *testing.T, network string) common.RouterProfile {
	t.Helper()
	profile, err := externalProfileFromCreateRequest(externalProfileCreateRequest{Name: "Original OpenVPN", Protocol: "openvpn", ExpectedPublicIP: "198.51.100.77",
		OpenVPN: &common.ExternalOpenVPNConfig{Config: "client\ndev tun\nproto " + network + "\nremote 203.0.113.24 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint " + strings.Repeat("ab", 32) + "\ntun-mtu 1500\ndata-ciphers AES-256-GCM:AES-128-GCM\n",
			Username: " captured user ", Password: " captured secret "}})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func desktopImportedOpenVPNFixture(t *testing.T, network, finalMode, entryLayer, finalLayer string) (string, multihopSelection) {
	t.Helper()
	root, selected := desktopImportedFixture(t, "openvpn", finalMode)
	entry := desktopImportedOpenVPNProfileFixture(t, network)
	entry.ID, entry.Name = selected.Entry.ID, selected.Entry.Name
	entry.DNSMode, entry.DNSProtocol, entry.DNSHost, entry.DNSPort = "home", "", "", 0
	selected.Entry = entry
	selected.Entry.StartLayer, selected.Exit.StartLayer = entryLayer, finalLayer
	if entryLayer != "off" {
		selected.Entry.External.StartLayer = &common.ExternalStartLayer{Mode: entryLayer, API: "http://10.93.0.1:8787",
			Transport: map[string]any{"type": "shadowsocks", "tag": "saved-layer", "server": entry.Endpoint,
				"server_port": float64(8389), "method": "2022-blake3-aes-256-gcm", "password": testWGKey('l')}}
	}
	selected.Control = cloneRouterProfile(selected.Exit)
	return root, selected
}

func TestDesktopImportedOpenVPNGraphs(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, mode := range []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong", "reality-vision"} {
			for _, first := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, last := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(network+"/"+mode+"/"+first+"/"+last, func(t *testing.T) {
						root, original := desktopImportedOpenVPNFixture(t, network, mode, first, last)
						before := mustImportedJSON(t, original)
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
						if selected.Native.openVPN == nil || launch.importedOpenVPN == nil || launch.importedOpenVPN.original != nil || launch.importedOpenVPN.retired.Load() ||
							entry["system"] != false || entry["username"] != original.Entry.External.OpenVPN.Username || entry["password"] != original.Entry.External.OpenVPN.Password ||
							entry["server"] != original.Entry.Endpoint || entry["server_port"] != float64(1194) || entry["network"] != network || entry["mtu"] != float64(1500) {
							t.Fatal("OpenVPN source, original remote or unmeasured live observation changed", entry)
						}
						port := 1194
						if first != "off" {
							port = 8389
							if entry["detour"] == nil {
								t.Fatal("original Start Layer omitted")
							}
						}
						if len(launch.nodePhysicalEgress) != 1 || launch.nodePhysicalEgress[0].Host != original.Entry.Endpoint || launch.nodePhysicalEgress[0].Port != port || launch.nodePhysicalEgress[0].Network != network {
							t.Fatal("OpenVPN opened a different physical tuple", launch.nodePhysicalEgress)
						}
						dns := graph["dns"].(map[string]any)
						servers := dns["servers"].([]any)
						if len(servers) != 1 || servers[0].(map[string]any)["server"] != original.Exit.AdGuardIPv4 || servers[0].(map[string]any)["detour"] != "proxy" || strings.Contains(string(mustImportedJSON(t, dns)), "1.1.1.1") || len(graph["inbounds"].([]any)) != 3 {
							t.Fatal("OpenVPN replaced final DNS or added another device")
						}
						selected.restoreMTU = 1280
						restored, err := compileRetainedNativeMultihopLaunch(selected, nil)
						if err != nil {
							t.Fatal(err)
						}
						if restored.importedOpenVPN == launch.importedOpenVPN || restored.importedOpenVPN.original != nil || !reflect.DeepEqual(entry, desktopImportedGraphNode(t, retainedGraph(t, restored.config), "entry-wg")) || !reflect.DeepEqual(launch.nodePhysicalEgress, restored.nodePhysicalEgress) {
							t.Fatal("restoration reused the old connection receipt or changed original endpoint")
						}
						if _, err := mobilemtu.NewPlan(string(restored.config), 1280); err != nil {
							t.Fatal(err)
						}
						selected.restoreMTU = 9000
						if _, err := compileRetainedNativeMultihopLaunch(selected, nil); err == nil {
							t.Fatal("restoration enlarged original packet capacity")
						}
						if string(before) != string(mustImportedJSON(t, original)) {
							t.Fatal("preparation changed original profiles")
						}
						if directory := os.Getenv("ROUTERVPN_IMPORTED_DESKTOP_OPENVPN_FIXTURES"); directory != "" {
							if err := os.WriteFile(filepath.Join(directory, network+"--"+mode+"--"+first+"--"+last+".json"), launch.config, 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
}

func TestDesktopImportedOpenVPNProfiles(t *testing.T) {
	desktopImportedSavedProfileAddLoadUpdateDelete(t, "openvpn", "wg")
}
func TestDesktopImportedOpenVPNPublicProof(t *testing.T) {
	desktopImportedEntryPublicProofWrongIdentityCancelAndReplacement(t, "openvpn")
}

func TestDesktopImportedOpenVPNSelectedDNS(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, mode := range []string{"home", "dot", "doh"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				root, original := desktopImportedOpenVPNFixture(t, network, "reality-vision", "aes-256-gcm", "aes-256-gcm+xor-whitening")
				if mode != "home" {
					original.Exit.DNSMode, original.Exit.DNSHost, original.Exit.DNSServerName = mode, "203.0.113.53", "selected-resolver.example"
					original.Exit.DNSPort, original.Exit.DNSPath = 8853, "/original-query"
				}
				original.Control = cloneRouterProfile(original.Exit)
				selected, err := captureNativeMultihopSelection(context.Background(), root, original, []string{original.ExitMode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				launch, err := compileRetainedNativeMultihopLaunch(selected, nil)
				if err != nil {
					t.Fatal(err)
				}
				wanted, err := expectedDNSSelection(original.Exit)
				if err != nil || verifySingBoxDNSConfigBytes(launch.config, wanted) != nil {
					t.Fatal("original final resolver was replaced", err)
				}
				var decoded map[string]any
				if json.Unmarshal(launch.config, &decoded) != nil {
					t.Fatal("native graph")
				}
				if len(launch.nodePhysicalEgress) != 1 || launch.nodePhysicalEgress[0].Host != original.Entry.Endpoint {
					t.Fatal("resolver gained physical bypass")
				}
			})
		}
	}
}

func TestDesktopImportedOpenVPNSourceOwnership(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, fault := range []string{"username", "password", "certificate", "remote", "port", "packet-mtu", "public-exit", "entry-layer", "final-layer", "final-token", "final-dns"} {
			t.Run(network+"/"+fault, func(t *testing.T) {
				root, original := desktopImportedOpenVPNFixture(t, network, "wg", "aes-256-gcm", "aes-256-gcm+xor-whitening")
				selected, err := captureNativeMultihopSelection(context.Background(), root, original, []string{original.ExitMode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				changed := selected
				changed.Entry, changed.Exit = cloneRouterProfile(selected.Entry), cloneRouterProfile(selected.Exit)
				p := changed.Entry.External.OpenVPN
				switch fault {
				case "username":
					p.Username += "replacement"
				case "password":
					p.Password += "replacement"
				case "certificate":
					p.Config = strings.Replace(p.Config, strings.Repeat("ab", 32), strings.Repeat("cd", 32), 1)
				case "remote":
					p.Config = strings.Replace(p.Config, "203.0.113.24", "203.0.113.25", 1)
				case "port":
					p.Config = strings.Replace(p.Config, "1194", "1195", 1)
				case "packet-mtu":
					p.Config = strings.Replace(p.Config, "1500", "1400", 1)
				case "public-exit":
					changed.Entry.External.ExpectedPublicIP = "203.0.113.99"
				case "entry-layer":
					changed.Entry.External.StartLayer.Transport["password"] = testWGKey('z')
				case "final-layer":
					changed.Exit.StartLayer = "off"
				case "final-token":
					changed.Exit.APIToken += "replacement"
				case "final-dns":
					changed.Exit.DNSHost = "203.0.113.99"
				}
				if selected.Native.validate(changed) == nil {
					t.Fatal("replaced source retained original OpenVPN authority", fault)
				}
				if _, err := compileRetainedNativeMultihopLaunch(changed, nil); err == nil {
					t.Fatal("replaced source reached native launch", fault)
				}
				if selected.Native.validate(selected) != nil {
					t.Fatal("replacement changed original capture")
				}
			})
		}
	}
}

func TestDesktopImportedOpenVPNLimits(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, fault := range []string{"cancel", "script", "multiple-remotes", "hostname", "undersized-entry", "fixed-overflow", "missing-layer", "server", "auto", "paired-mode", "third-control"} {
			t.Run(network+"/"+fault, func(t *testing.T) {
				root, selected := desktopImportedOpenVPNFixture(t, network, "awg2-strong", "off", "aes-256-gcm")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch fault {
				case "cancel":
					cancel()
				case "script":
					selected.Entry.External.OpenVPN.Config += "up arbitrary-command\n"
				case "multiple-remotes":
					selected.Entry.External.OpenVPN.Config += "remote 203.0.113.25 1195\n"
				case "hostname":
					selected.Entry.External.OpenVPN.Config = strings.Replace(selected.Entry.External.OpenVPN.Config, "203.0.113.24", "provider.example", 1)
				case "undersized-entry":
					selected.Entry.External.OpenVPN.Config = strings.Replace(selected.Entry.External.OpenVPN.Config, "1500", "1280", 1)
				case "fixed-overflow":
					selected.Exit.MTUPolicy, selected.Exit.ManualMTU = "manual", 1500
					selected.Control = cloneRouterProfile(selected.Exit)
				case "missing-layer":
					selected.Entry.StartLayer = "aes-256-gcm"
				default:
					request := multihopConnectRequest{EntryID: selected.Entry.ID, ExitID: selected.Exit.ID, EntryMode: "openvpn", ExitMode: selected.ExitMode, Execution: "local"}
					switch fault {
					case "server", "auto":
						request.Execution = fault
					case "paired-mode":
						request.EntryMode = "wg"
					case "third-control":
						selected.Control.ID = "unrelated"
					}
					if _, err := resolveNativeMultihopSelection(selected.Control, []common.RouterProfile{selected.Entry, selected.Exit}, request); err == nil {
						t.Fatal("unowned OpenVPN selection admitted", fault)
					}
					return
				}
				before := cloneRouterProfile(selected.Entry)
				if _, err := captureNativeMultihopSelection(ctx, root, selected, []string{selected.ExitMode}, nil); err == nil {
					t.Fatal("unsupported OpenVPN source or capacity admitted", fault)
				}
				if !reflect.DeepEqual(before, selected.Entry) {
					t.Fatal("failed admission rewrote original policy")
				}
			})
		}
	}
}
