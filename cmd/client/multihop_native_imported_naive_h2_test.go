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
	"router-vpn/internal/mobilemultihop"
)

func desktopImportedNaiveH2Fixture(t *testing.T, kind, first, last string) (string, multihopSelection) {
	t.Helper()
	const mode = "naive-h2"
	var root string
	var selected multihopSelection
	switch {
	case strings.HasPrefix(kind, "openvpn-"):
		root, selected = desktopImportedOpenVPNFixture(t, strings.TrimPrefix(kind, "openvpn-"), mode, first, last)
	case kind == "wireguard" || kind == "amneziawg":
		root, selected = desktopImportedPacketFixture(t, kind, mode, first, last)
	default:
		root, selected = desktopImportedFixture(t, kind, mode)
		selected.Entry.StartLayer, selected.Exit.StartLayer = first, last
		if first != "off" {
			selected.Entry.External.StartLayer = &common.ExternalStartLayer{Mode: first, API: "http://10.93.0.1:8787",
				Transport: map[string]any{"type": "shadowsocks", "tag": "saved-layer", "server": selected.Entry.Endpoint,
					"server_port": float64(8389), "method": "2022-blake3-aes-256-gcm", "password": testWGKey('l')}}
		}
	}
	// Explicit user selection for this fixture. The constructor must retain
	// it; it may not rewrite the default Home UDP policy to make CONNECT work.
	selected.Exit.DNSMode, selected.Exit.DNSProtocol = "home", "tcp"
	selected.Exit.DNSHost, selected.Exit.DNSPort = "", 5353
	selected.Control = cloneRouterProfile(selected.Exit)
	directory := filepath.Join(root, "generated", selected.Exit.ID, mode)
	path := filepath.Join(directory, "sing-box.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	graph := retainedGraph(t, raw)
	graph["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["certificate_path"] = "cert.pem"
	raw, err = json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	certificate, _ := nativeMultihopTrafficCertificate(t)
	if err := os.WriteFile(filepath.Join(directory, "cert.pem"), []byte(certificate), 0600); err != nil {
		t.Fatal(err)
	}
	return root, selected
}

func TestDesktopImportedNaiveH2CapturedGraphs(t *testing.T) {
	for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
		for _, first := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, last := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					root, original := desktopImportedNaiveH2Fixture(t, kind, first, last)
					before := mustImportedJSON(t, original)
					selected, err := captureNativeMultihopSelection(context.Background(), root, original, []string{original.ExitMode}, nil)
					if err != nil {
						t.Fatal(err)
					}
					launch, err := compileRetainedNativeMultihopLaunch(selected, nil)
					if err != nil {
						t.Fatal(err)
					}
					graph := retainedGraph(t, launch.config)
					final := desktopImportedGraphNode(t, graph, "routervpn-execution-local")
					if final["type"] != "naive" || final["quic"] != false || selected.Native.validate(selected) != nil || string(before) != string(mustImportedJSON(t, original)) {
						t.Fatal("desktop H2 changed its original selection or native transport")
					}
					files, err := readDesktopNodeAssets(root, original.Exit.ID, original.ExitMode)
					if err != nil {
						t.Fatal(err)
					}
					var start map[string][]byte
					if last != "off" {
						start, err = readDesktopNodeAssets(root, original.Exit.ID, "shadowsocks")
						if err != nil {
							t.Fatal(err)
						}
					}
					node, _, err := compileDesktopNode(context.Background(), original.Exit, original.ExitMode, files, start, nil)
					if err != nil {
						t.Fatal(err)
					}
					originalGraph := retainedGraph(t, []byte(node.Config()))
					copy := map[string]any{}
					for key, value := range final {
						copy[key] = value
					}
					copy["tag"] = "proxy"
					if last == "off" {
						if copy["detour"] != "entry-wg" {
							t.Fatal("H2 final escaped the original imported entry")
						}
						delete(copy, "detour")
					}
					if !reflect.DeepEqual(copy, desktopImportedGraphNode(t, originalGraph, "proxy")) {
						t.Fatal("desktop H2 changed original credentials, UoT, trust, Start Layer or resolver binding")
					}
					if len(launch.nodePhysicalEgress) == 0 {
						t.Fatal("desktop H2 lost its exact physical entry owner")
					}
					for _, tuple := range launch.nodePhysicalEgress {
						if tuple.Host != original.Entry.Endpoint || tuple.Host == original.Exit.Endpoint {
							t.Fatal("desktop H2 final acquired an unowned physical exception")
						}
					}
					servers := graph["dns"].(map[string]any)["servers"].([]any)
					dns, lower := servers[0].(map[string]any), servers[1].(map[string]any)
					if len(servers) != 2 || dns["type"] != "tcp" || dns["server"] != original.Exit.AdGuardIPv4 || dns["server_port"] != float64(5353) || dns["detour"] != "proxy" || lower["type"] != dns["type"] || lower["server"] != dns["server"] || lower["server_port"] != dns["server_port"] || strings.Contains(string(launch.config), "entry-private") {
						t.Fatal("desktop H2 changed selected DNS, bootstrap transport or paired-node authority")
					}
					restored := selected
					restored.restoreMTU = 1280
					again, err := compileRetainedNativeMultihopLaunch(restored, nil)
					if err != nil || !reflect.DeepEqual(again.nodePhysicalEgress, launch.nodePhysicalEgress) {
						t.Fatal("desktop H2 restoration lost its captured physical owner", err)
					}
					_, server := executionFixture()
					if _, err := compileRetainedNativeMultihopLaunch(selected, &server); err == nil {
						t.Fatal("desktop H2 import acquired Server proof authority")
					}
					if directory := os.Getenv("ROUTERVPN_DESKTOP_IMPORTED_NAIVE_H2_FIXTURES"); directory != "" {
						if err := os.WriteFile(filepath.Join(directory, kind+"--naive-h2--"+first+"--"+last+".json"), launch.config, 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestDesktopImportedNaiveH2RejectsChangedAuthority(t *testing.T) {
	for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
		for _, fault := range []string{"h3", "missing-user", "missing-password", "uot-v1", "insecure-tls", "foreign-detour", "missing-assets"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				root, selected := desktopImportedNaiveH2Fixture(t, kind, "off", "off")
				path := filepath.Join(root, "generated", selected.Exit.ID, selected.ExitMode, "sing-box.json")
				if fault == "missing-assets" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else {
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					graph := retainedGraph(t, raw)
					final := graph["outbounds"].([]any)[0].(map[string]any)
					switch fault {
					case "h3":
						final["quic"] = true
					case "missing-user":
						delete(final, "username")
					case "missing-password":
						delete(final, "password")
					case "uot-v1":
						final["udp_over_tcp"].(map[string]any)["version"] = float64(1)
					case "insecure-tls":
						final["tls"].(map[string]any)["insecure"] = true
					case "foreign-detour":
						final["detour"] = "direct"
					}
					raw, _ = json.Marshal(graph)
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{selected.ExitMode}, nil); err == nil {
					t.Fatal("desktop H2 accepted missing or substituted final authority", fault)
				}
			})
		}
	}
}

func TestDesktopImportedNaiveH2CONNECTRetainsSelectedDNSPolicy(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		for _, protocol := range []string{"udp", "hostname-bootstrap", "h3"} {
			t.Run(kind+"/"+protocol, func(t *testing.T) {
				root, selected := desktopImportedNaiveH2Fixture(t, kind, "aes-256-gcm", "aes-256-gcm+xor-whitening")
				selected.Exit.DNSProtocol = protocol
				if protocol == "udp" {
					// A literal H2 endpoint and literal AES/XOR peers need no
					// lower DNS query. Preserve Home UDP over authenticated H2
					// UoT; its dormant lower resolver gains no UDP authority.
					selected.Exit.DNSProtocol = ""
					selected.Exit.DNSPort = 0
				} else if protocol == "hostname-bootstrap" {
					// A selected resolver hostname still needs the captured Home
					// UDP bootstrap. CONNECT cannot supply that lower datagram.
					selected.Exit.DNSMode, selected.Exit.DNSProtocol = "doh", "https"
					selected.Exit.DNSHost, selected.Exit.DNSPort = "resolver.example.net", 8443
					selected.Exit.DNSServerName, selected.Exit.DNSPath = "resolver.example.net", "/captured-query"
				} else {
					selected.Exit.DNSServerName, selected.Exit.DNSPath = "adguard.home.example", "/captured-query"
				}
				selected.Control = cloneRouterProfile(selected.Exit)
				before := mustImportedJSON(t, selected)
				captured, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{selected.ExitMode}, nil)
				if protocol == "udp" {
					if err != nil || captured.Native == nil || captured.Native.validate(captured) != nil || string(before) != string(mustImportedJSON(t, selected)) {
						t.Fatal("desktop literal H2 changed or rejected the selected Home UDP policy", err)
					}
					launch, err := compileRetainedNativeMultihopLaunch(captured, nil)
					if err != nil {
						t.Fatal(err)
					}
					graph := retainedGraph(t, launch.config)
					rows := graph["dns"].(map[string]any)["servers"].([]any)
					if len(rows) != 2 {
						t.Fatal("literal Home policy lost its exact resolver closure")
					}
					resolver, lower := rows[0].(map[string]any), rows[1].(map[string]any)
					if resolver["type"] != "udp" || resolver["server"] != selected.Exit.AdGuardIPv4 || resolver["server_port"] != float64(53) || resolver["detour"] != "proxy" || lower["type"] != "udp" || lower["server"] != resolver["server"] || lower["server_port"] != resolver["server_port"] || lower["detour"] != mobilemultihop.NativeStartLayerTag {
						t.Fatal("literal Home DNS changed its transport or selected final/layer owner", resolver, lower)
					}
					if len(launch.nodePhysicalEgress) != 1 {
						t.Fatal("literal H2 changed its original physical CONNECT owner")
					}
					for _, tuple := range launch.nodePhysicalEgress {
						if tuple.Network != "tcp" || tuple.Host != selected.Entry.Endpoint {
							t.Fatal("literal H2 granted an unowned physical transport", tuple)
						}
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "captured TCP-compatible DNS bootstrap") || captured.Native != nil || string(before) != string(mustImportedJSON(t, selected)) {
					t.Fatal("desktop H2 changed or admitted an incompatible selected lower DNS transport", err)
				}
			})
		}
	}
}
