package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDesktopLinuxNodeRetainsExactPlainHysteria2(t *testing.T) {
	for _, layer := range []string{"", "off"} {
		t.Run(layer, func(t *testing.T) {
			if !DesktopLinuxNodePhysicalGraphSupported("hysteria2", layer) {
				t.Fatal("plain Hysteria2 has no retained Linux path")
			}
			files, profile, _ := nodeProfileFixture(t, "hysteria2", "")
			profile["start_layer"], profile["kill_switch_policy"] = layer, "always"
			original, err := NewNodeProfile("hysteria2", files, startJSON(t, profile), "", "")
			if err != nil {
				t.Fatal(err)
			}
			policy := desktopNodePlan(t, original, desktopNodeTestSession, "linux")
			assertDesktopNodeExactDerivation(t, policy)
			capture, err := policy.Capture()
			if err != nil || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Type != "hysteria2" ||
				capture.PhysicalRoots[0].Family != "outbounds" || len(capture.PhysicalRoots[0].Destinations) != 1 ||
				capture.PhysicalRoots[0].Destinations[0] != (PhysicalEgress{Host: "192.0.2.44", Port: 443, Network: "udp"}) ||
				capture.SelectedDNS.Host != "192.168.50.133" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" ||
				capture.ConfiguredMTU != 1280 || capture.KillSwitchPolicy != "always" {
				t.Fatal("plain Linux Hysteria2 lost its exact UDP peer, selected DNS, MTU or protection", err)
			}
			before := desktopNodeObject(t, startObject(t, original.Config()), "outbounds", "proxy")
			actual := desktopNodeObject(t, startObject(t, policy.Config()), "outbounds", "proxy")
			if actual["detour"] != DesktopNodePhysicalTag || actual["server"] != before["server"] || actual["server_port"] != before["server_port"] ||
				actual["password"] != before["password"] || !reflect.DeepEqual(actual["obfs"], before["obfs"]) || !reflect.DeepEqual(actual["tls"], before["tls"]) {
				t.Fatal("plain Linux Hysteria2 changed the captured endpoint, authentication, Salamander or TLS trust")
			}
			tls := actual["tls"].(map[string]any)
			if tls["enabled"] != true || tls["server_name"] != "entry.example" || tls["insecure"] == true || tls["certificate"] == nil || tls["certificate_path"] != nil {
				t.Fatal("plain Linux Hysteria2 lost its embedded selected certificate")
			}
		})
	}
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening", "OFF", "plain", " off", "unknown"} {
		if DesktopLinuxNodePhysicalGraphSupported("hysteria2", layer) {
			t.Fatal("plain Hysteria2 opened an unproved Start Layer", layer)
		}
	}
}

func TestDesktopLinuxNodeRetainsExactPlainWireGuard(t *testing.T) {
	for _, layer := range []string{"", "off"} {
		t.Run(layer, func(t *testing.T) {
			if !DesktopLinuxNodePhysicalGraphSupported("wg", layer) {
				t.Fatal("plain WireGuard has no retained Linux path")
			}
			files, profile, _ := nodeProfileFixture(t, "wg", "")
			profile["start_layer"], profile["kill_switch_policy"] = layer, "always"
			original, err := NewNodeProfile("wg", files, startJSON(t, profile), "", "")
			if err != nil {
				t.Fatal(err)
			}
			policy := desktopNodePlan(t, original, desktopNodeTestSession, "linux")
			assertDesktopNodeExactDerivation(t, policy)
			capture, err := policy.Capture()
			if err != nil || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Type != "wireguard" ||
				capture.PhysicalRoots[0].Family != "endpoints" || len(capture.PhysicalRoots[0].Destinations) != 1 ||
				capture.PhysicalRoots[0].Destinations[0] != (PhysicalEgress{Host: "192.0.2.1", Port: 51820, Network: "udp"}) ||
				capture.SelectedDNS.Host != "192.168.50.133" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" ||
				capture.ConfiguredMTU != 1280 || capture.KillSwitchPolicy != "always" {
				t.Fatal("plain Linux WireGuard lost its one UDP peer, selected DNS, MTU or protection", err)
			}
			before := desktopNodeObject(t, startObject(t, original.Config()), "endpoints", "proxy")
			actual := desktopNodeObject(t, startObject(t, policy.Config()), "endpoints", "proxy")
			if actual["detour"] != DesktopNodePhysicalTag || actual["system"] != false ||
				actual["private_key"] != before["private_key"] || !reflect.DeepEqual(actual["peers"], before["peers"]) {
				t.Fatal("plain Linux WireGuard changed native transport, private key or peer source")
			}
		})
	}
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening", "OFF", "plain", " off", "unknown"} {
		if DesktopLinuxNodePhysicalGraphSupported("wg", layer) {
			t.Fatal("plain WireGuard opened an unproved Start Layer", layer)
		}
	}
}

func TestDesktopLinuxNodeRetainsExactPlainAmnezia(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "off"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				if !DesktopLinuxNodePhysicalGraphSupported(mode, layer) {
					t.Fatal("plain AWG2 has no retained Linux path")
				}
				files, profile, _ := nodeProfileFixture(t, mode, "")
				if mode == "awg2-strong" {
					raw, _ := amneziaFixture()
					raw = strings.Replace(strings.Replace(raw, "Jc=3\n", "Jc=8\n", 1), "Jmax=900\n", "Jmax=1200\n", 1)
					encoded, err := json.Marshal(map[string]string{"awg.conf": base64.StdEncoding.EncodeToString([]byte(raw))})
					if err != nil {
						t.Fatal(err)
					}
					files = string(encoded)
				}
				profile["start_layer"], profile["kill_switch_policy"] = layer, "always"
				original, err := NewNodeProfile(mode, files, startJSON(t, profile), "", "")
				if err != nil {
					t.Fatal(err)
				}
				policy := desktopNodePlan(t, original, desktopNodeTestSession, "linux")
				assertDesktopNodeExactDerivation(t, policy)
				capture, err := policy.Capture()
				if err != nil || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Type != "routervpn-amneziawg" ||
					capture.PhysicalRoots[0].Family != "endpoints" || len(capture.PhysicalRoots[0].Destinations) != 1 ||
					capture.PhysicalRoots[0].Destinations[0] != (PhysicalEgress{Host: "192.0.2.1", Port: 51820, Network: "udp"}) ||
					capture.SelectedDNS.Host != "192.168.50.133" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" ||
					capture.ConfiguredMTU != 1280 || capture.KillSwitchPolicy != "always" {
					t.Fatal("plain Linux AWG2 lost its one UDP peer, selected DNS, MTU or protection", err)
				}
				before := desktopNodeObject(t, startObject(t, original.Config()), "endpoints", "proxy")
				actual := desktopNodeObject(t, startObject(t, policy.Config()), "endpoints", "proxy")
				parameters, ok := actual["amnezia"].(map[string]any)
				expectedJunk, expectedMaximum := "3", "900"
				if mode == "awg2-strong" {
					expectedJunk, expectedMaximum = "8", "1200"
				}
				if !ok || len(parameters) != 11 || parameters["jc"] != expectedJunk || parameters["jmax"] != expectedMaximum {
					t.Fatal("retained AWG graph changed its exact mode-specific source parameters")
				}
				if actual["detour"] != DesktopNodePhysicalTag || actual["type"] != "routervpn-amneziawg" ||
					actual["private_key"] != before["private_key"] || !reflect.DeepEqual(actual["peers"], before["peers"]) || !reflect.DeepEqual(actual["amnezia"], before["amnezia"]) {
					t.Fatal("plain Linux AWG2 changed native transport, private key or peer source")
				}
			})
		}
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening", "OFF", "plain", " off", "unknown"} {
			if DesktopLinuxNodePhysicalGraphSupported(mode, layer) {
				t.Fatal("plain AWG2 opened an unproved Start Layer", layer)
			}
		}
	}
}

func TestDesktopLinuxNodeRetainsExactShadowsocksLayers(t *testing.T) {
	for _, layer := range []string{"", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			if !DesktopLinuxNodePhysicalGraphSupported("shadowsocks", layer) {
				t.Fatal("exact Shadowsocks Start Layer was not admitted")
			}
			original := desktopNodeFixture(t, "shadowsocks", layer)
			policy := desktopNodePlan(t, original, desktopNodeTestSession, "linux")
			assertDesktopNodeExactDerivation(t, policy)
			capture, err := policy.Capture()
			if err != nil || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 2 ||
				capture.SelectedDNS.Host != "192.168.50.133" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" ||
				capture.ConfiguredMTU != 1280 || capture.KillSwitchPolicy != "always" {
				t.Fatal("Linux Start Layer changed its selected DNS, MTU, protection or physical owners", err)
			}
			graph := startObject(t, policy.Config())
			out := desktopNodeObject(t, graph, "outbounds", "proxy")
			kind := "shadowsocks"
			if layer == "aes-256-gcm+xor-whitening" {
				kind = "routervpn-aes-xor"
				if out["server_port"] != float64(8389) {
					t.Fatal("native whitening did not preserve its exact outer port")
				}
			}
			if out["type"] != kind || out["method"] != NativeStartLayerMethod ||
				out["password"] != base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))) || out["detour"] != DesktopNodePhysicalTag {
				t.Fatal("Linux layer replaced its actual cipher, captured key or owned physical lower")
			}
			for _, destination := range capture.PhysicalRoots[0].Destinations {
				if destination.Host != "192.0.2.44" || float64(destination.Port) != out["server_port"] ||
					destination.Network != "tcp" && destination.Network != "udp" {
					t.Fatal("inner source, DNS or proof target acquired outer physical authority")
				}
			}
		})
	}
	for _, mode := range append(append([]string(nil), predecessorFamilies...), "", "auto", "smart-auto", "tor", "openvpn", "external") {
		if mode != "shadowsocks" && DesktopLinuxNodePhysicalGraphSupported(mode, "aes-256-gcm+xor-whitening") {
			t.Fatal("Start Layer admission opened an unrelated Linux family", mode)
		}
	}
	for _, layer := range []string{"AES-256-GCM", "aes-256-gcm-xor", "xor", "whitening", " off", "unknown"} {
		if DesktopLinuxNodePhysicalGraphSupported("shadowsocks", layer) {
			t.Fatal("malformed or unauthenticated Linux Start Layer was admitted", layer)
		}
	}
}

func TestDesktopLinuxNodeStartLayerRejectsForeignOrIncompleteAESSource(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"unused-second-source", "wrong-cipher", "short-key"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				files, profile, _ := nodeProfileFixture(t, "shadowsocks", layer)
				start := ""
				if fault == "unused-second-source" {
					start = files
				} else {
					var assets map[string]string
					if err := json.Unmarshal([]byte(files), &assets); err != nil {
						t.Fatal(err)
					}
					raw, err := base64.StdEncoding.DecodeString(assets["sing-box.json"])
					if err != nil {
						t.Fatal(err)
					}
					graph := startObject(t, string(raw))
					out := desktopNodeObject(t, graph, "outbounds", "proxy")
					if fault == "wrong-cipher" {
						out["method"] = "chacha20-ietf-poly1305"
					} else {
						out["password"] = base64.StdEncoding.EncodeToString([]byte("too-short"))
					}
					assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
					files = startJSON(t, assets)
				}
				if compiled, err := NewNodeProfile("shadowsocks", files, startJSON(t, profile), start, ""); err == nil || compiled != nil {
					t.Fatal("Linux layer accepted missing authentication or borrowed another source")
				}
			})
		}
	}
}
