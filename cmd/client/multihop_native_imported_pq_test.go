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
)

func desktopImportedPQFixture(t *testing.T, kind, first, last string) (string, multihopSelection) {
	t.Helper()
	mode := "reality-pq-vision"
	if strings.HasPrefix(kind, "openvpn-") {
		return desktopImportedOpenVPNFixture(t, strings.TrimPrefix(kind, "openvpn-"), mode, first, last)
	}
	if kind == "wireguard" || kind == "amneziawg" {
		return desktopImportedPacketFixture(t, kind, mode, first, last)
	}
	root, selected := desktopImportedFixture(t, kind, mode)
	selected.Entry.StartLayer, selected.Exit.StartLayer = first, last
	if first != "off" {
		selected.Entry.External.StartLayer = &common.ExternalStartLayer{Mode: first, API: "http://10.93.0.1:8787",
			Transport: map[string]any{"type": "shadowsocks", "tag": "saved-layer", "server": selected.Entry.Endpoint,
				"server_port": float64(8389), "method": "2022-blake3-aes-256-gcm", "password": testWGKey('l')}}
	}
	selected.Control = cloneRouterProfile(selected.Exit)
	return root, selected
}

func TestDesktopImportedPQRealityCapturedGraphs(t *testing.T) {
	for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
		for _, first := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, last := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					root, original := desktopImportedPQFixture(t, kind, first, last)
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
					if final["type"] != "routervpn-xray" || final["mode"] != "reality-pq-vision" || selected.Native.validate(selected) != nil || string(before) != string(mustImportedJSON(t, original)) {
						t.Fatal("desktop PQ changed original selection or native mode")
					}
					raw := retainedGraph(t, []byte(final["config_json"].(string)))
					user := raw["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
					if !strings.HasPrefix(user["encryption"].(string), "mlkem768x25519plus.native.0rtt.") || user["flow"] != "xtls-rprx-vision" {
						t.Fatal("desktop PQ downgraded its captured encryption or flow")
					}
					for _, tuple := range launch.nodePhysicalEgress {
						if tuple.Host != original.Entry.Endpoint || tuple.Host == original.Exit.Endpoint {
							t.Fatal("desktop PQ final acquired an unowned physical exception")
						}
					}
					dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
					wanted := original.Exit.AdGuardIPv4
					if original.Exit.DNSMode == "custom" {
						wanted = original.Exit.DNSHost
					}
					if dns["server"] != wanted || dns["detour"] != "proxy" || strings.Contains(string(launch.config), "entry-private") {
						t.Fatal("desktop PQ changed DNS or borrowed paired entry authority")
					}
					restored := selected
					restored.restoreMTU = 1280
					again, err := compileRetainedNativeMultihopLaunch(restored, nil)
					if err != nil || !reflect.DeepEqual(again.nodePhysicalEgress, launch.nodePhysicalEgress) {
						t.Fatal("desktop PQ restoration lost captured physical owner", err)
					}
					_, server := executionFixture()
					if _, err := compileRetainedNativeMultihopLaunch(selected, &server); err == nil {
						t.Fatal("desktop PQ import acquired Server proof authority")
					}
					if directory := os.Getenv("ROUTERVPN_DESKTOP_IMPORTED_PQ_XRAY_FIXTURES"); directory != "" {
						if err := os.WriteFile(filepath.Join(directory, kind+"--reality-pq-vision--"+first+"--"+last+".json"), launch.config, 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestDesktopImportedPQRealityRejectsNativeDowngrade(t *testing.T) {
	for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
		for _, fault := range []string{"ordinary", "missing-encryption", "missing-xray", "missing-wrapper"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				root, selected := desktopImportedPQFixture(t, kind, "off", "off")
				directory := filepath.Join(root, "generated", selected.Exit.ID, selected.ExitMode)
				name := "xray.json"
				if fault == "missing-wrapper" {
					name = "sing-box.json"
				}
				path := filepath.Join(directory, name)
				if strings.HasPrefix(fault, "missing-") && fault != "missing-encryption" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else {
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					raw := retainedGraph(t, data)
					user := raw["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
					if fault == "ordinary" {
						user["encryption"] = "none"
					} else {
						delete(user, "encryption")
					}
					data, _ = json.Marshal(raw)
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{selected.ExitMode}, nil); err == nil {
					t.Fatal("desktop PQ admitted missing or ordinary final assets")
				}
			})
		}
	}
}
