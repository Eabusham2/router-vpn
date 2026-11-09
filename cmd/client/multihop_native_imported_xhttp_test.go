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

func desktopImportedXHTTPFixture(t *testing.T, kind, first, last string) (string, multihopSelection) {
	t.Helper()
	mode := "reality-xhttp"
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

func TestDesktopImportedXHTTPCapturedGraphs(t *testing.T) {
	for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
		for _, first := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, last := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					root, original := desktopImportedXHTTPFixture(t, kind, first, last)
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
					if final["type"] != "routervpn-xray" || final["mode"] != "reality-xhttp" || selected.Native.validate(selected) != nil || string(before) != string(mustImportedJSON(t, original)) {
						t.Fatal("desktop XHTTP changed original selection or native mode")
					}
					raw := retainedGraph(t, []byte(final["config_json"].(string)))
					user := raw["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
					if !strings.HasPrefix(user["encryption"].(string), "mlkem768x25519plus.native.0rtt.") || (user["flow"] != nil && user["flow"] != "") {
						t.Fatal("desktop XHTTP downgraded its captured encryption or flow")
					}
					saved, err := os.ReadFile(filepath.Join(root, "generated", original.Exit.ID, original.ExitMode, "xray.json"))
					if err != nil {
						t.Fatal(err)
					}
					savedRaw := retainedGraph(t, saved)
					savedOut := savedRaw["outbounds"].([]any)[0].(map[string]any)
					savedUser := savedOut["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
					stream := raw["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
					savedStream := savedOut["streamSettings"].(map[string]any)
					if !reflect.DeepEqual(user, savedUser) || !reflect.DeepEqual(stream["xhttpSettings"], savedStream["xhttpSettings"]) || !reflect.DeepEqual(stream["finalmask"], savedStream["finalmask"]) || stream["network"] != savedStream["network"] {
						t.Fatal("desktop XHTTP replaced original path, key, flow or FinalMask")
					}
					for _, tuple := range launch.nodePhysicalEgress {
						if tuple.Host != original.Entry.Endpoint || tuple.Host == original.Exit.Endpoint {
							t.Fatal("desktop XHTTP final acquired an unowned physical exception")
						}
					}
					dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
					wanted := original.Exit.AdGuardIPv4
					if original.Exit.DNSMode == "custom" {
						wanted = original.Exit.DNSHost
					}
					if dns["server"] != wanted || dns["detour"] != "proxy" || strings.Contains(string(launch.config), "entry-private") {
						t.Fatal("desktop XHTTP changed DNS or borrowed paired entry authority")
					}
					restored := selected
					restored.restoreMTU = 1280
					again, err := compileRetainedNativeMultihopLaunch(restored, nil)
					if err != nil || !reflect.DeepEqual(again.nodePhysicalEgress, launch.nodePhysicalEgress) {
						t.Fatal("desktop XHTTP restoration lost captured physical owner", err)
					}
					_, server := executionFixture()
					if _, err := compileRetainedNativeMultihopLaunch(selected, &server); err == nil {
						t.Fatal("desktop XHTTP import acquired Server proof authority")
					}
					if directory := os.Getenv("ROUTERVPN_DESKTOP_IMPORTED_XHTTP_XRAY_FIXTURES"); directory != "" {
						if err := os.WriteFile(filepath.Join(directory, kind+"--reality-xhttp--"+first+"--"+last+".json"), launch.config, 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestDesktopImportedXHTTPRejectsNativeDowngrade(t *testing.T) {
	for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
		for _, fault := range []string{"ordinary", "missing-encryption", "missing-xray", "vision-flow", "relative-path", "raw-network"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				root, selected := desktopImportedXHTTPFixture(t, kind, "off", "off")
				directory := filepath.Join(root, "generated", selected.Exit.ID, selected.ExitMode)
				name := "xray.json"
				path := filepath.Join(directory, name)
				if fault == "missing-xray" {
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
					if fault == "vision-flow" {
						user["flow"] = "xtls-rprx-vision"
					} else if fault == "relative-path" {
						raw["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["xhttpSettings"].(map[string]any)["path"] = "relative"
					} else if fault == "raw-network" {
						raw["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["network"] = "raw"
					} else if fault == "ordinary" {
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
					t.Fatal("desktop XHTTP admitted missing or ordinary final assets")
				}
			})
		}
	}
}
