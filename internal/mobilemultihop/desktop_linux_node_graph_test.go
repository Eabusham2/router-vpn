package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

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
