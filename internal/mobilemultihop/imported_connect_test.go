package mobilemultihop

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func importedCONNECTFixture(t *testing.T, protocol, method, dnsMode string) []string {
	t.Helper()
	graph, capture := externalTestFixture(t, protocol, "")
	files, profile, start := nodeProfileFixture(t, "shadowsocks", "")
	var assets map[string]string
	if err := exactJSON([]byte(files), &assets, 4<<20); err != nil {
		t.Fatal(err)
	}
	data, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
	raw := externalTestRead(t, string(data))
	out := raw["outbounds"].([]any)[0].(map[string]any)
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	out["method"], out["password"] = method, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", size)))
	assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, raw)))
	profile["socks_host"] = "10.77.0.1" // Captured private probe sink from this paired Router.
	profile["id"], profile["dns_mode"], profile["dns_protocol"], profile["dns_port"] = "paired-final", dnsMode, "tcp", float64(5353)
	if dnsMode == "custom" {
		profile["dns_host"] = "203.0.113.53"
	} else {
		profile["dns_host"] = profile["adguard_ipv4"]
		if protocol == "https-connect" {
			profile["adguard_ipv6"] = "fd77:77::53"
			profile["dns_host"] = profile["adguard_ipv6"]
		}
	}
	return []string{externalTestJSON(t, graph), externalTestJSON(t, capture), "shadowsocks", externalTestJSON(t, assets), externalTestJSON(t, profile), start, ""}
}
func TestImportedEntryCONNECTGraphs(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
			for _, dnsMode := range []string{"home", "custom"} {
				label := protocol + "--" + method + "--" + dnsMode
				t.Run(label, func(t *testing.T) {
					source := importedCONNECTFixture(t, protocol, method, dnsMode)
					original := append([]string(nil), source...)
					c := importedPacketCompile(t, source)
					g := externalTestRead(t, c.Config())
					if g["endpoints"] == nil {
						g["endpoints"] = []any{}
					}
					first := externalTestFind(t, g, "entry-wg")
					last := externalTestFind(t, g, LocalTag)
					if first["type"] != "http" || first["detour"] != nil || last["method"] != method || last["network"] != "tcp" || last["detour"] != "entry-wg" || c.meta.TransportCapability != "tcp-only" || c.meta.EntryAPI != "" || c.meta.EntryToken != "" {
						t.Fatal("captured stream owner changed")
					}
					dns := g["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
					p := externalTestRead(t, source[4])
					if dns["type"] != "tcp" || dns["detour"] != "proxy" || dns["server"] != p["dns_host"] || dns["server_port"] != p["dns_port"] {
						t.Fatal("selected TCP DNS changed", dns)
					}
					rules := g["route"].(map[string]any)["rules"].([]any)
					hijacks := 0
					refused := false
					for _, raw := range rules {
						rule := raw.(map[string]any)
						if rule["action"] == "hijack-dns" {
							if refused {
								t.Fatal("DNS followed UDP refusal")
							}
							hijacks++
						}
						if rule["network"] == "udp" && rule["action"] == "reject" {
							refused = true
						}
					}
					if !refused || hijacks < 2 {
						t.Fatal("missing explicit UDP refusal or DNS hijack")
					}
					if !reflect.DeepEqual(source, original) {
						t.Fatal("captured sources changed")
					}
					if _, err := New(c.Config(), c.Metadata()); err == nil {
						t.Fatal("metadata fabricated imported owner")
					}
					if dir := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); dir != "" {
						source = append(source, c.SourceSHA256(), c.Config())
						if err := os.WriteFile(filepath.Join(dir, "connect--"+label+".json"), []byte(externalTestJSON(t, source)), 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}
func TestImportedEntryCONNECTBoundaries(t *testing.T) {
	for _, fault := range []string{"udp-dns", "h3-dns", "dot-dns", "default-dns", "hostname-dns", "home-owner", "entry-layer", "final-layer", "hy-final", "wg-final", "awg-final", "legacy-cipher", "uot-enabled", "uot-disabled", "uot-malformed", "server-execution", "retained-source"} {
		t.Run(fault, func(t *testing.T) {
			s := importedCONNECTFixture(t, "https-connect", NativeStartLayerMethod, "home")
			p := externalTestRead(t, s[4])
			cap := externalTestRead(t, s[1])
			switch fault {
			case "udp-dns":
				p["dns_protocol"] = "udp"
			case "h3-dns":
				p["dns_protocol"] = "h3"
			case "dot-dns":
				p["dns_protocol"] = "tls"
			case "default-dns":
				delete(p, "dns_protocol")
			case "hostname-dns":
				p["dns_mode"], p["dns_host"] = "custom", "resolver.example.test"
			case "home-owner":
				p["dns_host"] = "192.168.50.132"
			case "entry-layer":
				externalTestAddLayer(cap["profile"].(map[string]any), "aes-256-gcm", "203.0.113.20", "10.93.0.1", "i")
				s[1] = externalTestJSON(t, cap)
			case "final-layer":
				p["start_layer"] = "aes-256-gcm"
			case "hy-final", "wg-final", "awg-final":
				mode := map[string]string{"hy-final": "hysteria2", "wg-final": "wg", "awg-final": "awg2-strong"}[fault]
				s[2], s[3], p, s[5] = mode, "", nil, ""
				files, profile, start := nodeProfileFixture(t, mode, "")
				s[3], s[5], p = files, start, profile
				p["dns_protocol"] = "tcp"
			case "legacy-cipher", "uot-enabled", "uot-disabled", "uot-malformed":
				var files map[string]string
				_ = exactJSON([]byte(s[3]), &files, 4<<20)
				raw, _ := base64.StdEncoding.DecodeString(files["sing-box.json"])
				g := externalTestRead(t, string(raw))
				out := g["outbounds"].([]any)[0].(map[string]any)
				if fault == "legacy-cipher" {
					out["method"] = "aes-256-gcm"
				} else if fault == "uot-malformed" {
					out["udp_over_tcp"] = "true"
				} else {
					out["udp_over_tcp"] = map[string]any{"enabled": fault == "uot-enabled", "version": float64(2)}
				}
				files["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, g)))
				s[3] = externalTestJSON(t, files)
			case "server-execution":
				p["multihop_execution"] = "server"
			case "retained-source":
				before := append([]string(nil), s...)
				c := importedPacketCompile(t, s)
				if _, err := New(c.Config(), c.Metadata()); err == nil || !reflect.DeepEqual(s, before) {
					t.Fatal("retained authority changed")
				}
				return
			}
			s[4] = externalTestJSON(t, p)
			if strings.HasPrefix(fault, "uot-") {
				if _, err := NewNodeProfile(s[2], s[3], s[4], s[5], s[6]); err != nil {
					t.Fatal("UoT refusal control did not reach CONNECT capture", err)
				}
			}
			if _, err := NewImportedEntry(s[0], s[1], s[2], s[3], s[4], s[5], s[6]); err == nil {
				t.Fatal("unsupported CONNECT capability admitted", fault)
			}
		})
	}
}
