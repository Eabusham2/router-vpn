package mobilemultihop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/nativecomposite"
	"strings"
	"testing"
)

func importedCONNECTServiceFixture(t *testing.T, protocol, layer, dnsMode, dnsProtocol string) []string {
	t.Helper()
	source := importedCONNECTFixture(t, protocol, NativeStartLayerMethod, dnsMode)
	profile := externalTestRead(t, source[4])
	profile["start_layer"], profile["dns_protocol"] = layer, dnsProtocol
	source[4] = externalTestJSON(t, profile)
	var assets map[string]string
	if err := exactJSON([]byte(source[3]), &assets, 8<<20); err != nil {
		t.Fatal(err)
	}
	original, err := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
	if err != nil {
		t.Fatal(err)
	}
	out := externalTestRead(t, string(original))["outbounds"].([]any)[0].(map[string]any)
	digest, key := sha256.Sum256(original), sha256.Sum256([]byte(out["password"].(string)))
	claim := map[string]any{"schema": 1, "node_id": profile["node_proof_id"], "configured_image": nativecomposite.SSServiceImage, "uot_version": 2,
		"endpoint": out["server"], "port": out["server_port"], "method": out["method"], "source_sha256": hex.EncodeToString(digest[:]), "key_sha256": hex.EncodeToString(key[:])}
	assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, claim)))
	source[3] = externalTestJSON(t, assets)
	return source
}

func TestImportedEntryCONNECTServiceConfiguredGraphs(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, dnsMode := range []string{"home", "custom"} {
				for _, dnsProtocol := range []string{"udp", "tcp"} {
					t.Run(protocol+"/"+layer+"/"+dnsMode+"/"+dnsProtocol, func(t *testing.T) {
						source := importedCONNECTServiceFixture(t, protocol, layer, dnsMode, dnsProtocol)
						original := append([]string(nil), source...)
						controller := importedPacketCompile(t, source)
						graph := externalTestRead(t, controller.Config())
						if graph["endpoints"] == nil {
							graph["endpoints"] = []any{}
						}
						final := externalTestFind(t, graph, LocalTag)
						expectedType := "shadowsocks"
						if layer == "aes-256-gcm+xor-whitening" {
							expectedType = "routervpn-aes-xor"
						}
						if final["type"] != expectedType || final["detour"] != "entry-wg" || final["network"] != nil || !reflect.DeepEqual(final["udp_over_tcp"], map[string]any{"enabled": true, "version": float64(2)}) || controller.meta.TransportCapability != "uot-v2" {
							t.Fatal("configured UoT lost its exact stream carrier", final)
						}
						dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
						profile := externalTestRead(t, source[4])
						if dns["type"] != dnsProtocol || dns["server"] != profile["dns_host"] || dns["server_port"] != profile["dns_port"] || dns["detour"] != "proxy" {
							t.Fatal("configured UoT changed selected DNS", dns)
						}
						for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
							rule := raw.(map[string]any)
							if rule["network"] == "udp" && rule["action"] == "reject" {
								t.Fatal("configured UDP was still rejected")
							}
						}
						if !reflect.DeepEqual(source, original) {
							t.Fatal("original captured inputs changed")
						}
						if directory := os.Getenv("ROUTERVPN_CONNECT_SERVICE_FIXTURES"); directory != "" {
							capture := append(append([]string(nil), source...), controller.SourceSHA256(), controller.Config())
							name := protocol + "--" + layer + "--" + dnsMode + "--" + dnsProtocol + ".json"
							if err := os.WriteFile(filepath.Join(directory, name), []byte(externalTestJSON(t, capture)), 0600); err != nil {
								t.Fatal(err)
							}
						}
						if _, err := New(controller.Config(), controller.Metadata()); err == nil {
							t.Fatal("metadata fabricated UoT authority")
						}
						plain, err := NewNodeProfile("shadowsocks", source[3], source[4], "", "")
						if err != nil || strings.Contains(plain.Config(), "udp_over_tcp") {
							t.Fatal("ordinary source consumer enabled UoT", err)
						}
					})
				}
			}
		}
	}
}

func TestImportedEntryCONNECTServiceAuthorityRefusals(t *testing.T) {
	for _, fault := range []string{"missing", "foreign-node", "stale-source", "wrong-key", "wrong-port", "wrong-image", "wrong-version", "extra-asset", "entry-layer", "unsupported-layer", "inline-uot", "dns-h3", "wrong-home"} {
		t.Run(fault, func(t *testing.T) {
			source := importedCONNECTServiceFixture(t, "https-connect", "off", "home", "udp")
			var assets map[string]string
			_ = exactJSON([]byte(source[3]), &assets, 8<<20)
			data, _ := base64.StdEncoding.DecodeString(assets[nativecomposite.SSServiceAsset])
			claim := externalTestRead(t, string(data))
			profile := externalTestRead(t, source[4])
			switch fault {
			case "missing":
				delete(assets, nativecomposite.SSServiceAsset)
			case "foreign-node":
				claim["node_id"] = strings.Repeat("f", 64)
			case "stale-source":
				claim["source_sha256"] = strings.Repeat("0", 64)
			case "wrong-key":
				claim["key_sha256"] = strings.Repeat("0", 64)
			case "wrong-port":
				claim["port"] = float64(9999)
			case "wrong-image":
				claim["configured_image"] = "foreign/image:v2"
			case "wrong-version":
				claim["uot_version"] = float64(1)
			case "extra-asset":
				assets["foreign.json"] = base64.StdEncoding.EncodeToString([]byte("{}"))
			case "entry-layer":
				capture := externalTestRead(t, source[1])
				capture["profile"].(map[string]any)["start_layer"] = "aes-256-gcm"
				source[1] = externalTestJSON(t, capture)
			case "unsupported-layer":
				profile["start_layer"] = "xor"
			case "inline-uot":
				raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
				graph := externalTestRead(t, string(raw))
				graph["outbounds"].([]any)[0].(map[string]any)["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, graph)))
			case "dns-h3":
				profile["dns_protocol"] = "h3"
			case "wrong-home":
				profile["dns_host"] = "10.99.0.1"
			}
			if fault != "missing" {
				assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, claim)))
			}
			source[3], source[4] = externalTestJSON(t, assets), externalTestJSON(t, profile)
			if _, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil {
				t.Fatal("invalid configured authority admitted", fault)
			}
		})
	}
}

func TestImportedEntryCONNECTServiceDefaultHomeAndInvalidTCPAuthority(t *testing.T) {
	t.Run("default-home", func(t *testing.T) {
		source := importedCONNECTServiceFixture(t, "http-connect", "off", "home", "udp")
		p := externalTestRead(t, source[4])
		delete(p, "dns_mode")
		delete(p, "dns_protocol")
		delete(p, "dns_host")
		delete(p, "dns_port")
		source[4] = externalTestJSON(t, p)
		c := importedPacketCompile(t, source)
		g := externalTestRead(t, c.Config())
		dns := g["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
		if dns["type"] != "udp" || dns["server"] != p["adguard_ipv4"] || dns["server_port"] != float64(53) || dns["detour"] != "proxy" {
			t.Fatal("default Home authority changed", dns)
		}
	})
	for _, fault := range []string{"foreign-node", "malformed", "stale-source"} {
		t.Run("tcp-"+fault, func(t *testing.T) {
			source := importedCONNECTServiceFixture(t, "https-connect", "off", "home", "tcp")
			var assets map[string]string
			_ = exactJSON([]byte(source[3]), &assets, 8<<20)
			data, _ := base64.StdEncoding.DecodeString(assets[nativecomposite.SSServiceAsset])
			claim := externalTestRead(t, string(data))
			if fault == "foreign-node" {
				claim["node_id"] = strings.Repeat("f", 64)
			} else {
				claim["source_sha256"] = strings.Repeat("0", 64)
			}
			data = []byte(externalTestJSON(t, claim))
			if fault == "malformed" {
				data = []byte("{")
			}
			assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString(data)
			source[3] = externalTestJSON(t, assets)
			if _, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil {
				t.Fatal("invalid authority downgraded to TCP")
			}
		})
	}
}
