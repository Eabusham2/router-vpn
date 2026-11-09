package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/applexray"
	"strings"
	"testing"
)

func importedXHTTPStream(raw map[string]any) map[string]any {
	return raw["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
}

func importedXHTTPFixture(t *testing.T, kind, first, last string) []string {
	t.Helper()
	source := importedPQFixture(t, kind, first, last)
	assets, raw, _ := importedSOCKSXrayRaw(t, source[3])
	delete(importedPQUser(raw), "flow")
	stream := importedXHTTPStream(raw)
	stream["network"] = "xhttp"
	stream["xhttpSettings"] = map[string]any{"path": "/assets/sync", "mode": "auto"}
	stream["finalmask"] = map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "100-300", "delay": "10-30", "maxSplit": "3-7"}}}}
	assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, raw)))
	source[2], source[3] = "reality-xhttp", externalTestJSON(t, assets)
	return source
}

func TestImportedXHTTPIndependentLayers(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, first := range importedPQLayers {
			for _, last := range importedPQLayers {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					source := importedXHTTPFixture(t, kind, first, last)
					captured := append([]string(nil), source...)
					plan := importedPacketXrayCompile(t, source)
					graph := importedPQGraph(t, plan.Config())
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					nodeGraph := importedPQGraph(t, node.Config())
					final, original := externalTestFind(t, graph, LocalTag), externalTestFind(t, nodeGraph, "proxy")
					if len(final) != 5 || final["type"] != applexray.Type || final["mode"] != "reality-xhttp" || final["config_json"] != original["config_json"] {
						t.Fatal("XHTTP final replaced its exact captured native transport")
					}
					pq := externalTestRead(t, final["config_json"].(string))
					if !strings.HasPrefix(importedPQUser(pq)["encryption"].(string), "mlkem768x25519plus.native.0rtt.") || predecessorText(importedPQUser(pq), "flow") != "" {
						t.Fatal("XHTTP final lost hybrid encryption or empty flow")
					}
					if last == "off" {
						if final["detour"] != "entry-wg" {
							t.Fatal("XHTTP final bypassed the imported entry")
						}
					} else {
						outer := externalTestFind(t, graph, applexray.StartLayerTag)
						copy := predecessorCopy(outer)
						delete(copy, "detour")
						if final["detour"] != applexray.StartLayerTag || outer["detour"] != "entry-wg" || !reflect.DeepEqual(copy, externalTestFind(t, nodeGraph, applexray.StartLayerTag)) {
							t.Fatal("XHTTP final bypassed or replaced its independent Start Layer")
						}
					}
					// Compile the same import with the original ordinary final to
					// compare every retained entry edge and credential, including
					// packet endpoint parameters and independent wrapper sources.
					ordinary := importedPQFixture(t, kind, first, last)
					assets, raw, _ := importedSOCKSXrayRaw(t, ordinary[3])
					importedPQUser(raw)["encryption"] = "none"
					assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, raw)))
					ordinary[2], ordinary[3] = "reality-vision", externalTestJSON(t, assets)
					old := importedPacketXrayCompile(t, ordinary)
					before := importedPQGraph(t, old.Config())
					for _, family := range []string{"outbounds", "endpoints"} {
						rows, _ := graph[family].([]any)
						for _, value := range rows {
							row := value.(map[string]any)
							tag, _ := row["tag"].(string)
							if tag == "entry-wg" || strings.HasPrefix(tag, "imported-entry-") {
								if !reflect.DeepEqual(row, externalTestFind(t, before, tag)) {
									t.Fatal("XHTTP selection changed imported entry credentials or layer ownership")
								}
							}
						}
					}
					profile := externalTestRead(t, source[4])
					if !reflect.DeepEqual(graph["dns"], nodeGraph["dns"]) || plan.meta.ExitMode != source[2] || plan.meta.Execution != "local" || plan.meta.EntryKind != "external" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.EntryNodeID != "" || plan.meta.ExitAPI != profile["router_api"] || plan.meta.ExitToken != profile["api_token"] || plan.meta.ExitNodeID != profile["node_proof_id"] || plan.Healthy() {
						t.Fatal("XHTTP selection changed final DNS, independent proof authority or live state")
					}
					if strings.HasSuffix(kind, "-connect") && plan.meta.TransportCapability != "vless-stream" {
						t.Fatal("PQ CONNECT lost its native VLESS capability")
					}
					if !reflect.DeepEqual(source, captured) || plan.SourceSHA256() == old.SourceSHA256() {
						t.Fatal("XHTTP source seal lost exact final encryption selection")
					}
					if directory := os.Getenv("ROUTERVPN_IMPORTED_XHTTP_XRAY_FIXTURES"); directory != "" {
						receipt, _ := json.Marshal(append(captured, plan.SourceSHA256(), plan.Config()))
						if err := os.WriteFile(filepath.Join(directory, kind+"--reality-xhttp--"+first+"--"+last+".json"), receipt, 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestImportedXHTTPRejectsDowngradeAndForeignSources(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, fault := range []string{"ordinary-encryption", "missing-encryption", "foreign-encryption", "missing-xray", "foreign-ss-authority", "foreign-xray-route", "ordinary-label", "pq-label", "foreign-flow", "udp443-flow", "raw-network", "missing-settings", "missing-path", "relative-path", "foreign-mode", "download-settings", "missing-final-layer", "foreign-final-layer", "missing-entry-layer", "server", "compare", "missing-pairing"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				source := importedXHTTPFixture(t, kind, "aes-256-gcm", "aes-256-gcm+xor-whitening")
				assets, raw, _ := importedSOCKSXrayRaw(t, source[3])
				profile, capture := externalTestRead(t, source[4]), externalTestRead(t, source[1])
				switch fault {
				case "ordinary-encryption":
					importedPQUser(raw)["encryption"] = "none"
				case "missing-encryption":
					delete(importedPQUser(raw), "encryption")
				case "foreign-encryption":
					importedPQUser(raw)["encryption"] = "mlkem1024.foreign"
				case "missing-xray":
					delete(assets, "xray.json")
				case "foreign-ss-authority":
					assets["routervpn-ss-service.json"] = base64.StdEncoding.EncodeToString([]byte("{}"))
				case "foreign-xray-route":
					raw["routing"] = map[string]any{"domainStrategy": "AsIs"}
				case "ordinary-label":
					source[2] = "reality-vision"
				case "pq-label":
					source[2] = "reality-pq-vision"
				case "foreign-flow":
					importedPQUser(raw)["flow"] = applexray.VisionFlow
				case "udp443-flow":
					importedPQUser(raw)["flow"] = applexray.VisionUDP443Flow
				case "raw-network":
					importedXHTTPStream(raw)["network"] = "raw"
				case "missing-settings":
					delete(importedXHTTPStream(raw), "xhttpSettings")
				case "missing-path":
					delete(importedXHTTPStream(raw)["xhttpSettings"].(map[string]any), "path")
				case "relative-path":
					importedXHTTPStream(raw)["xhttpSettings"].(map[string]any)["path"] = "relative"
				case "foreign-mode":
					importedXHTTPStream(raw)["xhttpSettings"].(map[string]any)["mode"] = "stream-one"
				case "download-settings":
					importedXHTTPStream(raw)["xhttpSettings"].(map[string]any)["downloadSettings"] = map[string]any{"address": "198.51.100.99"}
				case "missing-final-layer":
					source[5] = ""
				case "foreign-final-layer":
					var start map[string]string
					json.Unmarshal([]byte(source[5]), &start)
					data, _ := base64.StdEncoding.DecodeString(start["sing-box.json"])
					layer := externalTestRead(t, string(data))
					layer["outbounds"].([]any)[0].(map[string]any)["server"] = "198.51.100.99"
					start["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, layer)))
					source[5] = externalTestJSON(t, start)
				case "missing-entry-layer":
					delete(capture["profile"].(map[string]any)["external"].(map[string]any), "start_layer")
				case "server":
					profile["multihop_execution"] = "server"
				case "compare":
					profile["multihop_execution"] = "auto"
				case "missing-pairing":
					delete(profile, "node_proof_id")
				}
				if fault != "missing-xray" {
					assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, raw)))
				}
				source[1], source[3], source[4] = externalTestJSON(t, capture), externalTestJSON(t, assets), externalTestJSON(t, profile)
				if plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || plan != nil {
					t.Fatal("XHTTP graph accepted downgraded or foreign source")
				}
			})
		}
	}
}

func TestImportedXHTTPPreservesSelectedDNSAndUDP443(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, flow := range []string{""} {
			for _, transport := range []string{"udp", "tcp", "tls", "https", "h3"} {
				t.Run(kind+"/"+flow+"/"+transport, func(t *testing.T) {
					source := importedXHTTPFixture(t, kind, "off", "aes-256-gcm")
					importedCONNECTXrayFlow(t, source, flow)
					profile := externalTestRead(t, source[4])
					profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", transport, "203.0.113.53", float64(443)
					if transport == "tls" || transport == "https" || transport == "h3" {
						profile["dns_server_name"] = "resolver.example.test"
					}
					if transport == "https" || transport == "h3" {
						profile["dns_path"] = "/dns-query"
					}
					source[4] = externalTestJSON(t, profile)
					plan := importedPacketXrayCompile(t, source)
					graph := importedPQGraph(t, plan.Config())
					final := externalTestFind(t, graph, LocalTag)
					if importedPQUser(externalTestRead(t, final["config_json"].(string)))["flow"] != flow {
						t.Fatal("XHTTP graph replaced its empty flow for selected DNS")
					}
					dns := graph["dns"].(map[string]any)
					server := dns["servers"].([]any)[0].(map[string]any)
					if server["type"] != transport || server["server"] != "203.0.113.53" || server["server_port"] != float64(443) || server["detour"] != "proxy" {
						t.Fatal("XHTTP graph replaced selected final DNS or its route")
					}
				})
			}
		}
	}
}

func TestImportedXHTTPPreservesAllowedNetworkAndFlow(t *testing.T) {
	for _, network := range []string{"xhttp", "splithttp"} {
		for _, explicit := range []bool{false, true} {
			t.Run(network+"/"+map[bool]string{false: "absent", true: "empty"}[explicit], func(t *testing.T) {
				source := importedXHTTPFixture(t, "socks5", "off", "off")
				assets, raw, _ := importedSOCKSXrayRaw(t, source[3])
				importedXHTTPStream(raw)["network"] = network
				if explicit {
					importedPQUser(raw)["flow"] = ""
				}
				assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, raw)))
				source[3] = externalTestJSON(t, assets)
				plan := importedPacketXrayCompile(t, source)
				final := externalTestFind(t, importedPQGraph(t, plan.Config()), LocalTag)
				captured := externalTestRead(t, final["config_json"].(string))
				_, present := importedPQUser(captured)["flow"]
				if importedXHTTPStream(captured)["network"] != network || present != explicit || predecessorText(importedPQUser(captured), "flow") != "" {
					t.Fatal("XHTTP rewrote captured network or flow")
				}
			})
		}
	}
}

func TestImportedXHTTPLegacyRawAssetsRemainCaptured(t *testing.T) {
	for _, kind := range importedPQKinds {
		t.Run(kind, func(t *testing.T) {
			source := importedXHTTPFixture(t, kind, "off", "off")
			full := importedPacketXrayCompile(t, source)
			assets, _, _ := importedSOCKSXrayRaw(t, source[3])
			delete(assets, "sing-box.json")
			source[3] = externalTestJSON(t, assets)
			rawOnly := importedPacketXrayCompile(t, source)
			if full.Config() != rawOnly.Config() || full.SourceSHA256() == rawOnly.SourceSHA256() {
				t.Fatal("legacy XHTTP raw capture changed graph or lost distinct source identity")
			}
		})
	}
}
