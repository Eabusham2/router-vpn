package mobilemultihop

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/applexray"
)

var importedPQKinds = []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"}
var importedPQLayers = []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"}

// These are the existing independently captured imported graphs. Only the
// paired final selects its own PQ asset map; imported credentials stay intact.
func importedPQFixture(t *testing.T, kind, first, last string) []string {
	t.Helper()
	var source []string
	switch kind {
	case "socks5":
		source = importedSOCKSXrayFixture(t, strings.TrimPrefix(first, "off"), strings.TrimPrefix(last, "off"))
	case "shadowsocks", "hysteria2":
		source = importedProxyXrayFixture(t, kind, first, last)
	case "http-connect", "https-connect":
		source = importedCONNECTXrayFixture(t, kind, first, last)
	default:
		source = importedPacketXrayFixture(t, kind, first, last)
	}
	assets, xray, _ := importedSOCKSXrayRaw(t, source[3])
	user := importedPQUser(xray)
	// Valid deterministic public test material, never a production credential.
	pq, err := mlkem.NewDecapsulationKey768(bytes.Repeat([]byte{0x65}, 64))
	if err != nil {
		t.Fatal(err)
	}
	user["encryption"] = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())
	assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, xray)))
	source[2], source[3] = "reality-pq-vision", externalTestJSON(t, assets)
	return source
}

func importedPQUser(xray map[string]any) map[string]any {
	return xray["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
}

func importedPQGraph(t *testing.T, raw string) map[string]any {
	graph := externalTestRead(t, raw)
	if graph["endpoints"] == nil {
		graph["endpoints"] = []any{}
	}
	return graph
}

func TestImportedPQRealityIndependentLayers(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, first := range importedPQLayers {
			for _, last := range importedPQLayers {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					source := importedPQFixture(t, kind, first, last)
					captured := append([]string(nil), source...)
					plan := importedPacketXrayCompile(t, source)
					graph := importedPQGraph(t, plan.Config())
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					nodeGraph := importedPQGraph(t, node.Config())
					final, original := externalTestFind(t, graph, LocalTag), externalTestFind(t, nodeGraph, "proxy")
					if len(final) != 5 || final["type"] != applexray.Type || final["mode"] != "reality-pq-vision" || final["config_json"] != original["config_json"] {
						t.Fatal("PQ final replaced its exact captured native transport")
					}
					pq := externalTestRead(t, final["config_json"].(string))
					if !strings.HasPrefix(importedPQUser(pq)["encryption"].(string), "mlkem768x25519plus.native.0rtt.") || importedPQUser(pq)["flow"] != applexray.VisionFlow {
						t.Fatal("PQ final lost hybrid encryption or captured Vision flow")
					}
					if last == "off" {
						if final["detour"] != "entry-wg" {
							t.Fatal("PQ final bypassed the imported entry")
						}
					} else {
						outer := externalTestFind(t, graph, applexray.StartLayerTag)
						copy := predecessorCopy(outer)
						delete(copy, "detour")
						if final["detour"] != applexray.StartLayerTag || outer["detour"] != "entry-wg" || !reflect.DeepEqual(copy, externalTestFind(t, nodeGraph, applexray.StartLayerTag)) {
							t.Fatal("PQ final bypassed or replaced its independent Start Layer")
						}
					}
					// Compile the same import with the original ordinary final to
					// compare every retained entry edge and credential, including
					// packet endpoint parameters and independent wrapper sources.
					ordinary := append([]string(nil), source...)
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
									t.Fatal("PQ selection changed imported entry credentials or layer ownership")
								}
							}
						}
					}
					profile := externalTestRead(t, source[4])
					if !reflect.DeepEqual(graph["dns"], nodeGraph["dns"]) || plan.meta.ExitMode != source[2] || plan.meta.Execution != "local" || plan.meta.EntryKind != "external" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.EntryNodeID != "" || plan.meta.ExitAPI != profile["router_api"] || plan.meta.ExitToken != profile["api_token"] || plan.meta.ExitNodeID != profile["node_proof_id"] || plan.Healthy() {
						t.Fatal("PQ selection changed final DNS, independent proof authority or live state")
					}
					if strings.HasSuffix(kind, "-connect") && plan.meta.TransportCapability != "vless-stream" {
						t.Fatal("PQ CONNECT lost its native VLESS capability")
					}
					if !reflect.DeepEqual(source, captured) || plan.SourceSHA256() == old.SourceSHA256() {
						t.Fatal("PQ source seal lost exact final encryption selection")
					}
					if directory := os.Getenv("ROUTERVPN_IMPORTED_PQ_XRAY_FIXTURES"); directory != "" {
						receipt, _ := json.Marshal(append(captured, plan.SourceSHA256(), plan.Config()))
						if err := os.WriteFile(filepath.Join(directory, kind+"--reality-pq-vision--"+first+"--"+last+".json"), receipt, 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestImportedPQRealityRejectsDowngradeAndForeignSources(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, fault := range []string{"ordinary-encryption", "missing-encryption", "foreign-encryption", "missing-xray", "missing-wrapper", "foreign-ss-authority", "foreign-xray-route", "ordinary-label", "xhttp-label", "foreign-flow", "missing-final-layer", "foreign-final-layer", "missing-entry-layer", "server", "compare", "missing-pairing"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				source := importedPQFixture(t, kind, "aes-256-gcm", "aes-256-gcm+xor-whitening")
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
				case "missing-wrapper":
					delete(assets, "sing-box.json")
				case "foreign-ss-authority":
					assets["routervpn-ss-service.json"] = base64.StdEncoding.EncodeToString([]byte("{}"))
				case "foreign-xray-route":
					raw["routing"] = map[string]any{"domainStrategy": "AsIs"}
				case "ordinary-label":
					source[2] = "reality-vision"
				case "xhttp-label":
					source[2] = "reality-xhttp"
				case "foreign-flow":
					importedPQUser(raw)["flow"] = ""
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
					t.Fatal("PQ graph accepted downgraded or foreign source")
				}
			})
		}
	}
}

func TestImportedPQRealityPreservesSelectedDNSAndUDP443(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, flow := range []string{applexray.VisionFlow, applexray.VisionUDP443Flow} {
			for _, transport := range []string{"udp", "tcp", "tls", "https", "h3"} {
				t.Run(kind+"/"+flow+"/"+transport, func(t *testing.T) {
					source := importedPQFixture(t, kind, "off", "aes-256-gcm")
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
						t.Fatal("PQ graph replaced explicit Vision UDP443 policy")
					}
					dns := graph["dns"].(map[string]any)
					server := dns["servers"].([]any)[0].(map[string]any)
					if server["type"] != transport || server["server"] != "203.0.113.53" || server["server_port"] != float64(443) || server["detour"] != "proxy" {
						t.Fatal("PQ graph replaced selected final DNS or its route")
					}
				})
			}
		}
	}
}
