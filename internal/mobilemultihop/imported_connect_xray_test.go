package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativecomposite"
)

// These are two original transports. The CONNECT endpoint is never converted
// to SOCKS, and the paired REALITY source never acquires SS UoT authority.
func importedCONNECTXrayFixture(t *testing.T, protocol, first, last string) []string {
	t.Helper()
	if last == "off" {
		last = ""
	}
	source := importedSOCKSXrayFixture(t, "", last)
	graph, capture := externalTestFixture(t, protocol, "")
	if first != "off" && first != "" {
		externalTestAddLayer(capture["profile"].(map[string]any), first, "203.0.113.20", "10.93.0.1", "i")
	}
	source[0], source[1] = externalTestJSON(t, graph), externalTestJSON(t, capture)
	return source
}

func importedCONNECTXrayCompile(t *testing.T, source []string) *Controller {
	t.Helper()
	if len(source) != 7 {
		t.Fatal("CONNECT REALITY lost its seven original private inputs")
	}
	plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
	if err != nil {
		t.Fatal("captured CONNECT REALITY graph was rejected", err)
	}
	return plan
}

func importedCONNECTXrayFlow(t *testing.T, source []string, flow string) {
	t.Helper()
	assets, xray, _ := importedSOCKSXrayRaw(t, source[3])
	user := xray["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	user["flow"] = flow
	assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, xray)))
	source[3] = externalTestJSON(t, assets)
}

func TestImportedCONNECTRealityVisionIndependentLayers(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			for _, firstLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, finalLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(firstLayer+"/"+finalLayer, func(t *testing.T) {
						source := importedCONNECTXrayFixture(t, protocol, firstLayer, finalLayer)
						captured := append([]string(nil), source...)
						plan := importedCONNECTXrayCompile(t, source)
						original := externalTestRead(t, source[0])
						original["endpoints"] = []any{}
						graph := externalTestRead(t, plan.Config())
						graph["endpoints"] = []any{}
						first, final := externalTestFind(t, graph, "entry-wg"), externalTestFind(t, graph, LocalTag)
						originalFirst := externalTestFind(t, original, ExternalFinalTag)
						copied := predecessorCopy(first)
						copied["tag"] = ExternalFinalTag
						delete(copied, "detour")
						if firstLayer != "off" {
							copied["server"], copied["server_port"] = originalFirst["server"], originalFirst["server_port"]
						}
						if first["type"] != "http" || !reflect.DeepEqual(copied, originalFirst) {
							t.Fatal("CONNECT changed its original authentication, TLS or inner protocol")
						}
						if firstLayer == "off" {
							if first["detour"] != nil {
								t.Fatal("Off CONNECT entry acquired a foreign layer")
							}
						} else {
							outer := externalTestFind(t, graph, first["detour"].(string))
							entry := externalTestRead(t, source[1])["profile"].(map[string]any)
							provision := entry["external"].(map[string]any)["start_layer"].(map[string]any)
							expected := predecessorCopy(provision["transport"].(map[string]any))
							expected["tag"] = outer["tag"]
							if firstLayer == "aes-256-gcm+xor-whitening" {
								expected["type"], expected["server_port"] = "routervpn-aes-xor", float64(8389)
							}
							if !reflect.DeepEqual(outer, expected) || first["server"] != "10.93.0.1" || provision["api"] != "http://10.93.0.1:8787" {
								t.Fatal("CONNECT layer replaced its original physical owner or private inner endpoint")
							}
						}
						node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
						if err != nil {
							t.Fatal(err)
						}
						nodeGraph := externalTestRead(t, node.Config())
						nodeGraph["endpoints"] = []any{}
						originalFinal := externalTestFind(t, nodeGraph, "proxy")
						if len(final) != 5 || final["type"] != "routervpn-xray" || final["mode"] != "reality-vision" || final["config_json"] != originalFinal["config_json"] {
							t.Fatal("CONNECT changed the original paired VLESS/REALITY transport")
						}
						if finalLayer == "off" {
							if final["detour"] != "entry-wg" {
								t.Fatal("REALITY final lost its captured CONNECT stream owner")
							}
						} else {
							if final["detour"] != applexray.StartLayerTag {
								t.Fatal("REALITY bypassed the final authenticated layer")
							}
							outer := externalTestFind(t, graph, applexray.StartLayerTag)
							expected := externalTestFind(t, nodeGraph, applexray.StartLayerTag)
							copied := predecessorCopy(outer)
							delete(copied, "detour")
							if outer["detour"] != "entry-wg" || !reflect.DeepEqual(copied, expected) {
								t.Fatal("CONNECT REALITY borrowed a different final layer or physical owner")
							}
							if firstLayer != "off" {
								entryOuter := externalTestFind(t, graph, first["detour"].(string))
								if entryOuter["password"] == outer["password"] || entryOuter["server"] == outer["server"] || entryOuter["tag"] == outer["tag"] {
									t.Fatal("CONNECT and REALITY layers collapsed their independent credentials")
								}
							}
						}
						if plan.meta.TransportCapability != "vless-stream" || plan.meta.EntryKind != "external" || plan.meta.EntryMode != protocol || plan.meta.ExitMode != "reality-vision" || plan.meta.Execution != "local" || plan.meta.EntryNodeID != "" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.Healthy() {
							t.Fatal("CONNECT fabricated a private entry identity, readiness or SS UoT capability")
						}
						if !reflect.DeepEqual(graph["dns"], nodeGraph["dns"]) || !reflect.DeepEqual(source, captured) {
							t.Fatal("CONNECT REALITY changed selected DNS or original private source bytes")
						}
						for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
							if rule := raw.(map[string]any); rule["network"] == "udp" && rule["action"] == "reject" {
								t.Fatal("CONNECT rejected the real final's VLESS datagram carrier")
							}
						}
						importedSOCKSXrayDevicePolicy(t, graph, "default-home")
						expectedInputs, _ := json.Marshal(append([]string{"routervpn-imported-entry-v1"}, source...))
						if plan.SourceSHA256() != externalDigest(expectedInputs) {
							t.Fatal("CONNECT REALITY lost one of its seven original source identities")
						}
						for _, index := range []int{0, 1, 3, 4, 5} {
							if source[index] == "" {
								continue
							}
							changed := append([]string(nil), source...)
							changed[index] += "\n"
							next := importedCONNECTXrayCompile(t, changed)
							if next.Config() != plan.Config() || next.SourceSHA256() == plan.SourceSHA256() {
								t.Fatal("CONNECT restored equivalent graph bytes using a different private original")
							}
						}
						if _, err := New(plan.Config(), plan.Metadata()); err == nil {
							t.Fatal("CONNECT metadata acquired the original capture's authority")
						}
						if directory := os.Getenv("ROUTERVPN_IMPORTED_CONNECT_XRAY_FIXTURES"); directory != "" {
							receipt := append(append([]string(nil), source...), plan.SourceSHA256(), plan.Config())
							name := protocol + "--reality-vision--" + firstLayer + "--" + finalLayer + ".json"
							if err := os.WriteFile(filepath.Join(directory, name), []byte(externalTestJSON(t, receipt)), 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		})
	}
}

func TestImportedCONNECTRealityVisionSelectedPolicy(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			for _, policy := range []string{"default-home", "custom-udp", "custom-tcp", "tls", "https", "h3", "ipv6-off", "lan-off", "fixed-mtu"} {
				t.Run(policy, func(t *testing.T) {
					source := importedCONNECTXrayFixture(t, protocol, "aes-256-gcm+xor-whitening", "aes-256-gcm")
					profile := externalTestRead(t, source[4])
					switch policy {
					case "custom-udp", "custom-tcp":
						profile["dns_mode"], profile["dns_protocol"] = "custom", strings.TrimPrefix(policy, "custom-")
						profile["dns_host"], profile["dns_port"] = "203.0.113.53", 5353
					case "tls", "https", "h3":
						profile["dns_mode"], profile["dns_protocol"] = "custom", policy
						profile["dns_host"], profile["dns_server_name"] = "203.0.113.53", "resolver.example.net"
						profile["dns_port"] = 853
						if policy != "tls" {
							profile["dns_port"], profile["dns_path"] = 443, "/owned-dns-query"
						}
						if policy == "h3" {
							importedCONNECTXrayFlow(t, source, applexray.VisionUDP443Flow)
						}
					case "ipv6-off":
						profile["ipv6_mode"] = "off"
					case "lan-off":
						profile["home_lan_access"] = false
					case "fixed-mtu":
						profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1392
					}
					source[4] = externalTestJSON(t, profile)
					plan := importedCONNECTXrayCompile(t, source)
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					graph := externalTestRead(t, plan.Config())
					if plan.meta.TransportCapability != "vless-stream" || !reflect.DeepEqual(graph["dns"], externalTestRead(t, node.Config())["dns"]) {
						t.Fatal("CONNECT REALITY changed selected final policy")
					}
					if policy != "tls" && policy != "https" && policy != "h3" {
						importedSOCKSXrayDevicePolicy(t, graph, policy)
					}
				})
			}
		})
	}
}

func TestImportedCONNECTRealityVisionOriginalFlowsAndBootstrap(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			for _, flow := range []string{applexray.VisionFlow, applexray.VisionUDP443Flow} {
				t.Run(flow, func(t *testing.T) {
					for _, transport := range []string{"tls", "https", "h3"} {
						t.Run(transport, func(t *testing.T) {
							source := importedCONNECTXrayFixture(t, protocol, "aes-256-gcm", "aes-256-gcm+xor-whitening")
							importedCONNECTXrayFlow(t, source, flow)
							profile := externalTestRead(t, source[4])
							profile["dns_mode"], profile["dns_protocol"] = "custom", transport
							profile["dns_host"], profile["dns_port"] = "resolver.example.net", 8853
							profile["dns_server_name"], profile["dns_path"] = "resolver.example.net", "/owned-dns-query"
							source[4] = externalTestJSON(t, profile)
							source[6] = externalTestJSON(t, map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "203.0.113.54", "server_port": 5354, "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "timeout": "3s", "disable_cache": true}})
							plan := importedCONNECTXrayCompile(t, source)
							node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
							if err != nil {
								t.Fatal(err)
							}
							graph, original := externalTestRead(t, plan.Config()), externalTestRead(t, node.Config())
							graph["endpoints"], original["endpoints"] = []any{}, []any{}
							if !reflect.DeepEqual(graph["dns"], original["dns"]) || externalTestFind(t, graph, LocalTag)["config_json"] != externalTestFind(t, original, "proxy")["config_json"] {
								t.Fatal("CONNECT replaced the original flow, selected DNS or UDP bootstrap")
							}
							// This is source/capture evidence. The native gate separately
							// proves ordinary Vision's UDP443 refusal and opt-in DoH3.
						})
					}
				})
			}
		})
	}
}

func TestImportedCONNECTRealityVisionNeverBorrowsSSAuthority(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			for _, kind := range []string{"no-service", "same-node-layer-service", "foreign-final-service"} {
				t.Run(kind, func(t *testing.T) {
					source := importedCONNECTXrayFixture(t, protocol, "aes-256-gcm", "aes-256-gcm+xor-whitening")
					profile := externalTestRead(t, source[4])
					if kind != "no-service" {
						source[5] = pairedSSServiceFiles(t, source[5], profile["node_proof_id"].(string))
					}
					if kind == "foreign-final-service" {
						var final, layer map[string]string
						if json.Unmarshal([]byte(source[3]), &final) != nil || json.Unmarshal([]byte(source[5]), &layer) != nil {
							t.Fatal("invalid original source maps")
						}
						final[nativecomposite.SSServiceAsset] = layer[nativecomposite.SSServiceAsset]
						source[3] = externalTestJSON(t, final)
						if plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || plan != nil {
							t.Fatal("REALITY accepted another protocol's service authority")
						}
						return
					}
					plan := importedCONNECTXrayCompile(t, source)
					if plan.meta.TransportCapability != "vless-stream" {
						t.Fatal("CONNECT depended on the layer's SS service for VLESS datagrams")
					}
					for _, raw := range externalTestRead(t, plan.Config())["outbounds"].([]any) {
						if _, present := raw.(map[string]any)["udp_over_tcp"]; present {
							t.Fatal("CONNECT injected SS UoT into the VLESS carrier")
						}
					}
				})
			}
		})
	}
}

func TestImportedCONNECTRealityVisionRejectsChangedAuthority(t *testing.T) {
	faults := []string{"entry-password", "entry-username", "entry-endpoint", "entry-protocol", "entry-tls-source", "entry-insecure", "entry-layer-missing", "entry-layer-mode", "entry-layer-foreign", "entry-layer-unused", "entry-route", "entry-paired-proof", "entry-paired-api", "same-node", "final-not-paired", "final-missing-proof", "final-missing-token", "final-missing-xray", "final-wrapper", "final-plaintext", "final-flow", "final-layer-missing", "final-layer-foreign", "final-layer-unused", "server", "compare", "foreign-bootstrap"}
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {
					source := importedCONNECTXrayFixture(t, protocol, "aes-256-gcm+xor-whitening", "aes-256-gcm")
					_ = importedCONNECTXrayCompile(t, source)
					graph, capture, profile := externalTestRead(t, source[0]), externalTestRead(t, source[1]), externalTestRead(t, source[4])
					graph["endpoints"] = []any{}
					first := externalTestFind(t, graph, ExternalFinalTag)
					entry := capture["profile"].(map[string]any)
					external := entry["external"].(map[string]any)
					assets, xray, _ := importedSOCKSXrayRaw(t, source[3])
					switch fault {
					case "entry-password":
						first["password"] = "foreign-original-secret"
					case "entry-username":
						first["username"] = "foreign-original-user"
					case "entry-endpoint":
						first["server"] = "203.0.113.99"
					case "entry-protocol":
						capture["protocol"] = "socks5"
					case "entry-tls-source":
						first["tls"] = map[string]any{"enabled": true, "server_name": "foreign-entry.example.net"}
					case "entry-insecure":
						first["tls"] = map[string]any{"enabled": true, "server_name": "entry.example.net", "insecure": true}
						if protocol == "https-connect" {
							external["https_connect"].(map[string]any)["tls_insecure"] = true
						}
					case "entry-layer-missing":
						delete(external, "start_layer")
					case "entry-layer-mode":
						entry["start_layer"] = "aes-256-gcm"
					case "entry-layer-foreign":
						external["start_layer"].(map[string]any)["transport"].(map[string]any)["server"] = "203.0.113.99"
					case "entry-layer-unused":
						entry["start_layer"] = "off"
					case "entry-route":
						first["detour"] = "foreign-owner"
					case "entry-paired-proof":
						entry["node_proof_id"] = strings.Repeat("a", 64)
					case "entry-paired-api":
						entry["router_api"] = "http://10.93.0.1:8787"
					case "same-node":
						profile["id"] = capture["exit_id"]
					case "final-not-paired":
						profile["node_kind"] = "external"
					case "final-missing-proof":
						delete(profile, "node_proof_id")
					case "final-missing-token":
						delete(profile, "api_token")
					case "final-missing-xray":
						delete(assets, "xray.json")
					case "final-wrapper":
						raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
						wrapper := externalTestRead(t, string(raw))
						wrapper["outbounds"].([]any)[0].(map[string]any)["detour"] = "foreign-owner"
						assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, wrapper)))
					case "final-plaintext":
						xray["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["security"] = "none"
						assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, xray)))
					case "final-flow":
						xray["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["flow"] = "vision+udp443"
						assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, xray)))
					case "final-layer-missing":
						source[5] = ""
					case "final-layer-foreign":
						var layer map[string]string
						if json.Unmarshal([]byte(source[5]), &layer) != nil {
							t.Fatal("invalid original final layer map")
						}
						raw, _ := base64.StdEncoding.DecodeString(layer["sing-box.json"])
						wrapper := externalTestRead(t, string(raw))
						wrapper["outbounds"].([]any)[0].(map[string]any)["server"] = "203.0.113.99"
						layer["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, wrapper)))
						source[5] = externalTestJSON(t, layer)
					case "final-layer-unused":
						profile["start_layer"] = "off"
					case "server":
						profile["multihop_execution"] = "server"
					case "compare":
						profile["multihop_execution"] = "auto"
					case "foreign-bootstrap":
						source[6] = `{"server":{"type":"udp","tag":"external-dns-bootstrap","server":"203.0.113.54","detour":"direct"},"query":{"server":"external-dns-bootstrap"}}`
					}
					source[0], source[1], source[3], source[4] = externalTestJSON(t, graph), externalTestJSON(t, capture), externalTestJSON(t, assets), externalTestJSON(t, profile)
					if plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || plan != nil {
						t.Fatal("CONNECT REALITY accepted changed original authority", fault)
					}
				})
			}
		})
	}
}

func TestImportedCONNECTRealityVisionKeepsScope(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			for _, mode := range []string{"hysteria2", "wg", "awg2-fast", "awg2-strong", "reality-pq-vision", "reality-xhttp", "split", "max"} {
				t.Run(mode, func(t *testing.T) {
					source := importedCONNECTXrayFixture(t, protocol, "off", "off")
					files, profile, start := nodeProfileFixture(t, mode, "")
					if _, err := NewNodeProfile(mode, files, externalTestJSON(t, profile), start, ""); err != nil {
						t.Fatal("scope control did not begin with a valid paired source", err)
					}
					// PQ/XHTTP require their exact assets; retain this
					// required scope verdict as an ordinary-under-native downgrade rejection.
					if mode == "reality-pq-vision" || mode == "reality-xhttp" {
						files, _, _ = nodeProfileFixture(t, "reality-vision", "")
					}
					if plan, err := NewImportedEntry(source[0], source[1], mode, files, externalTestJSON(t, profile), start, ""); err == nil || plan != nil {
						t.Fatal("CONNECT REALITY widened another graph family")
					}
				})
			}
		})
	}
}
