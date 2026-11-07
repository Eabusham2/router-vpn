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
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/nativeopenvpn"
)

// The names distinguish original OpenVPN wire transports, not new UI modes.
var importedPacketXrayKinds = []string{"wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"}

func importedPacketXrayFixture(t *testing.T, kind, first, last string) []string {
	t.Helper()
	if first == "off" {
		first = ""
	}
	if last == "off" {
		last = ""
	}
	var source []string
	if strings.HasPrefix(kind, "openvpn-") {
		source = importedOpenVPNFixture(t, strings.TrimPrefix(kind, "openvpn-"), "reality-vision", first, last)
	} else {
		source = importedPacketFixture(t, kind, "reality-vision", first, last)
	}
	profile := externalTestRead(t, source[4])
	profile["multihop_execution"] = "local"
	if last == "" {
		profile["start_layer"] = "off"
	}
	source[4] = externalTestJSON(t, profile)
	return source
}

func importedPacketXrayCompile(t *testing.T, source []string) *Controller {
	t.Helper()
	if len(source) != 7 {
		t.Fatal("packet REALITY lost an original private input")
	}
	plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
	if err != nil {
		t.Fatal("captured packet REALITY source was rejected", err)
	}
	t.Cleanup(func() { _ = plan.Close() })
	return plan
}

func TestImportedPacketRealityVisionIndependentLayers(t *testing.T) {
	for _, kind := range importedPacketXrayKinds {
		t.Run(kind, func(t *testing.T) {
			for _, firstLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, lastLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(firstLayer+"/"+lastLayer, func(t *testing.T) {
						source := importedPacketXrayFixture(t, kind, firstLayer, lastLayer)
						captured := append([]string(nil), source...)
						plan := importedPacketXrayCompile(t, source)
						graph := externalTestRead(t, plan.Config())
						original := externalTestFind(t, externalTestRead(t, source[0]), ExternalFinalTag)
						entry := externalTestFind(t, graph, "entry-wg")
						if endpoints, ok := graph["endpoints"].([]any); !ok || len(endpoints) != 1 {
							t.Fatal("REALITY did not retain exactly one native packet endpoint")
						}
						copy := predecessorCopy(entry)
						copy["tag"] = ExternalFinalTag
						delete(copy, "detour")
						protocol := kind
						if strings.HasPrefix(kind, "openvpn-") {
							protocol = "openvpn"
							if !plan.hasImportedOpenVPN() || plan.imported.openvpnMTU != 1500 || !reflect.DeepEqual(entry, plan.imported.openvpnTransport) {
								t.Fatal("OpenVPN REALITY lost original connected-state/MTU authority")
							}
						} else if firstLayer != "off" {
							peer := copy["peers"].([]any)[0].(map[string]any)
							oldPeer := original["peers"].([]any)[0].(map[string]any)
							if peer["address"] != "10.93.0.1" {
								t.Fatal("packet layer lost captured private inner destination")
							}
							peer["address"], peer["port"] = oldPeer["address"], oldPeer["port"]
						}
						if !reflect.DeepEqual(copy, original) {
							t.Fatal("packet REALITY changed original keys, peer/cipher/control parameters, remotes or MTU", copy, original)
						}
						if firstLayer == "off" {
							if entry["detour"] != nil {
								t.Fatal("unlayered packet entry acquired another physical owner")
							}
						} else {
							outer := externalTestFind(t, graph, entry["detour"].(string))
							if outer["detour"] != nil {
								t.Fatal("packet entry layer bypassed its physical owner")
							}
							if protocol == "openvpn" {
								if outer["type"] != nativeopenvpn.LayerMapType {
									t.Fatal("OpenVPN entry lost its exact native layer mapper")
								}
								payload := predecessorCopy(outer)
								delete(payload, "type")
								delete(payload, "tag")
								var mapping nativeopenvpn.LayerMap
								if json.Unmarshal([]byte(externalTestJSON(t, payload)), &mapping) != nil || mapping.Validate() != nil || mapping.Mode != firstLayer || len(mapping.Remotes) != 1 || mapping.Remotes[0].Network != strings.TrimPrefix(kind, "openvpn-") || mapping.Remotes[0].Host != "203.0.113.24" || mapping.Remotes[0].Port != 1194 {
									t.Fatal("OpenVPN layer lost its exact public remote/control transport")
								}
							} else if outer["server"] != original["peers"].([]any)[0].(map[string]any)["address"] {
								t.Fatal("packet layer borrowed another public endpoint")
							}
						}
						node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
						if err != nil {
							t.Fatal(err)
						}
						nodeGraph := externalTestRead(t, node.Config())
						nodeGraph["endpoints"] = []any{}
						final, originalFinal := externalTestFind(t, graph, LocalTag), externalTestFind(t, nodeGraph, "proxy")
						if len(final) != 5 || final["type"] != "routervpn-xray" || final["mode"] != "reality-vision" || final["config_json"] != originalFinal["config_json"] {
							t.Fatal("packet entry replaced the original VLESS/REALITY source")
						}
						if lastLayer == "off" {
							if final["detour"] != "entry-wg" {
								t.Fatal("REALITY stream bypassed original packet endpoint")
							}
						} else {
							if final["detour"] != applexray.StartLayerTag {
								t.Fatal("REALITY lost independently captured final layer")
							}
							outer := externalTestFind(t, graph, applexray.StartLayerTag)
							copy := predecessorCopy(outer)
							delete(copy, "detour")
							if outer["detour"] != "entry-wg" || !reflect.DeepEqual(copy, externalTestFind(t, nodeGraph, applexray.StartLayerTag)) {
								t.Fatal("REALITY borrowed a different final wrapper or packet owner")
							}
						}
						if !reflect.DeepEqual(graph["dns"], nodeGraph["dns"]) || !reflect.DeepEqual(source, captured) || plan.meta.EntryMode != protocol || plan.meta.ExitMode != "reality-vision" || plan.meta.EntryKind != "external" || plan.meta.EntryNodeID != "" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.Execution != "local" || plan.meta.TransportCapability != "" || plan.Healthy() {
							t.Fatal("packet REALITY changed DNS/private sources or fabricated proof, UoT authority or readiness")
						}
						if plan.meta.PacketMTUState != "" || plan.meta.PacketControlMax != "" || plan.meta.PacketDataOverhead != "" {
							t.Fatal("VLESS stream invented a nested raw-packet final envelope")
						}
						importedSOCKSXrayDevicePolicy(t, graph, "default-home")
						mtu, err := mobilemtu.NewPlan(plan.Config(), 1280)
						if err != nil {
							t.Fatal(err)
						}
						retuned, err := mtu.Config(1400)
						if err != nil || !reflect.DeepEqual(externalTestFind(t, externalTestRead(t, retuned), "entry-wg"), entry) {
							t.Fatal("virtual TUN retest rewrote the original packet interface", err)
						}
						inputs, _ := json.Marshal(append([]string{"routervpn-imported-entry-v1"}, source...))
						if plan.SourceSHA256() != externalDigest(inputs) {
							t.Fatal("packet REALITY lost complete source identity")
						}
						if _, err := New(plan.Config(), plan.Metadata()); err == nil {
							t.Fatal("public metadata acquired original packet authority")
						}
						if directory := os.Getenv("ROUTERVPN_IMPORTED_PACKET_XRAY_FIXTURES"); directory != "" {
							receipt := append(append([]string(nil), source...), plan.SourceSHA256(), plan.Config())
							name := kind + "--reality-vision--" + firstLayer + "--" + lastLayer + ".json"
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

func TestImportedPacketRealityVisionSelectedPolicy(t *testing.T) {
	for _, kind := range importedPacketXrayKinds {
		t.Run(kind, func(t *testing.T) {
			for _, policy := range []string{"default-home", "custom-udp", "custom-tcp", "tls", "https", "h3", "ipv6-off", "lan-off", "fixed-mtu", "entry-fixed", "virtual-jumbo"} {
				t.Run(policy, func(t *testing.T) {
					source := importedPacketXrayFixture(t, kind, "aes-256-gcm+xor-whitening", "aes-256-gcm")
					capture, profile := externalTestRead(t, source[1]), externalTestRead(t, source[4])
					entryProfile := capture["profile"].(map[string]any)
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
						entryProfile["ipv6_mode"] = "off"
						profile["ipv6_mode"] = "on"
					case "lan-off":
						entryProfile["home_lan_access"] = false
						profile["home_lan_access"] = true
					case "fixed-mtu":
						profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1392
					case "entry-fixed":
						entryProfile["mtu_policy"], entryProfile["manual_mtu"] = "fixed", 1360
					case "virtual-jumbo":
						profile["jumbo_tun"] = true
					}
					source[1], source[4] = externalTestJSON(t, capture), externalTestJSON(t, profile)
					plan := importedPacketXrayCompile(t, source)
					graph := externalTestRead(t, plan.Config())
					entry := externalTestFind(t, graph, "entry-wg")
					if policy == "entry-fixed" {
						if entry["mtu"] != float64(1360) || graph["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1280) {
							t.Fatal("entry Fixed MTU rewrote final virtual interface")
						}
					} else if entry["mtu"] != externalTestFind(t, externalTestRead(t, source[0]), ExternalFinalTag)["mtu"] {
						t.Fatal("final policy changed captured packet MTU")
					}
					if policy == "virtual-jumbo" {
						if graph["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(9000) {
							t.Fatal("proxy virtual capacity was discarded")
						}
					} else if policy != "tls" && policy != "https" && policy != "h3" && policy != "entry-fixed" {
						importedSOCKSXrayDevicePolicy(t, graph, policy)
					}
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					if policy != "ipv6-off" && !reflect.DeepEqual(graph["dns"], externalTestRead(t, node.Config())["dns"]) {
						t.Fatal("packet REALITY substituted selected final DNS")
					}
				})
			}
		})
	}
}

func TestImportedPacketRealityVisionOriginalFlowsAndBootstrap(t *testing.T) {
	for _, kind := range importedPacketXrayKinds {
		t.Run(kind, func(t *testing.T) {
			for _, flow := range []string{applexray.VisionFlow, applexray.VisionUDP443Flow} {
				t.Run(flow, func(t *testing.T) {
					for _, transport := range []string{"tls", "https", "h3"} {
						t.Run(transport, func(t *testing.T) {
							source := importedPacketXrayFixture(t, kind, "aes-256-gcm", "aes-256-gcm+xor-whitening")
							importedCONNECTXrayFlow(t, source, flow)
							profile := externalTestRead(t, source[4])
							profile["dns_mode"], profile["dns_protocol"] = "custom", transport
							profile["dns_host"], profile["dns_port"] = "resolver.example.net", 8853
							profile["dns_server_name"], profile["dns_path"] = "resolver.example.net", "/owned-dns-query"
							source[4] = externalTestJSON(t, profile)
							source[6] = externalTestJSON(t, map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "203.0.113.54", "server_port": 5354, "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "timeout": "3s", "disable_cache": true}})
							plan := importedPacketXrayCompile(t, source)
							node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
							if err != nil {
								t.Fatal(err)
							}
							graph, original := externalTestRead(t, plan.Config()), externalTestRead(t, node.Config())
							original["endpoints"] = []any{}
							if !reflect.DeepEqual(graph["dns"], original["dns"]) || externalTestFind(t, graph, LocalTag)["config_json"] != externalTestFind(t, original, "proxy")["config_json"] {
								t.Fatal("packet REALITY replaced original flow/DNS/bootstrap")
							}
							changed := append([]string(nil), source...)
							changed[6] = strings.Replace(changed[6], "203.0.113.54", "203.0.113.55", 1)
							if importedPacketXrayCompile(t, changed).SourceSHA256() == plan.SourceSHA256() {
								t.Fatal("bootstrap replaced original source identity")
							}
							for _, index := range []int{0, 1, 3, 4, 5} {
								if source[index] == "" {
									continue
								}
								changed := append([]string(nil), source...)
								changed[index] += "\n"
								next := importedPacketXrayCompile(t, changed)
								if next.Config() != plan.Config() || next.SourceSHA256() == plan.SourceSHA256() {
									t.Fatal("equivalent graph lost the original private source bytes")
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestImportedPacketRealityVisionRejectsUnownedSources(t *testing.T) {
	for _, kind := range importedPacketXrayKinds {
		t.Run(kind, func(t *testing.T) {
			for _, fault := range []string{"entry-source", "entry-system", "entry-missing-layer", "entry-foreign-layer", "entry-off-unused", "entry-invalid-layer", "entry-jumbo", "entry-invalid-fixed", "entry-private-authority", "final-missing-layer", "final-foreign-layer", "final-off-unused", "final-invalid-layer", "final-bypassed-layer", "final-unknown-flow", "final-invalid-fixed", "same-node", "server", "compare"} {
				t.Run(fault, func(t *testing.T) {
					source := importedPacketXrayFixture(t, kind, "aes-256-gcm+xor-whitening", "aes-256-gcm")
					_ = importedPacketXrayCompile(t, source)
					graph, capture, final := externalTestRead(t, source[0]), externalTestRead(t, source[1]), externalTestRead(t, source[4])
					entry := externalTestFind(t, graph, ExternalFinalTag)
					profile := capture["profile"].(map[string]any)
					external := profile["external"].(map[string]any)
					switch fault {
					case "entry-source":
						if strings.HasPrefix(kind, "openvpn-") {
							entry["password"] = "foreign original password"
						} else {
							entry["private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("Q", 32)))
						}
					case "entry-system":
						entry["system"] = true
					case "entry-missing-layer":
						delete(external, "start_layer")
					case "entry-foreign-layer":
						external["start_layer"].(map[string]any)["transport"].(map[string]any)["server"] = "203.0.113.99"
					case "entry-off-unused":
						profile["start_layer"] = "off"
					case "entry-invalid-layer":
						profile["start_layer"] = "unowned"
					case "entry-jumbo":
						profile["jumbo_tun"] = true
					case "entry-invalid-fixed":
						profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1279
					case "entry-private-authority":
						profile["node_proof_id"] = strings.Repeat("a", 64)
					case "final-missing-layer":
						source[5] = ""
					case "final-foreign-layer":
						var files map[string]string
						if json.Unmarshal([]byte(source[5]), &files) != nil {
							t.Fatal("invalid original final layer map")
						}
						raw, _ := base64.StdEncoding.DecodeString(files["sing-box.json"])
						wrapper := externalTestRead(t, string(raw))
						wrapper["outbounds"].([]any)[0].(map[string]any)["server"] = "203.0.113.99"
						files["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, wrapper)))
						source[5] = externalTestJSON(t, files)
					case "final-off-unused":
						final["start_layer"] = "off"
					case "final-invalid-layer":
						final["start_layer"] = "unowned"
					case "final-bypassed-layer":
						assets, xray, _ := importedSOCKSXrayRaw(t, source[3])
						xray["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["sockopt"] = map[string]any{"dialerProxy": "foreign"}
						assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, xray)))
						source[3] = externalTestJSON(t, assets)
					case "final-unknown-flow":
						importedCONNECTXrayFlow(t, source, "vision-foreign")
					case "final-invalid-fixed":
						final["mtu_policy"], final["manual_mtu"] = "fixed", 1279
					case "same-node":
						final["id"] = capture["exit_id"]
					case "server":
						final["multihop_execution"] = "server"
					case "compare":
						final["multihop_execution"] = "auto"
					}
					source[0], source[1], source[4] = externalTestJSON(t, graph), externalTestJSON(t, capture), externalTestJSON(t, final)
					if plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || plan != nil {
						t.Fatal("unowned packet REALITY source acquired native authority")
					}
				})
			}
		})
	}
}

func TestImportedPacketRealityVisionKeepsScope(t *testing.T) {
	for _, kind := range importedPacketXrayKinds {
		t.Run(kind, func(t *testing.T) {
			for _, mode := range []string{"reality-pq-vision", "reality-xhttp", "split", "max"} {
				t.Run(mode, func(t *testing.T) {
					source := importedPacketXrayFixture(t, kind, "off", "off")
					files, profile, start := nodeProfileFixture(t, mode, "")
					if _, err := NewNodeProfile(mode, files, externalTestJSON(t, profile), start, ""); err != nil {
						t.Fatal("scope control lacks a valid paired original", err)
					}
					if plan, err := NewImportedEntry(source[0], source[1], mode, files, externalTestJSON(t, profile), start, ""); err == nil || plan != nil {
						t.Fatal("packet REALITY admitted another final family")
					}
				})
			}
		})
	}
}
