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
)

// The entry is the original standalone transport; the final remains the
// independently paired Xray source. No SOCKS conversion or synthetic pairing.
func importedProxyXrayFixture(t *testing.T, kind, first, last string) []string {
	t.Helper()
	if first == "off" {
		first = ""
	}
	if last == "off" {
		last = ""
	}
	source := importedSOCKSXrayFixture(t, "", last)
	switch kind {
	case "shadowsocks":
		source[0], source[1], _, _ = importedEntryFixture(t, first, "")
	case "hysteria2":
		source[0], source[1], _, _ = importedHysteriaFixture(t, first, "")
	default:
		t.Fatal("unknown original imported proxy")
	}
	return source
}

func importedProxyXrayCompile(t *testing.T, source []string) *Controller {
	t.Helper()
	plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
	if err != nil {
		t.Fatal("captured imported proxy REALITY graph was rejected", err)
	}
	return plan
}

func TestImportedProxyRealityVisionIndependentLayers(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			for _, a := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, b := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(a+"/"+b, func(t *testing.T) {
						source := importedProxyXrayFixture(t, kind, a, b)
						plan := importedProxyXrayCompile(t, source)
						original := externalTestRead(t, source[0])
						original["endpoints"] = []any{}
						capture := externalTestRead(t, source[1])
						selected := capture["profile"].(map[string]any)
						graph := externalTestRead(t, plan.Config())
						graph["endpoints"] = []any{}
						first, final := externalTestFind(t, graph, "entry-wg"), externalTestFind(t, graph, LocalTag)
						originalFirst := externalTestFind(t, original, ExternalFinalTag)
						copied := predecessorCopy(first)
						copied["tag"] = ExternalFinalTag
						delete(copied, "detour")
						if a != "off" {
							copied["server"] = originalFirst["server"]
							copied["server_port"] = originalFirst["server_port"]
						}
						if !reflect.DeepEqual(copied, originalFirst) || first["type"] != kind {
							t.Fatal("imported REALITY changed original transport credentials or TLS")
						}
						if a == "off" {
							if first["detour"] != nil {
								t.Fatal("Off entry acquired a foreign wrapper")
							}
						} else {
							outer := externalTestFind(t, graph, first["detour"].(string))
							provision := selected["external"].(map[string]any)["start_layer"].(map[string]any)
							transport := provision["transport"].(map[string]any)
							expected := predecessorCopy(transport)
							expected["tag"] = outer["tag"]
							if a == "aes-256-gcm+xor-whitening" {
								expected["type"] = "routervpn-aes-xor"
								expected["server_port"] = float64(8389)
							}
							if !reflect.DeepEqual(outer, expected) || provision["api"] != "http://10.93.0.1:8787" || first["server"] != "10.93.0.1" || first["server_port"] != originalFirst["server_port"] {
								t.Fatal("imported REALITY changed captured entry layer or inner address")
							}
						}
						node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
						if err != nil {
							t.Fatal(err)
						}
						nodeGraph := externalTestRead(t, node.Config())
						nodeGraph["endpoints"] = []any{}
						nodeFinal := externalTestFind(t, nodeGraph, "proxy")
						if len(final) != 5 || final["type"] != "routervpn-xray" || final["mode"] != "reality-vision" || final["config_json"] != nodeFinal["config_json"] {
							t.Fatal("imported REALITY replaced original paired final")
						}
						if b == "off" {
							if final["detour"] != "entry-wg" {
								t.Fatal("Off final lost captured entry owner")
							}
						} else {
							if final["detour"] != applexray.StartLayerTag {
								t.Fatal("imported REALITY bypassed final authenticated wrapper")
							}
							outer := externalTestFind(t, graph, applexray.StartLayerTag)
							expected := externalTestFind(t, nodeGraph, applexray.StartLayerTag)
							copied := predecessorCopy(outer)
							delete(copied, "detour")
							if outer["detour"] != "entry-wg" || !reflect.DeepEqual(copied, expected) {
								t.Fatal("imported REALITY borrowed final layer or physical owner")
							}
							if a != "off" {
								entryOuter := externalTestFind(t, graph, first["detour"].(string))
								if outer["password"] == entryOuter["password"] || outer["server"] == entryOuter["server"] || outer["tag"] == entryOuter["tag"] {
									t.Fatal("independent layers collapsed into one node")
								}
							}
						}
						if !reflect.DeepEqual(graph["dns"], nodeGraph["dns"]) || plan.meta.EntryMode != kind || plan.meta.ExitMode != "reality-vision" || plan.meta.EntryKind != "external" || plan.meta.EntryNodeID != "" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.Execution != "local" || plan.Healthy() {
							t.Fatal("imported REALITY changed DNS, Local policy or distinct proof authority")
						}
						importedSOCKSXrayDevicePolicy(t, graph, "default-home")
						expectedInputs, _ := json.Marshal(append([]string{"routervpn-imported-entry-v1"}, source...))
						if plan.SourceSHA256() != externalDigest(expectedInputs) {
							t.Fatal("imported REALITY did not retain all seven exact original inputs")
						}
						for _, index := range []int{0, 1, 3, 4, 5} {
							if source[index] != "" {
								changed := append([]string(nil), source...)
								changed[index] += "\n"
								next := importedProxyXrayCompile(t, changed)
								if next.Config() != plan.Config() || next.SourceSHA256() == plan.SourceSHA256() {
									t.Fatal("equivalent source bytes replaced captured authority")
								}
							}
						}
						if _, err := New(plan.Config(), plan.Metadata()); err == nil {
							t.Fatal("metadata manufactured imported REALITY authority")
						}
						if dir := os.Getenv("ROUTERVPN_IMPORTED_PROXY_XRAY_FIXTURES"); dir != "" {
							receipt := append(append([]string(nil), source...), plan.SourceSHA256(), plan.Config())
							if err := os.WriteFile(filepath.Join(dir, kind+"--reality-vision--"+a+"--"+b+".json"), []byte(externalTestJSON(t, receipt)), 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		})
	}
}

func TestImportedProxyRealityVisionSelectedPolicy(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			for _, policy := range []string{"default-home", "custom-udp", "custom-tcp", "tls", "https", "h3", "ipv6-off", "lan-off", "fixed-mtu"} {
				t.Run(policy, func(t *testing.T) {
					source := importedProxyXrayFixture(t, kind, "aes-256-gcm+xor-whitening", "aes-256-gcm")
					profile := externalTestRead(t, source[4])
					switch policy {
					case "custom-udp", "custom-tcp":
						profile["dns_mode"], profile["dns_protocol"] = "custom", strings.TrimPrefix(policy, "custom-")
						profile["dns_host"], profile["dns_port"] = "203.0.113.53", 5353
					case "tls", "https", "h3":
						profile["dns_mode"], profile["dns_protocol"] = "custom", policy
						profile["dns_host"] = "203.0.113.53"
						profile["dns_server_name"] = "resolver.example.net"
						if policy == "tls" {
							profile["dns_port"] = 853
						} else {
							profile["dns_port"] = 443
							profile["dns_path"] = "/dns-query"
						}
					case "ipv6-off":
						profile["ipv6_mode"] = "off"
					case "lan-off":
						profile["home_lan_access"] = false
					case "fixed-mtu":
						profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1392
					}
					source[4] = externalTestJSON(t, profile)
					plan := importedProxyXrayCompile(t, source)
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					graph, nodeGraph := externalTestRead(t, plan.Config()), externalTestRead(t, node.Config())
					if !reflect.DeepEqual(graph["dns"], nodeGraph["dns"]) {
						t.Fatal("imported REALITY substituted selected DNS")
					}
					if policy == "tls" || policy == "https" || policy == "h3" {
						dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
						if dns["type"] != policy || dns["server"] != "203.0.113.53" || dns["detour"] != "proxy" {
							t.Fatal("imported REALITY changed selected encrypted DNS transport")
						}
					} else {
						importedSOCKSXrayDevicePolicy(t, graph, policy)
					}
				})
			}
		})
	}
}

func TestImportedProxyRealityVisionRejectsChangedAuthority(t *testing.T) {
	faults := []string{"entry-password", "entry-endpoint", "entry-foreign-protocol", "entry-invalid-transport", "entry-layer-missing", "entry-layer-mode", "entry-layer-foreign", "entry-layer-unused", "entry-route", "entry-paired-proof", "entry-paired-api", "same-node", "final-not-paired", "final-missing-proof", "final-missing-token", "final-missing-xray", "final-wrapper", "final-plaintext", "final-layer-missing", "final-layer-foreign", "final-layer-unused", "server", "compare", "foreign-bootstrap"}
	for _, kind := range []string{"shadowsocks", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {
					source := importedProxyXrayFixture(t, kind, "aes-256-gcm+xor-whitening", "aes-256-gcm")
					_ = importedProxyXrayCompile(t, source)
					graph, capture, profile := externalTestRead(t, source[0]), externalTestRead(t, source[1]), externalTestRead(t, source[4])
					graph["endpoints"] = []any{}
					first := externalTestFind(t, graph, ExternalFinalTag)
					entry := capture["profile"].(map[string]any)
					external := entry["external"].(map[string]any)
					assets, xray, _ := importedSOCKSXrayRaw(t, source[3])
					switch fault {
					case "entry-password":
						first["password"] = "wrong-original-secret"
					case "entry-endpoint":
						first["server"] = "203.0.113.99"
					case "entry-foreign-protocol":
						capture["protocol"] = "socks5"
					case "entry-invalid-transport":
						if kind == "shadowsocks" {
							first["method"] = "aes-256-gcm"
							external["shadowsocks"].(map[string]any)["method"] = "aes-256-gcm"
						} else {
							first["tls"].(map[string]any)["insecure"] = true
							external["hysteria2"].(map[string]any)["tls_insecure"] = true
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
						first["detour"] = "foreign"
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
						body, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
						wrapper := externalTestRead(t, string(body))
						wrapper["outbounds"].([]any)[0].(map[string]any)["server_port"] = 2090
						assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, wrapper)))
					case "final-plaintext":
						xray["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["security"] = "none"
						assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, xray)))
					case "final-layer-missing":
						source[5] = ""
					case "final-layer-foreign":
						layer := map[string]string{}
						if json.Unmarshal([]byte(source[5]), &layer) != nil {
							t.Fatal("invalid original final layer")
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
					if _, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil {
						t.Fatal("changed imported REALITY authority was accepted")
					}
				})
			}
		})
	}
}

func TestImportedProxyRealityVisionEncryptedDNSBootstrap(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			for _, protocol := range []string{"tls", "https", "h3"} {
				t.Run(protocol, func(t *testing.T) {
					source := importedProxyXrayFixture(t, kind, "aes-256-gcm", "aes-256-gcm+xor-whitening")
					profile := externalTestRead(t, source[4])
					profile["dns_mode"] = map[string]string{"tls": "dot", "https": "doh", "h3": "doh3"}[protocol]
					profile["dns_protocol"] = protocol
					profile["dns_host"], profile["dns_port"] = "resolver.example.net", 8853
					profile["dns_server_name"], profile["dns_path"] = "resolver.example.net", "/owned-dns-query"
					source[4] = externalTestJSON(t, profile)
					source[6] = externalTestJSON(t, map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "203.0.113.54", "server_port": 5354, "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "timeout": "3s", "disable_cache": true}})
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					plan := importedProxyXrayCompile(t, source)
					if !reflect.DeepEqual(externalTestRead(t, plan.Config())["dns"], externalTestRead(t, node.Config())["dns"]) {
						t.Fatal("imported REALITY changed encrypted DNS or its captured bootstrap")
					}
					source[6] = strings.Replace(source[6], `"detour":"proxy"`, `"detour":"direct"`, 1)
					if _, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil {
						t.Fatal("imported REALITY accepted bootstrap outside selected final")
					}
				})
			}
		})
	}
}

func TestImportedProxyRealityVisionSS2022Methods(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			source := importedProxyXrayFixture(t, "shadowsocks", "aes-256-gcm+xor-whitening", "aes-256-gcm")
			graph, capture := externalTestRead(t, source[0]), externalTestRead(t, source[1])
			graph["endpoints"] = []any{}
			first := externalTestFind(t, graph, ExternalFinalTag)
			raw := capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", size)))
			first["method"], first["password"], raw["method"], raw["password"] = method, key, method, key
			source[0], source[1] = externalTestJSON(t, graph), externalTestJSON(t, capture)
			plan := importedProxyXrayCompile(t, source)
			compiled := externalTestRead(t, plan.Config())
			compiled["endpoints"] = []any{}
			entry := externalTestFind(t, compiled, "entry-wg")
			if entry["method"] != method || entry["password"] != key {
				t.Fatal("imported REALITY replaced selected SS2022 cipher or key")
			}

			candidates := []struct {
				name, value string
				valid       bool
			}{
				{"malformed", "invalid-key", false}, {"empty", "", false},
				{"short", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", size-1))), false},
				{"long", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", size+1))), false},
				{"identity-chain", key + ":" + key, method != "2022-blake3-chacha20-poly1305"},
				{"empty-identity", key + ":", false},
			}
			for _, candidate := range candidates {
				t.Run(candidate.name, func(t *testing.T) {
					first["password"], raw["password"] = candidate.value, candidate.value
					source[0], source[1] = externalTestJSON(t, graph), externalTestJSON(t, capture)
					next, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
					if candidate.valid {
						if err != nil {
							t.Fatal("valid SS2022 original identity chain was rejected", err)
						}
						compiled := externalTestRead(t, next.Config())
						compiled["endpoints"] = []any{}
						if externalTestFind(t, compiled, "entry-wg")["password"] != candidate.value {
							t.Fatal("SS2022 identity chain was normalized or reordered")
						}
					} else if err == nil {
						t.Fatal("imported REALITY accepted malformed selected cipher key")
					}
				})
			}

		})
	}
}

func TestImportedProxyRealityVisionKeepsScope(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			for _, mode := range []string{"reality-pq-vision", "reality-xhttp", "split", "max"} {
				t.Run(mode, func(t *testing.T) {
					source := importedProxyXrayFixture(t, kind, "off", "off")
					files, profile, start := nodeProfileFixture(t, mode, "")
					if _, err := NewNodeProfile(mode, files, externalTestJSON(t, profile), start, ""); err != nil {
						t.Fatal("scope control did not begin with valid original paired node", err)
					}
					if _, err := NewImportedEntry(source[0], source[1], mode, files, externalTestJSON(t, profile), start, ""); err == nil {
						t.Fatal("imported REALITY admitted another final graph family")
					}
				})
			}
		})
	}
}
