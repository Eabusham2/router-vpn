package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func importedNaiveH2Compile(t *testing.T, source []string) *Controller {
	t.Helper()
	plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
	if err != nil {
		t.Fatal("captured imported Naive H2 source was rejected", err)
	}
	return plan
}

func importedNaiveH2Fixture(t *testing.T, kind, first, last string) []string {
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
	layer := last
	if layer == "off" {
		layer = ""
	}
	files, profile, start := nodeProfileFixture(t, "naive-h2", layer)
	graph := proxyEntryGraph("naive-h2")
	graph["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["certificate_path"] = "cert.pem"
	files = proxyEntryProfile(t, graph, entryCertificate(t))
	// This is an explicit captured Home TCP policy, not a rewrite by the
	// compiler. The separate policy matrix retains the default Home UDP case.
	profile["dns_protocol"] = "tcp"
	source[2], source[3], source[4], source[5], source[6] = "naive-h2", files, externalTestJSON(t, profile), start, ""
	return source
}

func TestImportedNaiveH2IndependentLayers(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, first := range importedPQLayers {
			for _, last := range importedPQLayers {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					source := importedNaiveH2Fixture(t, kind, first, last)
					captured := append([]string(nil), source...)
					plan := importedNaiveH2Compile(t, source)
					graph := importedPQGraph(t, plan.Config())
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					original := importedPQGraph(t, node.Config())
					final, before := externalTestFind(t, graph, LocalTag), externalTestFind(t, original, "proxy")
					copy := predecessorCopy(final)
					copy["tag"] = "proxy"
					if last == "off" {
						delete(copy, "detour")
						if final["detour"] != "entry-wg" {
							t.Fatal("Naive H2 bypassed its original imported entry")
						}
					} else {
						outer := externalTestFind(t, graph, NativeStartLayerTag)
						layer := predecessorCopy(outer)
						delete(layer, "detour")
						if final["detour"] != NativeStartLayerTag || outer["detour"] != "entry-wg" || !reflect.DeepEqual(layer, externalTestFind(t, original, NativeStartLayerTag)) {
							t.Fatal("Naive H2 changed or bypassed its independently captured final layer")
						}
					}
					if final["type"] != "naive" || final["quic"] != false || !reflect.DeepEqual(copy, before) {
						t.Fatal("Naive H2 lost original credentials, trust, stream transport or resolver binding")
					}
					dns, prior := graph["dns"].(map[string]any), original["dns"].(map[string]any)
					servers, old := dns["servers"].([]any), prior["servers"].([]any)
					if dns["final"] != ExternalDNSTag || len(servers) != 2 || len(old) != 2 || !reflect.DeepEqual(servers[0], old[0]) {
						t.Fatal("Naive H2 changed selected Home TCP DNS")
					}
					bootstrap := predecessorCopy(servers[1].(map[string]any))
					if last == "off" {
						if bootstrap["detour"] != "entry-wg" {
							t.Fatal("Naive H2 bootstrap escaped its captured imported entry")
						}
						delete(bootstrap, "detour")
					}
					if !reflect.DeepEqual(bootstrap, old[1]) {
						t.Fatal("Naive H2 changed the captured bootstrap policy or final-layer owner")
					}
					if strings.HasSuffix(kind, "-connect") && plan.meta.TransportCapability != "naive-h2-stream" {
						t.Fatal("Naive H2 borrowed another final's CONNECT authority")
					}
					profile := externalTestRead(t, source[4])
					if plan.meta.EntryKind != "external" || plan.meta.ExitMode != "naive-h2" || plan.meta.Execution != "local" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.EntryNodeID != "" || plan.meta.ExitNodeID != profile["node_proof_id"] || plan.meta.ExitAPI != profile["router_api"] || plan.meta.ExitToken != profile["api_token"] || plan.Healthy() || !reflect.DeepEqual(captured, source) {
						t.Fatal("Naive H2 changed independent identity/proof authority or original source")
					}
					capture, err := plan.ImportedDesktopCapture()
					if err != nil || !capture.UDPAvailable || capture.SelectedDNS.Type != "tcp" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" || len(capture.BootstrapDNS) != 1 {
						t.Fatal("Naive H2 lost its desktop policy/physical-source capture", err, capture)
					}
					if directory := os.Getenv("ROUTERVPN_IMPORTED_NAIVE_H2_FIXTURES"); directory != "" {
						receipt, _ := json.Marshal(append(captured, plan.SourceSHA256(), plan.Config()))
						if err := os.WriteFile(filepath.Join(directory, kind+"--naive-h2--"+first+"--"+last+".json"), receipt, 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestImportedNaiveH2PreservesSelectedDNSPolicy(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
			for _, layer := range importedPQLayers {
				t.Run(kind+"/"+protocol+"/"+layer, func(t *testing.T) {
					source := importedNaiveH2Fixture(t, kind, "aes-256-gcm", layer)
					profile := externalTestRead(t, source[4])
					profile["dns_protocol"] = protocol
					port := float64(5443)
					if protocol == "udp" {
						// Test the unchanged Home AdGuard default explicitly.
						delete(profile, "dns_protocol")
						port = 53
					} else {
						profile["dns_port"] = port
					}
					profile["dns_server_name"], profile["dns_path"] = "adguard.home.example", "/owned-query"
					source[4] = externalTestJSON(t, profile)
					original := append([]string(nil), source...)
					plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])

					if err != nil || !reflect.DeepEqual(source, original) {
						t.Fatal("Naive H2 failed or changed its compatible captured DNS policy", err)
					}
					graph := externalTestRead(t, plan.Config())
					servers := graph["dns"].(map[string]any)["servers"].([]any)
					selected, lower := servers[0].(map[string]any), servers[1].(map[string]any)
					if selected["type"] != protocol || selected["server"] != profile["adguard_ipv4"] || selected["server_port"] != port || selected["detour"] != "proxy" {
						t.Fatal("Naive H2 substituted selected Home resolver or transport")
					}
					for key, value := range selected {
						if key != "tag" && key != "detour" && !reflect.DeepEqual(lower[key], value) {
							t.Fatal("Naive H2 changed a retained bootstrap policy field", key)
						}
					}
					capture, err := plan.ImportedDesktopCapture()
					if err != nil || !capture.UDPAvailable || capture.SelectedDNS.Physical || capture.SelectedDNS.Type != protocol || len(capture.BootstrapDNS) != 1 || capture.BootstrapDNS[0].Physical {
						t.Fatal("Naive H2 lost selected versus lower DNS ownership", err)
					}
				})
			}
		}
	}
}

func importedNaiveH2HostnameDNS(t *testing.T, source []string, bootstrapProtocol string) {
	t.Helper()
	profile := externalTestRead(t, source[4])
	profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "doh", "https", "resolver.example.net"
	profile["dns_port"], profile["dns_server_name"], profile["dns_path"] = float64(8443), "resolver.example.net", "/owned-query"
	source[4] = externalTestJSON(t, profile)
	source[6] = externalTestJSON(t, map[string]any{
		"server": map[string]any{"type": bootstrapProtocol, "tag": "external-dns-bootstrap", "server": "203.0.113.54", "server_port": float64(5354), "detour": "proxy"},
		"query":  map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "timeout": "3s", "disable_cache": true, "disable_optimistic_cache": true, "rewrite_ttl": float64(42), "client_subnet": "192.0.2.0/24"},
	})
}

func TestImportedNaiveH2RetainsCompleteHostnameBootstrap(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, protocol := range []string{"tcp", "udp"} {
			for _, layer := range []string{"off", "aes-256-gcm+xor-whitening"} {
				t.Run(kind+"/"+protocol+"/"+layer, func(t *testing.T) {
					source := importedNaiveH2Fixture(t, kind, "off", layer)
					importedNaiveH2HostnameDNS(t, source, protocol)
					captured := append([]string(nil), source...)
					plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])

					if err != nil || !reflect.DeepEqual(captured, source) {
						t.Fatal("original hostname DNS capture changed or failed", err)
					}
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					graph, original := externalTestRead(t, plan.Config()), externalTestRead(t, node.Config())
					servers := graph["dns"].(map[string]any)["servers"].([]any)
					before := original["dns"].(map[string]any)["servers"].([]any)
					if len(servers) != 4 || len(before) != 4 {
						t.Fatal("Naive H2 lost its complete separate bootstrap tree")
					}
					for index, raw := range servers {
						server := predecessorCopy(raw.(map[string]any))
						if index >= 2 && layer == "off" {
							if server["detour"] != "entry-wg" {
								t.Fatal("Naive bootstrap escaped through a physical/default route")
							}
							delete(server, "detour")
						}
						if !reflect.DeepEqual(server, before[index]) {
							t.Fatal("Naive H2 changed captured resolver transport, TLS, path or query policy")
						}
					}
					capture, err := plan.ImportedDesktopCapture()
					if err != nil || len(capture.BootstrapDNS) != 3 || capture.SelectedDNS.Detour != "proxy" {
						t.Fatal("desktop H2 capture omitted a resolver dependency", err, capture.BootstrapDNS)
					}
					for _, resolver := range capture.BootstrapDNS {
						if resolver.Physical {
							t.Fatal("H2 resolver acquired a physical bypass")
						}
					}
				})
			}
		}
	}
}

func TestImportedNaiveH2RejectsForeignTransportAuthority(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, fault := range []string{"h3-label", "h3-transport", "missing-uot", "disabled-uot", "uot-v1", "missing-user", "missing-password", "insecure-tls", "missing-sni", "bad-certificate", "missing-certificate", "foreign-dialer", "hostname-endpoint", "ss-authority", "missing-final-layer", "foreign-final-layer", "missing-entry-layer", "missing-pairing", "server", "compare"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				source := importedNaiveH2Fixture(t, kind, "aes-256-gcm", "aes-256-gcm+xor-whitening")
				assets := map[string]string{}
				if json.Unmarshal([]byte(source[3]), &assets) != nil {
					t.Fatal("invalid original Naive asset map")
				}
				raw, err := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, string(raw))
				final := graph["outbounds"].([]any)[0].(map[string]any)
				profile, entry := externalTestRead(t, source[4]), externalTestRead(t, source[1])
				switch fault {
				case "h3-label":
					source[2] = "naive-h3"
				case "h3-transport":
					final["quic"] = true
				case "missing-uot":
					delete(final, "udp_over_tcp")
				case "disabled-uot":
					final["udp_over_tcp"].(map[string]any)["enabled"] = false
				case "uot-v1":
					final["udp_over_tcp"].(map[string]any)["version"] = float64(1)
				case "missing-user":
					delete(final, "username")
				case "missing-password":
					delete(final, "password")
				case "insecure-tls":
					final["tls"].(map[string]any)["insecure"] = true
				case "missing-sni":
					delete(final["tls"].(map[string]any), "server_name")
				case "bad-certificate":
					final["tls"].(map[string]any)["certificate"] = []any{"not a captured certificate"}
				case "missing-certificate":
					delete(assets, "cert.pem")
				case "foreign-dialer":
					final["detour"] = "foreign-owner"
				case "hostname-endpoint":
					final["server"] = "unowned.example.test"
				case "ss-authority":
					assets["routervpn-ss-service.json"] = base64.StdEncoding.EncodeToString([]byte("{}"))
				case "missing-final-layer":
					source[5] = ""
				case "foreign-final-layer":
					final["server"] = "192.0.2.99"
				case "missing-entry-layer":
					delete(entry["profile"].(map[string]any)["external"].(map[string]any), "start_layer")
				case "missing-pairing":
					delete(profile, "node_proof_id")
				case "server":
					profile["multihop_execution"] = "server"
				case "compare":
					profile["multihop_execution"] = "auto"
				}
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, graph)))
				source[1], source[3], source[4] = externalTestJSON(t, entry), externalTestJSON(t, assets), externalTestJSON(t, profile)
				if plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || plan != nil {
					t.Fatal("imported Naive H2 admitted foreign or incomplete authority")
				}
			})
		}
	}
}

func TestImportedNaiveH2PreservesExplicitSystemTrust(t *testing.T) {
	source := importedNaiveH2Fixture(t, "https-connect", "off", "off")
	assets := map[string]string{}
	if json.Unmarshal([]byte(source[3]), &assets) != nil {
		t.Fatal("invalid original Naive asset map")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
	if err != nil {
		t.Fatal(err)
	}
	graph := externalTestRead(t, string(raw))
	tls := graph["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
	delete(tls, "certificate_path")
	delete(assets, "cert.pem")
	raw, err = json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	assets["sing-box.json"] = base64.StdEncoding.EncodeToString(raw)
	source[3] = externalTestJSON(t, assets)
	original := append([]string(nil), source...)
	plan := importedNaiveH2Compile(t, source)
	final := externalTestFind(t, importedPQGraph(t, plan.Config()), LocalTag)
	if !reflect.DeepEqual(final["tls"], tls) || !reflect.DeepEqual(source, original) {
		t.Fatal("H2 silently replaced explicit system trust or disabled its original TLS verification")
	}
}
