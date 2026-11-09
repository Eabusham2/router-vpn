package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestImportedNaiveH3EntryCipherKeys(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("n", size)))
		for _, layer := range importedPQLayers {
			for _, candidate := range []struct {
				name, value string
				valid       bool
			}{
				{"original", key, true}, {"malformed", "invalid-key", false}, {"empty", "", false},
				{"short", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("n", size-1))), false},
				{"long", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("n", size+1))), false},
				{"identity-chain", key + ":" + key, method != "2022-blake3-chacha20-poly1305"},
				{"empty-identity", key + ":", false},
			} {
				t.Run(method+"/"+layer+"/"+candidate.name, func(t *testing.T) {
					source := importedNaiveH3Fixture(t, "shadowsocks", layer, "aes-256-gcm+xor-whitening")
					graph, capture := externalTestRead(t, source[0]), externalTestRead(t, source[1])
					transport := externalTestFind(t, graph, ExternalFinalTag)
					profile := capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
					transport["method"], profile["method"] = method, method
					transport["password"], profile["password"] = candidate.value, candidate.value
					source[0], source[1] = externalTestJSON(t, graph), externalTestJSON(t, capture)
					plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
					if !candidate.valid {
						if err == nil || plan != nil {
							t.Fatal("imported Naive H3 accepted malformed selected SS2022 cipher key")
						}
						return
					}
					if err != nil {
						t.Fatal("valid original SS2022 identity was rejected", err)
					}
					entry := externalTestFind(t, importedPQGraph(t, plan.Config()), "entry-wg")
					if entry["method"] != method || entry["password"] != candidate.value {
						t.Fatal("H3 changed its original entry cipher or identity chain")
					}
				})
			}
		}
	}
}

// Attack the actual compiled dependency closure at the composition boundary.
// A valid final has two independent resolver trees; no layer may introduce a
// different endpoint, physical bypass, cycle or silently discarded query field.
func TestImportedNaiveH3RejectsChangedBootstrapClosure(t *testing.T) {
	for _, layer := range []string{"off", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"application-detour", "bootstrap-detour", "bootstrap-endpoint", "bootstrap-port", "bootstrap-server-name", "bootstrap-path", "bootstrap-query-option", "bootstrap-cycle", "bootstrap-duplicate", "bootstrap-extra", "bootstrap-removed", "final-resolver-server", "final-resolver-strategy", "physical-bootstrap", "unknown-bootstrap-key"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				source := importedNaiveH3Fixture(t, "socks5", "aes-256-gcm", layer)
				importedNaiveH2HostnameDNS(t, source, "tcp")
				original, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
				if err != nil {
					t.Fatal(err)
				}
				graph := importedPQGraph(t, original.Config())
				final := externalTestFind(t, graph, "proxy")
				if err := importedNaiveH3DNS(graph, final); err != nil {
					t.Fatal("unchanged captured Naive dependency closure was rejected", err)
				}
				dns := graph["dns"].(map[string]any)
				servers := dns["servers"].([]any)
				var application, lower, bootstrap map[string]any
				for _, raw := range servers {
					server := raw.(map[string]any)
					switch server["tag"] {
					case ExternalDNSTag:
						application = server
					case "routervpn-predecessor-bootstrap-0":
						lower = server
					case "routervpn-predecessor-bootstrap-1":
						bootstrap = server
					}
				}
				if application == nil || lower == nil || bootstrap == nil {
					t.Fatal("fixture omitted its original DNS dependency tree")
				}
				switch fault {
				case "application-detour":
					application["detour"] = "direct"
				case "bootstrap-detour":
					lower["detour"] = "foreign-entry"
				case "bootstrap-endpoint":
					bootstrap["server"] = "192.0.2.155"
				case "bootstrap-port":
					bootstrap["server_port"] = float64(53)
				case "bootstrap-server-name":
					lower["tls"].(map[string]any)["server_name"] = "foreign.example.test"
				case "bootstrap-path":
					lower["path"] = "/different-query"
				case "bootstrap-query-option":
					delete(lower["domain_resolver"].(map[string]any), "disable_cache")
				case "bootstrap-cycle":
					lower["domain_resolver"].(map[string]any)["server"] = lower["tag"]
				case "bootstrap-duplicate":
					bootstrap["tag"] = lower["tag"]
				case "bootstrap-extra":
					dns["servers"] = append(servers, predecessorCopy(bootstrap))
				case "bootstrap-removed":
					dns["servers"] = servers[:3]
				case "final-resolver-server":
					final["domain_resolver"].(map[string]any)["server"] = ExternalDNSTag
				case "final-resolver-strategy":
					final["domain_resolver"].(map[string]any)["strategy"] = "ipv6_only"
				case "physical-bootstrap":
					bootstrap["detour"] = "direct"
				case "unknown-bootstrap-key":
					bootstrap["fallback"] = "system"
				}
				if err := importedNaiveH3DNS(graph, final); err == nil {
					t.Fatal("changed bootstrap authority was accepted", fault)
				}
			})
		}
	}
}

func TestImportedNaiveH3RetainsSealedOriginalLaunch(t *testing.T) {
	for _, kind := range importedNaiveH3Kinds {
		for _, first := range importedPQLayers {
			for _, last := range importedPQLayers {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					source := importedNaiveH3Fixture(t, kind, first, last)
					original := importedNaiveH3Compile(t, source)
					checkImportedLaunchRoundTrip(t, original, source)
					protected := desktopImportedOriginal(t, source, "always")
					policy := desktopImportedPlan(t, protected, desktopNodeTestSession, 1392)
					assertDesktopImportedExactDerivation(t, policy)
					_, meta, capture, err := policy.ReadValidated()
					if err != nil || meta.ExitMode != "naive-h3" || meta.RestoredMTU != 1392 || meta.KillSwitchPolicy != "always" || meta.SOCKSUDPAssociationRequired != (kind == "socks5" && first == "off") || capture.SelectedDNS.Physical {
						t.Fatal("sealed H3 derivation changed final transport, protection, restored MTU or physical scope", err)
					}
				})
			}
		}
	}
}

func TestImportedNaiveH3RefusesStreamOnlyEntries(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		for _, first := range importedPQLayers {
			for _, last := range importedPQLayers {
				for _, claim := range []string{"original", "naive-h2-stream", "uot-v2", "vless-stream"} {
					t.Run(kind+"/"+first+"/"+last+"/"+claim, func(t *testing.T) {
						source := importedNaiveH3Fixture(t, kind, first, last)
						if claim != "original" {
							capture := externalTestRead(t, source[1])
							capture["transport_capability"] = claim
							source[1] = externalTestJSON(t, capture)
						}
						captured := append([]string(nil), source...)
						plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
						if err == nil || plan != nil || !reflect.DeepEqual(source, captured) {
							t.Fatal("H3 borrowed a stream final's capability or rewrote its original source", err)
						}
					})
				}
				// The inner H2 UoT declaration does not turn an H3 final into H2: the
				// capability derivation itself must reject this actual compiled graph.
				t.Run(kind+"/"+first+"/"+last+"/derivation", func(t *testing.T) {
					source := importedNaiveH3Fixture(t, kind, first, last)
					profile := externalTestRead(t, source[4])
					profile["dns_protocol"] = "tcp"
					source[4] = externalTestJSON(t, profile)
					// Even an explicitly compatible TCP resolver does not grant
					// the lower UDP transport required by the actual H3 final.
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					graph := importedPQGraph(t, node.Config())
					final := externalTestFind(t, graph, "proxy")
					if capability, err := importedCONNECTCapture(graph, final, first, "naive-h3", externalTestRead(t, source[4]), source[3]); err == nil || capability != "" {
						t.Fatal("H3 derived a CONNECT datagram carrier", err, capability)
					}
					if err := importedNaiveDNS(graph, final, "naive-h3", false); err == nil {
						t.Fatal("H3 closure accepted a lower without datagram authority")
					}
				})
			}
		}
	}
}

// These are source/ownership checks, not successful native IPv6 or TLS peer
// verdicts. The actual Cronet H3 resolver/probe boundary has a separate gate.
func TestImportedNaiveH3RetainsCapturedLiteralAndTLS(t *testing.T) {
	for _, kind := range importedNaiveH3Kinds {
		for _, layer := range importedPQLayers {
			t.Run(kind+"/"+layer, func(t *testing.T) {
				source := importedNaiveH3Fixture(t, kind, layer, layer)
				change := func(files string) string {
					var assets map[string]string
					if json.Unmarshal([]byte(files), &assets) != nil {
						t.Fatal("missing captured asset map")
					}
					raw, err := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
					if err != nil {
						t.Fatal(err)
					}
					graph := externalTestRead(t, string(raw))
					graph["outbounds"].([]any)[0].(map[string]any)["server"] = "2001:db8::44"
					assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, graph)))
					return externalTestJSON(t, assets)
				}
				source[3] = change(source[3])
				if layer != "off" {
					source[5] = change(source[5])
				}
				profile := externalTestRead(t, source[4])
				profile["endpoint"] = "2001:db8::44"
				source[4] = externalTestJSON(t, profile)
				before := append([]string(nil), source...)
				plan := importedNaiveH3Compile(t, source)
				graph := importedPQGraph(t, plan.Config())
				final := externalTestFind(t, graph, LocalTag)
				endpoint := "2001:db8::44"
				if layer != "off" {
					endpoint = "127.0.0.1"
				}
				tls := final["tls"].(map[string]any)
				if final["server"] != endpoint || final["quic"] != true || tls["server_name"] != "entry.example" || !reflect.DeepEqual(before, source) {
					t.Fatal("H3 rewrote the literal endpoint, original SNI or source")
				}
				capture, err := plan.ImportedDesktopCapture()
				if err != nil {
					t.Fatal(err)
				}
				for _, root := range capture.PhysicalRoots {
					for _, destination := range root.Destinations {
						if destination.Host == "2001:4860:4860::8888" {
							t.Fatal("source admission invented Chromium reachability-probe authority")
						}
					}
				}
			})
		}
	}
}
