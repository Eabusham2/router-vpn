package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestImportedNaiveH2CONNECTLiteralHomeUDP(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		for _, first := range importedPQLayers {
			for _, last := range importedPQLayers {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					source := importedNaiveH2Fixture(t, kind, first, last)
					profile := externalTestRead(t, source[4])
					delete(profile, "dns_protocol")
					profile["kill_switch_policy"] = "on-connect"
					source[4] = externalTestJSON(t, profile)
					original := append([]string(nil), source...)
					plan := importedNaiveH2Compile(t, source)
					defer plan.Close()
					node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
					if err != nil {
						t.Fatal(err)
					}
					graph, prior := importedPQGraph(t, plan.Config()), importedPQGraph(t, node.Config())
					rows, previous := graph["dns"].(map[string]any)["servers"].([]any), prior["dns"].(map[string]any)["servers"].([]any)
					if len(rows) != 2 || len(previous) != 2 || !reflect.DeepEqual(rows[0], previous[0]) {
						t.Fatal("literal H2 changed selected DNS closure")
					}
					selected := rows[0].(map[string]any)
					if selected["type"] != "udp" || selected["server"] != profile["adguard_ipv4"] || selected["server_port"] != float64(53) || selected["detour"] != "proxy" {
						t.Fatal("default Home UDP lost final ownership", selected)
					}
					lower := predecessorCopy(rows[1].(map[string]any))
					if last == "off" {
						if lower["detour"] != "entry-wg" {
							t.Fatal("bootstrap gained another lower owner")
						}
						delete(lower, "detour")
					} else if lower["detour"] != NativeStartLayerTag {
						t.Fatal("bootstrap lost its exact captured final layer")
					}
					if !reflect.DeepEqual(lower, previous[1]) {
						t.Fatal("literal H2 replaced or removed its original bootstrap")
					}
					final := predecessorCopy(externalTestFind(t, graph, LocalTag))
					final["tag"] = "proxy"
					if last == "off" {
						delete(final, "detour")
					}
					if !reflect.DeepEqual(final, externalTestFind(t, prior, "proxy")) || !reflect.DeepEqual(source, original) || plan.Healthy() {
						t.Fatal("literal admission changed source, credentials, TLS or invented proof")
					}
					capture, err := plan.ImportedDesktopCapture()
					if err != nil || !capture.UDPAvailable || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Physical || len(capture.BootstrapDNS) != 1 {
						t.Fatal("literal H2 lost captured final and bootstrap ownership", err)
					}
					if len(capture.PhysicalRoots) != 1 || capture.BootstrapDNS[0].Physical {
						t.Fatal("dormant resolver gained physical socket authority")
					}
					for _, destination := range capture.PhysicalRoots[0].Destinations {
						if destination.Network != "tcp" {
							t.Fatal("CONNECT gained lower UDP authority", destination)
						}
					}
					policy, err := NewDesktopImportedPolicy(plan, desktopNodeTestSession, "windows")
					if err != nil {
						t.Fatal("captured Home DNS graph lost protected policy", err)
					}
					assertDesktopImportedExactDerivation(t, policy)
					faults := []string{"hostname", "wrong-resolver", "missing-resolver", "foreign-lower"}
					if last != "off" {
						faults = append(faults, "layer-hostname", "layer-missing-peer", "layer-mapped-peer", "layer-duplicate")
					}
					for _, fault := range faults {
						t.Run(fault, func(t *testing.T) {
							changed := predecessorCopy(prior)
							f := externalTestFind(t, changed, "proxy")
							switch fault {
							case "hostname":
								f["server"] = "foreign.invalid"
							case "wrong-resolver":
								f["domain_resolver"] = map[string]any{"server": "foreign"}
							case "missing-resolver":
								delete(f, "domain_resolver")
							case "foreign-lower":
								changed["dns"].(map[string]any)["servers"].([]any)[1].(map[string]any)["detour"] = "direct"
							case "layer-hostname":
								externalTestFind(t, changed, NativeStartLayerTag)["server"] = "start-layer.example"
							case "layer-missing-peer":
								delete(externalTestFind(t, changed, NativeStartLayerTag), "server")
							case "layer-mapped-peer":
								externalTestFind(t, changed, NativeStartLayerTag)["server"] = "::ffff:192.0.2.44"
							case "layer-duplicate":
								changed["outbounds"] = append(changed["outbounds"].([]any), predecessorCopy(externalTestFind(t, changed, NativeStartLayerTag)))
							}
							if err := importedNaiveH2DNS(changed, f, false); err == nil {
								t.Fatal("literal exception admitted changed original owner", fault)
							}
						})
					}
					plan.config = strings.Replace(plan.config, "routervpn-predecessor-bootstrap-0", "foreign-bootstrap", 1)
					if _, err := plan.ImportedDesktopCapture(); err == nil {
						t.Fatal("mutated retained graph kept source authority")
					}
				})
			}
		}
	}
}

func TestImportedNaiveH2CONNECTHomeUDPRequiresLiteralLayerPeer(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(kind+"/"+layer, func(t *testing.T) {
				source := importedNaiveH2Fixture(t, kind, "off", layer)
				assets := map[string]string{}
				if err := json.Unmarshal([]byte(source[5]), &assets); err != nil {
					t.Fatal(err)
				}
				raw, err := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, string(raw))
				graph["outbounds"].([]any)[0].(map[string]any)["server"] = "start-layer.example"
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, graph)))
				source[5] = externalTestJSON(t, assets)
				// The independently captured SS proxy already requires a literal
				// peer, even with TCP DNS. Preserve that source boundary as well
				// as the graph-level dormant-resolver checks above.
				for _, protocol := range []string{"tcp", "udp"} {
					profile := externalTestRead(t, source[4])
					profile["dns_mode"], profile["dns_protocol"] = "custom", protocol
					source[4] = externalTestJSON(t, profile)
					original := append([]string(nil), source...)
					if plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || plan != nil || !strings.Contains(err.Error(), "literal unicast server") || !reflect.DeepEqual(source, original) {
						t.Fatal("literal inner Naive bypassed its original outer peer boundary", protocol, err)
					}
				}
			})
		}
	}
}

func TestImportedNaiveH2CONNECTDormantCompleteResolverTree(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		for _, layer := range importedPQLayers {
			for _, protocol := range []string{"https", "h3"} {
				for _, bootstrap := range []string{"udp", "tcp"} {
					t.Run(kind+"/"+layer+"/"+protocol+"/"+bootstrap, func(t *testing.T) {
						source := importedNaiveH2Fixture(t, kind, "off", layer)
						importedNaiveH2HostnameDNS(t, source, bootstrap)
						profile := externalTestRead(t, source[4])
						profile["dns_mode"], profile["dns_protocol"] = "custom", protocol
						source[4] = externalTestJSON(t, profile)
						captured := append([]string(nil), source...)
						plan := importedNaiveH2Compile(t, source)
						defer plan.Close()
						capture, err := plan.ImportedDesktopCapture()
						if err != nil || capture.SelectedDNS.Type != protocol || capture.SelectedDNS.Host != "resolver.example.net" || capture.SelectedDNS.Port != 8443 || capture.SelectedDNS.Path != "/owned-query" || capture.SelectedDNS.ServerName != "resolver.example.net" || len(capture.BootstrapDNS) != 3 {
							t.Fatal("selected hostname policy lost exact captured fields or complete lower tree", err, capture)
						}
						if !reflect.DeepEqual(captured, source) || plan.Healthy() {
							t.Fatal("DNS admission changed source or invented native proof")
						}
						for _, resolver := range capture.BootstrapDNS {
							if resolver.Physical {
								t.Fatal("dormant lower resolver acquired physical authority", resolver)
							}
						}
						if len(capture.PhysicalRoots) != 1 {
							t.Fatal("DNS extension added a physical owner", capture.PhysicalRoots)
						}
						for _, destination := range capture.PhysicalRoots[0].Destinations {
							if destination.Network != "tcp" {
								t.Fatal("final UoT granted lower CONNECT UDP", destination)
							}
						}
						node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
						if err != nil {
							t.Fatal(err)
						}
						original := importedPQGraph(t, node.Config())
						for _, fault := range []string{"missing-bootstrap", "foreign-bootstrap", "cycle", "changed-port", "changed-transport", "changed-tls", "lower-bypass"} {
							graph := predecessorCopy(original)
							rows := graph["dns"].(map[string]any)["servers"].([]any)
							lower := rows[3].(map[string]any)
							boot := rows[2].(map[string]any)
							switch fault {
							case "missing-bootstrap":
								graph["dns"].(map[string]any)["servers"] = append(rows[:2], rows[3])
							case "foreign-bootstrap":
								lower["domain_resolver"].(map[string]any)["server"] = "foreign"
							case "cycle":
								boot["domain_resolver"] = map[string]any{"server": "routervpn-predecessor-bootstrap-0"}
							case "changed-port":
								boot["server_port"] = float64(53)
							case "changed-transport":
								boot["type"] = "https"
							case "changed-tls":
								lower["tls"].(map[string]any)["server_name"] = "foreign.invalid"
							case "lower-bypass":
								lower["detour"] = "direct"
							}
							if err := importedNaiveH2DNS(graph, externalTestFind(t, graph, "proxy"), false); err == nil {
								t.Fatal("dormant resolver exception accepted a changed original tree", fault)
							}
						}
					})
				}
			}
		}
	}
}
