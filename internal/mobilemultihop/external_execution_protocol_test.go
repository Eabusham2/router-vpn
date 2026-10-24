package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

var externalExecutionProtocols = []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"}

func externalExecutionProtocolFixture(t *testing.T, protocol, selection, layer string) (string, string) {
	t.Helper()
	graph, capture := externalTestFixture(t, protocol, "router-wg")
	profile := capture["profile"].(map[string]any)
	profile["multihop_enabled"], profile["multihop_entry_id"], profile["multihop_exit_id"], profile["multihop_exit_mode"], profile["multihop_execution"] = true, "saved-entry", "saved-exit", protocol, selection
	ext := profile["external"].(map[string]any)
	ext["response_probe"] = map[string]any{"url": "https://203.0.113.20/node-response", "server_name": "example.com"}
	if layer != "" {
		profile["start_layer"] = layer
		ext["start_layer"] = map[string]any{"mode": layer, "api": "http://10.93.0.1:8787", "transport": map[string]any{
			"type": "shadowsocks", "tag": "captured-exit-start", "server": "203.0.113.20", "server_port": 8388,
			"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("l", 32))),
		}}
	}
	return externalTestJSON(t, graph), externalTestJSON(t, capture)
}

func TestExternalExecutionProtocolsKeepExactCandidatesPoliciesAndRestoredChoice(t *testing.T) {
	for _, protocol := range externalExecutionProtocols {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, execution := range []string{"local", "server", "auto"} {
				for _, restored := range []string{"", "local", "server"} {
					if restored != "" && execution != "auto" && restored != execution {
						continue // Explicit-selection rejection is exercised separately.
					}
					t.Run(strings.Join([]string{protocol, layer, execution, restored}, "/"), func(t *testing.T) {
						source, captured := externalExecutionProtocolFixture(t, protocol, execution, layer)
						prepared, err := PrepareExternalExecutionCapture(source, captured, restored)
						if err != nil {
							t.Fatal(err)
						}
						policy, err := NewExternalPolicy(source, prepared)
						if err != nil {
							t.Fatal(err)
						}
						graph, original := externalTestRead(t, policy.Config()), externalTestRead(t, source)
						ownedTag := LocalTag
						if execution == "local" && restored == "" {
							ownedTag = ExternalFinalTag
						}
						local := externalTestFind(t, graph, ownedTag)
						expected := predecessorCopy(externalTestFind(t, original, ExternalFinalTag))
						expected["tag"] = ownedTag
						if layer != "" {
							expected["server"], expected["detour"] = "10.93.0.1", multihoprelay.ExitStartLayerTag
							outer := externalTestFind(t, graph, multihoprelay.ExitStartLayerTag)
							if outer["server"] != "203.0.113.20" || outer["detour"] != "entry-wg" || outer["method"] != "2022-blake3-aes-256-gcm" || (outer["type"] == "routervpn-aes-xor") != (layer == "aes-256-gcm+xor-whitening") {
								t.Fatal("external wrapper replaced its captured server, entry or encryption")
							}
						}
						if !reflect.DeepEqual(local, expected) {
							t.Fatal("native candidate changed saved transport, TLS identity or credentials", local["type"])
						}
						if !reflect.DeepEqual(externalTestFind(t, graph, "entry-wg"), externalTestFind(t, original, "entry-wg")) {
							t.Fatal("execution changed the captured entry")
						}
						meta := externalTestRead(t, policy.Metadata())
						if meta["protocol"] != protocol || layer != "" && meta["start_layer"] != layer || meta["config_sha256"] != externalDigest([]byte(policy.Config())) || meta["configured_mtu"] != float64(1280) {
							t.Fatal("execution lost exact source, selected encryption or configured MTU")
						}
						if meta["dns_mode"] != "rescue" || meta["dns_protocol"] != "https" || meta["dns_detour"] != ExternalFinalTag || meta["public_exit_proof"] != "required" || meta["entry_proof"] != "required" {
							t.Fatal("execution changed DNS or manufactured traffic proof")
						}
						if ownedTag == ExternalFinalTag {
							return
						}
						plan := policy.capture.Execution
						if plan.Request.ExitMode != protocol || plan.Request.ExitStartLayer != layer || policy.capture.Profile["multihop_execution"] != execution {
							t.Fatal("lease changed saved transport, layer or execution")
						}
						want := execution
						if restored != "" {
							want = restored
						}
						if plan.Selection != want {
							t.Fatal("restoration reran Compare instead of retaining its proved choice")
						}
						server := externalTestFind(t, graph, ServerTag)
						if server["type"] != "socks" || server["detour"] != "entry-wg" || server["server"] != "10.77.0.1" || server["password"] != plan.Request.Password {
							t.Fatal("server candidate lost its authenticated entry-owned listener")
						}
					})
				}
			}
		}
	}
}

func TestExternalExecutionProtocolCaptureRejectsCredentialTLSLayerAndPolicySubstitution(t *testing.T) {
	for _, protocol := range externalExecutionProtocols {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			source, capture := externalExecutionProtocolFixture(t, protocol, "auto", layer)
			prepared, err := PrepareExternalExecutionCapture(source, capture, "")
			if err != nil {
				t.Fatal(err)
			}
			changes := map[string]func(map[string]any){
				"password": func(c map[string]any) {
					c["profile"].(map[string]any)["external"].(map[string]any)[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)["password"] = "replacement-secret"
				},
				"protocol": func(c map[string]any) { c["protocol"] = "wireguard" },
				"last-node TLS": func(c map[string]any) {
					c["profile"].(map[string]any)["external"].(map[string]any)["response_probe"].(map[string]any)["server_name"] = "different.example"
				},
				"listener": func(c map[string]any) {
					c["execution"].(map[string]any)["request"].(map[string]any)["listener_username"] = strings.Repeat("f", 48)
				},
			}
			if protocol == "hysteria2" || protocol == "https-connect" {
				changes["transport TLS"] = func(c map[string]any) {
					c["profile"].(map[string]any)["external"].(map[string]any)[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)["tls_server_name"] = "different.example"
				}
			}
			if protocol == "socks5" || strings.HasSuffix(protocol, "-connect") {
				changes["username"] = func(c map[string]any) {
					c["profile"].(map[string]any)["external"].(map[string]any)[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)["username"] = "different-user"
				}
			}
			if layer != "" {
				changes["layer password"] = func(c map[string]any) {
					c["profile"].(map[string]any)["external"].(map[string]any)["start_layer"].(map[string]any)["transport"].(map[string]any)["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
				}
				changes["omitted layer"] = func(c map[string]any) {
					delete(c["profile"].(map[string]any)["external"].(map[string]any), "start_layer")
				}
			}
			for name, change := range changes {
				t.Run(protocol+"/"+layer+"/"+name, func(t *testing.T) {
					selected := externalTestRead(t, prepared)
					change(selected)
					if _, err := NewExternalPolicy(source, externalTestJSON(t, selected)); err == nil {
						t.Fatal("changed capture acquired the previous lease authority")
					}
				})
			}
		}
	}
}

func TestExternalExecutionNewProtocolsKeepLiveScoreAndRestorationLifecycle(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public-a", "http://1.0.0.1/public-b"}
	defer func() { Targets = previous }()
	for _, protocol := range externalExecutionProtocols {
		for _, restored := range []string{"", "local", "server"} {
			t.Run(protocol+"/"+restored, func(t *testing.T) {
				source, captured := externalExecutionProtocolFixture(t, protocol, "auto", "aes-256-gcm+xor-whitening")
				r, engine := externalExecutionCapturedRequest(t, source, captured, restored)
				if _, err := r.Run(); err != nil {
					t.Fatal(err)
				}
				want := restored
				if want == "" {
					want = "server"
				}
				if !r.Healthy() || r.Execution() != want || len(engine.errors) != 0 {
					t.Fatal("native selection lost its proved execution", r.ProgressJSON(), engine.errors)
				}
				var progress Progress
				if json.Unmarshal([]byte(r.ProgressJSON()), &progress) != nil {
					t.Fatal("comparison progress invalid")
				}
				for _, measurement := range progress.Measurements {
					if !measurement.Eligible || measurement.ScoreMS == nil || *measurement.ScoreMS != measurement.LastNodeMS/2+measurement.ExternalMS/2 {
						t.Fatal("candidate lost exact two-probe average")
					}
				}
				if restored == "" {
					if len(progress.Measurements) != 2 || engine.nodeCalls[ServerTag] < 2 || engine.probeTargets[LocalTag][1] != engine.probeTargets[ServerTag][1] || engine.probeTargets[ServerTag][1] != engine.probeTargets[ServerTag][3] {
						t.Fatal("comparison failed to repeat both probes through the same chosen endpoint")
					}
				} else if len(engine.nodeCalls) != 1 {
					t.Fatal("restoration trialed the other candidate")
				}
				if err := r.Close(); err != nil || r.Healthy() || r.Execution() != "" {
					t.Fatal("closed selection retained authority", err)
				}
				for _, process := range engine.runner.processes {
					if process.Alive() {
						t.Fatal("retired selection leaked its isolated relay")
					}
				}
			})
		}
	}
}

func TestExternalExecutionDoesNotBorrowPacketPeerIdentitiesOrAnonymousCredentials(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			graph, selected := externalTestFixture(t, "wireguard", "router-wg")
			externalTestFind(t, graph, "entry-wg")["mtu"] = float64(1500)
			if protocol == "amneziawg" {
				externalAmneziaReplace(t, graph, selected, false, "fast")
			} else if protocol == "openvpn" {
				externalOpenVPNReplace(t, graph, selected, false, "tcp")
			}
			source := externalTestJSON(t, graph)
			if _, err := NewExternalPolicy(source, externalTestJSON(t, selected)); err != nil {
				t.Fatal("negative control did not begin with a valid native Local path", err)
			}
			profile := selected["profile"].(map[string]any)
			profile["multihop_enabled"], profile["multihop_entry_id"], profile["multihop_exit_id"], profile["multihop_exit_mode"], profile["multihop_execution"] = true, "saved-entry", "saved-exit", protocol, "auto"
			profile["external"].(map[string]any)["response_probe"] = map[string]any{"url": "https://203.0.113.20/node-response", "server_name": "example.com"}
			if _, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, selected), ""); err == nil {
				t.Fatal("one packet identity was silently reused by local and server candidates")
			}
		})
	}
	for _, protocol := range []string{"socks5", "http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			source, capture := externalExecutionProtocolFixture(t, protocol, "local", "")
			graph, selected := externalTestRead(t, source), externalTestRead(t, capture)
			out := externalTestFind(t, graph, ExternalFinalTag)
			profile := selected["profile"].(map[string]any)
			block := profile["external"].(map[string]any)[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)
			for _, key := range []string{"username", "password"} {
				delete(out, key)
				delete(block, key)
			}
			source = externalTestJSON(t, graph)
			if _, err := NewExternalPolicy(source, externalTestJSON(t, selected)); err != nil {
				t.Fatal("valid Local-only anonymous proxy regressed", err)
			}
			profile["multihop_execution"] = "server"
			if _, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, selected), ""); err == nil {
				t.Fatal("anonymous proxy acquired authenticated server lease authority")
			}
		})
	}
}

func TestExternalExecutionProtocolSelectorRetainsDNSLANIPv6AndFixedMTU(t *testing.T) {
	for _, protocol := range externalExecutionProtocols {
		t.Run(protocol, func(t *testing.T) {
			source, capture := externalExecutionProtocolFixture(t, protocol, "auto", "aes-256-gcm")
			selected := externalTestRead(t, capture)
			profile := selected["profile"].(map[string]any)
			profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", "tcp", "9.9.9.9", float64(5353)
			profile["ipv6_mode"], profile["home_lan_access"], profile["mtu_policy"], profile["manual_mtu"] = "off", false, "fixed", float64(1360)
			prepared, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, selected), "")
			if err != nil {
				t.Fatal(err)
			}
			policy, err := NewExternalPolicy(source, prepared)
			if err != nil {
				t.Fatal(err)
			}
			graph := externalTestRead(t, policy.Config())
			dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if dns["type"] != "tcp" || dns["server"] != "9.9.9.9" || dns["server_port"] != float64(5353) || dns["detour"] != ExternalFinalTag {
				t.Fatal("selector changed the chosen resolver or its routed transport")
			}
			tun := graph["inbounds"].([]any)[0].(map[string]any)
			if tun["mtu"] != float64(1360) {
				t.Fatal("selector/layer silently replaced the requested fixed MTU")
			}
			meta := externalTestRead(t, policy.Metadata())
			if meta["ipv6_mode"] != "off" || meta["home_lan_access"] != false || meta["mtu_policy"] != "fixed" || meta["configured_mtu"] != float64(1360) {
				t.Fatal("selected device policy lost its captured identity")
			}
			rules := graph["route"].(map[string]any)["rules"].([]any)
			if len(rules) != 4 || rules[0].(map[string]any)["ip_version"] != float64(6) || rules[0].(map[string]any)["action"] != "reject" || rules[3].(map[string]any)["action"] != "reject" {
				t.Fatal("execution selector bypassed the actual TUN restrictions")
			}
		})
	}
}
