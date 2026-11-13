package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func nodeChainHostnameFixture(t *testing.T, mode, method string) NodeChainSource {
	t.Helper()
	source := nodeChainImportedFixture(t, mode, "")
	var input nodeChainImportedInput
	if err := json.Unmarshal([]byte(source.Nodes[1]), &input); err != nil {
		t.Fatal(err)
	}
	graph, capture := externalTestRead(t, input.Config), externalTestRead(t, input.Capture)
	profile := capture["profile"].(map[string]any)
	out := externalTestFind(t, graph, ExternalFinalTag)
	ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("h", size)))
	out["server"], out["method"], out["password"] = "middle.example.test", method, key
	ss["server"], ss["method"], ss["password"] = out["server"], method, key
	profile["endpoint"], profile["dns_mode"], profile["dns_protocol"] = "middle.example.test", "custom", "tcp"
	profile["dns_host"], profile["dns_port"] = "10.81.0.53", float64(5353)
	profile["kill_switch_policy"], profile["home_lan_access"], profile["ipv6_mode"] = "always", false, "off"
	input.Config, input.Capture = startJSON(t, graph), startJSON(t, capture)
	var err error
	source.Nodes[1], err = NodeChainImportedMemberInput(input.Config, input.Capture)
	if err != nil {
		t.Fatal("exact hostname middle source rejected", err)
	}
	return source
}

func TestNodeChainImportedHostnamePreservesSourceAndPrefixDNS(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
			t.Run(mode+"/"+method, func(t *testing.T) {
				source := nodeChainHostnameFixture(t, mode, method)
				before := startJSON(t, source)
				chain, err := NewNodeChain(before)
				if err != nil {
					t.Fatal(err)
				}
				if startJSON(t, source) != before || chain.importedMiddle.input != source.Nodes[1] || chain.importedMiddle.policy != nil || chain.Progress().Ready {
					t.Fatal("hostname source acquired standalone or ready authority")
				}
				for _, target := range []string{"", "android", "ios", "linux", "darwin", "windows"} {
					t.Run("target="+target, func(t *testing.T) {
						derived := chain
						if target != "" {
							derived, err = ProjectNodeChain(chain, target, 1280)
							if err != nil {
								t.Fatal(err)
							}
						}
						graph := externalTestRead(t, derived.Config())
						middle := externalTestFind(t, graph, derived.proofs[1].Tag)
						if middle["server"] != "middle.example.test" || middle["method"] != method || middle["detour"] != derived.proofs[0].Tag {
							t.Fatal("original middle transport changed", middle)
						}
						query := middle["domain_resolver"].(map[string]any)
						if len(query) != 2 || query["strategy"] != "ipv4_only" {
							t.Fatal("exact lookup options changed", query)
						}
						count := 0
						for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
							dns := raw.(map[string]any)
							if dns["tag"] == query["server"] {
								count++
								if len(dns) != 5 || dns["type"] != "tcp" || dns["server"] != "10.81.0.53" || dns["server_port"] != float64(5353) || dns["detour"] != derived.proofs[0].Tag {
									t.Fatal("transport DNS escaped its original prefix", dns)
								}
							}
							if dns["tag"] == derived.DNSCapture().ResolverTag && (dns["server"] != "10.82.0.53" || dns["detour"] != derived.FinalTag() || dns["type"] != "udp") {
								t.Fatal("final Home AdGuard changed", dns)
							}
						}
						if count != 1 {
							t.Fatal("transport DNS missing/duplicated")
						}
						launch, err := derived.LaunchInput()
						if err != nil {
							t.Fatal(err)
						}
						reopened, err := ParseNodeChainLaunchInput(launch)
						if err != nil || reopened.Config() != derived.Config() || reopened.Metadata() != derived.Metadata() {
							t.Fatal("exact source replay failed", err)
						}
						firstPhysical, err := chain.nodes[0].PhysicalEgress()
						if err != nil || !nodeChainSamePhysical(derived.physical, firstPhysical) {
							t.Fatal("hostname or resolver became a physical grant", derived.physical)
						}
					})
				}
			})
		}
	}
}

func TestNodeChainImportedHostnamePreservesMixedCase(t *testing.T) {
	source := nodeChainHostnameFixture(t, "wg", NativeStartLayerMethod)
	var input nodeChainImportedInput
	_ = json.Unmarshal([]byte(source.Nodes[1]), &input)
	graph, capture := externalTestRead(t, input.Config), externalTestRead(t, input.Capture)
	profile := capture["profile"].(map[string]any)
	out := externalTestFind(t, graph, ExternalFinalTag)
	ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
	const original = "Middle.EXAMPLE.test"
	out["server"], ss["server"], profile["endpoint"] = original, original, original
	input.Config, input.Capture = startJSON(t, graph), startJSON(t, capture)
	var err error
	source.Nodes[1], err = NodeChainImportedMemberInput(input.Config, input.Capture)
	if err != nil {
		t.Fatal("original mixed-case hostname rejected", err)
	}
	var retained nodeChainImportedInput
	_ = json.Unmarshal([]byte(source.Nodes[1]), &retained)
	if retained.Config != input.Config || retained.Capture != input.Capture {
		t.Fatal("original source was normalized")
	}
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	if externalTestFind(t, externalTestRead(t, chain.Config()), chain.proofs[1].Tag)["server"] != original {
		t.Fatal("compiled hostname changed original spelling")
	}
	launch, err := chain.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := ParseNodeChainLaunchInput(launch)
	if err != nil || reopened.Config() != chain.Config() || reopened.importedMiddle.input != source.Nodes[1] {
		t.Fatal("mixed-case source replay changed", err)
	}
	profile["endpoint"] = strings.ToLower(original)
	if _, err := NodeChainImportedMemberInput(input.Config, startJSON(t, capture)); err == nil {
		t.Fatal("case-only source mismatch accepted")
	}
}

func TestNodeChainImportedHostnameRejectsUnownedSource(t *testing.T) {
	source := nodeChainHostnameFixture(t, "wg", NativeStartLayerMethod)
	faults := []string{"home", "rescue", "fastest", "udp", "tls", "resolver-hostname", "resolver-loopback", "resolver-mapped", "resolver-port", "resolver-default-port", "resolver-path", "resolver-tls", "resolver-bootstrap", "profile-bootstrap", "unknown-capture", "wrong-endpoint", "wrong-external-server", "wrong-key", "source-plugin", "legacy-cipher", "identity-chain", "wrong-proof", "borrowed-api", "layer", "external-layer", "physical-detour", "unowned-resolver", "foreign-source-dns", "extra-outbound", "extra-endpoint", "extra-service", "extra-inbound", "reordered-inbounds", "extra-route", "unknown-root", "unknown-tun", "wrong-address", "wrong-stack", "log-file", "nonboolean-lan", "bad-ipv6", "bad-kill", "bad-mtu", "server-execution", "localhost", "trailing-dot"}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			var input nodeChainImportedInput
			_ = json.Unmarshal([]byte(source.Nodes[1]), &input)
			graph, capture := externalTestRead(t, input.Config), externalTestRead(t, input.Capture)
			profile := capture["profile"].(map[string]any)
			out := externalTestFind(t, graph, ExternalFinalTag)
			ext := profile["external"].(map[string]any)
			ss := ext["shadowsocks"].(map[string]any)
			switch fault {
			case "home", "rescue", "fastest":
				profile["dns_mode"] = fault
			case "udp", "tls":
				profile["dns_protocol"] = fault
			case "resolver-hostname":
				profile["dns_host"] = "resolver.example.test"
			case "resolver-loopback":
				profile["dns_host"] = "127.0.0.1"
			case "resolver-mapped":
				profile["dns_host"] = "::ffff:192.0.2.1"
			case "resolver-port":
				profile["dns_port"] = float64(3.5)
			case "resolver-default-port":
				delete(profile, "dns_port")
			case "resolver-path":
				profile["dns_path"] = "/dns-query"
			case "resolver-tls":
				profile["dns_server_name"] = "resolver.example.test"
			case "resolver-bootstrap":
				capture["dns_bootstrap"] = map[string]any{"server": map[string]any{}, "query": map[string]any{}}
			case "profile-bootstrap":
				profile["dns_bootstrap"] = map[string]any{"server": "system"}
			case "unknown-capture":
				capture["system_dns"] = true
			case "wrong-endpoint":
				profile["endpoint"] = "other.example.test"
			case "wrong-external-server":
				ss["server"] = "other.example.test"
			case "wrong-key":
				out["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
			case "source-plugin":
				ss["plugin"] = "unowned-transport"
			case "legacy-cipher":
				out["method"], ss["method"] = "aes-256-gcm", "aes-256-gcm"
			case "identity-chain":
				out["password"] = out["password"].(string) + ":" + out["password"].(string)
				ss["password"] = out["password"]
			case "wrong-proof":
				capture["expected_public_ip"] = "203.0.113.99"
			case "borrowed-api":
				profile["router_api"] = "http://10.0.0.1:8787"
			case "layer":
				profile["start_layer"] = "aes-256-gcm"
			case "external-layer":
				ext["start_layer"] = map[string]any{"mode": "aes-256-gcm"}
			case "physical-detour":
				out["detour"] = "direct"
			case "unowned-resolver":
				out["domain_resolver"] = map[string]any{"server": "system"}
			case "foreign-source-dns":
				graph["dns"] = map[string]any{"servers": []any{}, "final": "foreign"}
			case "extra-outbound":
				graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": "escape"})
			case "extra-endpoint":
				graph["endpoints"] = []any{map[string]any{"type": "wireguard"}}
			case "extra-service":
				graph["services"] = []any{map[string]any{"type": "tor"}}
			case "extra-inbound":
				graph["inbounds"].([]any)[1].(map[string]any)["listen"] = "0.0.0.0"
			case "reordered-inbounds":
				ins := graph["inbounds"].([]any)
				ins[0], ins[1] = ins[1], ins[0]
			case "extra-route":
				graph["route"].(map[string]any)["default_domain_resolver"] = "system"
			case "unknown-root":
				graph["experimental"] = map[string]any{}
			case "unknown-tun":
				graph["inbounds"].([]any)[0].(map[string]any)["exclude_interface"] = []any{"eth0"}
			case "wrong-address":
				graph["inbounds"].([]any)[0].(map[string]any)["address"] = []any{"192.0.2.1/24", "fd29::1/126"}
			case "wrong-stack":
				graph["inbounds"].([]any)[0].(map[string]any)["stack"] = "foreign"
			case "log-file":
				graph["log"].(map[string]any)["output"] = "/foreign/file"
			case "nonboolean-lan":
				profile["home_lan_access"] = float64(1)
			case "bad-ipv6":
				profile["ipv6_mode"] = "disabled"
			case "bad-kill":
				profile["kill_switch_policy"] = "sometimes"
			case "bad-mtu":
				profile["mtu_policy"] = "fixed"
				profile["fixed_mtu"] = float64(0)
			case "server-execution":
				capture["execution"] = map[string]any{"selection": "server"}
			case "localhost", "trailing-dot":
				host := map[string]string{"localhost": "localhost", "trailing-dot": "middle.example.test."}[fault]
				out["server"], ss["server"], profile["endpoint"] = host, host, host
			}
			if _, err := NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture)); err == nil {
				t.Fatal("uncaptured hostname source accepted", fault)
			}
		})
	}
}

func TestNodeChainImportedHostnameCapturesExactOptionalDNSAndIPv6(t *testing.T) {
	for _, ipv6 := range []string{"on", "off"} {
		for _, address := range []string{"10.81.0.53", "fd81::53"} {
			t.Run(ipv6+"/"+address, func(t *testing.T) {
				source := nodeChainHostnameFixture(t, "wg", NativeStartLayerMethod)
				var input nodeChainImportedInput
				_ = json.Unmarshal([]byte(source.Nodes[1]), &input)
				var selected externalPolicyCapture
				_ = json.Unmarshal([]byte(input.Capture), &selected)
				selected.Profile["ipv6_mode"], selected.Profile["dns_host"] = ipv6, address
				input.Capture = startJSON(t, selected)
				without, err := NodeChainImportedMemberInput(input.Config, input.Capture)
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, input.Config)
				dns, _, err := externalSelectedDNS(selected, ipv6, true)
				if err != nil {
					t.Fatal(err)
				}
				graph["dns"] = dns
				input.Config = startJSON(t, graph)
				with, err := NodeChainImportedMemberInput(input.Config, input.Capture)
				if err != nil {
					t.Fatal("matching original DNS refused", err)
				}
				before, _ := parseNodeChainImportedMember(without)
				after, _ := parseNodeChainImportedMember(with)
				if before.source == after.source || before.hostname.Config != after.hostname.Config || after.input != with {
					t.Fatal("optional DNS lost original bytes or changed executable policy")
				}
				source.Nodes[1] = with
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				compiled := externalTestRead(t, chain.Config())
				middle := externalTestFind(t, compiled, chain.proofs[1].Tag)
				query := middle["domain_resolver"].(map[string]any)
				if ipv6 == "on" && len(query) != 1 || ipv6 == "off" && query["strategy"] != "ipv4_only" {
					t.Fatal("lookup strategy changed saved IPv6 policy", query)
				}
				dns["servers"].([]any)[0].(map[string]any)["server_port"] = float64(53)
				if _, err := NodeChainImportedMemberInput(startJSON(t, graph), input.Capture); err == nil {
					t.Fatal("source DNS port differed from saved selection")
				}
			})
		}
	}
}

func TestNodeChainImportedHostnameKeepsDeviceAndNoStandaloneAuthority(t *testing.T) {
	source := nodeChainHostnameFixture(t, "wg", NativeStartLayerMethod)
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	var input nodeChainImportedInput
	_ = json.Unmarshal([]byte(source.Nodes[1]), &input)
	if _, err := NewExternalPolicy(input.Config, input.Capture); err == nil {
		t.Fatal("hostname acquired ordinary physical-root policy")
	}
	for _, target := range []string{"linux", "darwin", "windows"} {
		t.Run(target, func(t *testing.T) {
			policy, err := NewDesktopNodeChainPolicy(chain, desktopNodeTestSession, target, 1280)
			if err != nil {
				t.Fatal(err)
			}
			_, meta, physical, err := policy.ReadValidated()
			if err != nil {
				t.Fatal(err)
			}
			if meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess {
				t.Fatal("hostname discarded its original device restrictions", meta)
			}
			for _, root := range physical.PhysicalRoots {
				if !strings.HasPrefix(root.Tag, "routervpn-chain-0-") {
					t.Fatal("hostname middle acquired physical authority", root)
				}
			}
			found := false
			for _, dns := range physical.BootstrapDNS {
				if dns.Host == "10.81.0.53" {
					found = true
					if dns.Physical || dns.Type != "tcp" || dns.Port != 5353 || dns.Detour != policy.NodeChain().proofs[0].Tag {
						t.Fatal("lookup policy lost its prefix owner", dns)
					}
				}
			}
			if !found {
				t.Fatal("desktop omitted executable hostname dependency")
			}
		})
	}
	for _, fault := range []string{"hostname", "resolver", "kill", "lan", "ipv6", "compiled", "device"} {
		t.Run("stale-"+fault, func(t *testing.T) {
			fresh, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "hostname":
				fresh.importedMiddle.selection.Profile["endpoint"] = "other.example.test"
			case "resolver":
				fresh.importedMiddle.selection.Profile["dns_host"] = "10.99.0.53"
			case "kill":
				fresh.importedMiddle.selection.Profile["kill_switch_policy"] = "off"
			case "lan":
				fresh.importedMiddle.selection.Profile["home_lan_access"] = true
			case "ipv6":
				fresh.importedMiddle.selection.Profile["ipv6_mode"] = "on"
			case "compiled":
				fresh.importedMiddle.hostname.Config = strings.Replace(fresh.importedMiddle.hostname.Config, "middle.example.test", "other.example.test", 1)
			case "device":
				fresh.importedMiddle.hostname.Device.KillSwitchPolicy = "off"
			}
			if _, err := fresh.importedMiddle.devicePolicy(); err == nil {
				t.Fatal("mutated source acquired device restrictions")
			}
			if _, err := NewDesktopNodeChainPolicy(fresh, desktopNodeTestSession, "windows", 1280); err == nil {
				t.Fatal("mutated source acquired physical owner")
			}
		})
	}
	// Adding unrelated standalone defaults to the saved profile changes the
	// captured source without changing the final application's selected policy.
	again, err := NewNodeChain(startJSON(t, source))
	if err != nil || !reflect.DeepEqual(chain.physical, again.physical) {
		t.Fatal("source is not deterministic", err)
	}
}

func TestNodeChainImportedHostnameSavedControlDoesNotEnterPrefixPreparation(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, target := range []string{"linux", "darwin", "windows"} {
			t.Run(mode+"/"+target, func(t *testing.T) {
				source := nodeChainHostnameFixture(t, mode, NativeStartLayerMethod)
				candidate, _ := candidateSourceFixture(t, "external", NativeStartLayerMethod)
				inventory := candidateInventoryFixture(t, "hostname-saved-control", candidate)
				preparation, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
				if err != nil {
					t.Fatal(err)
				}
				policy, err := NewDesktopNodeCandidatePreparationPolicy(preparation, desktopNodeTestSession, target, 0)
				if err != nil {
					t.Fatal(err)
				}
				config, meta, capture, err := ReadDesktopPhysicalPolicy(policy)
				if err != nil {
					t.Fatal(err)
				}
				if meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess ||
					policy.Metadata().PolicyProfileID != preparation.original.proofs[2].ProfileID ||
					strings.Contains(config, "middle.example.test") || strings.Contains(config, "10.81.0.53") ||
					strings.Contains(config, nodeChainImportedResolver) || len(capture.PhysicalRoots) != 1 {
					t.Fatal("saved hostname suffix lost restrictions or acquired preparation authority")
				}
				graph := externalTestRead(t, config)
				if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
					t.Fatal("prefix opened application ingress")
				}
				if _, err := NewNodeChainCandidatePreparation(startJSON(t, source), 1, inventory); err == nil {
					t.Fatal("hostname SS middle acquired packet candidate timing")
				}
				preparation.original.importedMiddle.selection.Profile["dns_host"] = "10.99.0.53"
				if policy.Validate() == nil {
					t.Fatal("changed saved resolver retained preparation authority")
				}
			})
		}
	}
}
