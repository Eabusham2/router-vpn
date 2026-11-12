package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nodeChainExecutionProjectionFixture(t *testing.T) (*NodeChainExecutionPreparation, *NodeChainExecutionPolicy, *NodeChainExecutionProjection) {
	t.Helper()
	source := nodeChainExecutionFixtureSource(t, 4, "aes-256-gcm+xor-whitening", "auto")
	prep, err := NewNodeChainExecutionPreparation(source.LocalSource, source.Execution)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := prep.BindExecution(policy)
	if err != nil {
		t.Fatal(err)
	}
	return prep, policy, projection
}

func TestNodeChainExecutionPreparationRetainsOriginalTUNAndDNS(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, execution), func(t *testing.T) {
				layer := "aes-256-gcm"
				if count == 8 {
					layer = ""
				}
				source := nodeChainExecutionFixtureSource(t, count, layer, execution)
				prep, err := NewNodeChainExecutionPreparation(source.LocalSource, execution)
				if err != nil {
					t.Fatal(err)
				}
				original, graph := importedPQGraph(t, prep.local.Config()), importedPQGraph(t, prep.Config())
				if !reflect.DeepEqual(original["inbounds"], graph["inbounds"]) || !reflect.DeepEqual(original["endpoints"], graph["endpoints"]) ||
					prep.SourceSHA256() == prep.local.SourceSHA256() || prep.ConfigSHA256() == prep.local.ConfigSHA256() ||
					externalDigest([]byte(prep.Config())) != prep.ConfigSHA256() || prep.LocalSource() != source.LocalSource || prep.LocalSourceSHA256() != prep.local.SourceSHA256() {
					t.Fatal("preparation lost original TUN/source or relabeled an unchanged hash")
				}
				originalRoute := predecessorCopy(original["route"].(map[string]any))
				originalRoute["final"] = NodeChainExecutionGateTag
				if !reflect.DeepEqual(originalRoute, graph["route"]) {
					t.Fatal("preparation changed original device route restrictions")
				}
				originalRows, rows := original["outbounds"].([]any), graph["outbounds"].([]any)
				if len(rows) != len(originalRows)+1 || !reflect.DeepEqual(rows[:len(originalRows)], originalRows) ||
					!reflect.DeepEqual(rows[len(rows)-1], map[string]any{"type": NodeChainExecutionGateType, "tag": NodeChainExecutionGateTag, "detour": SelectorTag}) {
					t.Fatal("preparation changed original outbound or opened/configured another gate")
				}
				oldDNS, actualDNS := original["dns"].(map[string]any), graph["dns"].(map[string]any)
				expected := predecessorCopy(oldDNS)
				for _, raw := range expected["servers"].([]any) {
					row := raw.(map[string]any)
					if row["detour"] == prep.local.FinalTag() {
						row["detour"] = SelectorTag
					}
				}
				if !reflect.DeepEqual(expected, actualDNS) {
					t.Fatal("preparation replaced selected DNS, bootstrap or an original lower resolver")
				}
				dns, err := prep.DNSCapture()
				if err != nil || dns.SelectedTag != prep.local.FinalTag() || dns.DNS.SourceSHA256 != prep.SourceSHA256() || dns.DNS.ConfigSHA256 != prep.ConfigSHA256() || dns.DNS.FinalTag != SelectorTag {
					t.Fatal("preparation DNS receipt claimed another graph/path", err)
				}
				discovery, err := prep.Discovery()
				if err != nil || discovery.Entry != prep.local.proofs[0] || discovery.SourceSHA256 != prep.SourceSHA256() || discovery.ConfigSHA256 != prep.ConfigSHA256() || discovery.API != "http://10.80.0.1:8787" || discovery.Address != "10.80.0.1:8787" || discovery.Network != "tcp" || discovery.Token != predecessorText(prep.local.nodes[0].profile, "api_token") {
					t.Fatal("discovery did not retain original authenticated private entry", err, discovery)
				}
				physical, err := prep.PhysicalEgress()
				originalPhysical, _ := prep.local.PhysicalEgress()
				if err != nil || !reflect.DeepEqual(physical, originalPhysical) {
					t.Fatal("preparation added physical application/DNS authority", err)
				}
				policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				projection, err := prep.BindExecution(policy)
				if err != nil {
					t.Fatal(err)
				}
				transition, err := projection.Transition()
				if err != nil || transition.PreparationSourceSHA256 != prep.SourceSHA256() || transition.PreparationConfigSHA256 != prep.ConfigSHA256() ||
					transition.SourceSHA256 != policy.SourceSHA256() || transition.ConfigSHA256 != projection.ConfigSHA256() ||
					transition.GateTag != NodeChainExecutionGateTag || transition.SelectorTag != SelectorTag || transition.EntryTag != prep.local.proofs[0].Tag || transition.TUNTag != prep.local.dns.TUNTag ||
					len(transition.AddedOutbounds) != count-1 || projection.ConfigSHA256() == policy.ConfigSHA256() || projection.ConfigSHA256() == prep.ConfigSHA256() || projection.Source() != policy.Source() {
					t.Fatal("actual projected identity/extension did not match captured owners", err)
				}
				if projection.ValidateTransition(prep.Config(), projection.Config()) != nil ||
					projection.ValidateTransition(prep.local.Config(), projection.Config()) == nil || projection.ValidateTransition(prep.Config(), policy.Config()) == nil ||
					projection.ValidateTransition(prep.Config()+" ", projection.Config()) == nil || projection.ValidateTransition(prep.Config(), projection.Config()+" ") == nil {
					t.Fatal("missing gate, old graph or relabeled canonical receipt accepted")
				}
				for _, candidate := range []string{"local", "server"} {
					capture, err := projection.DNSCapture(candidate)
					plain, _ := policy.DNSCapture(candidate)
					plain.DNS.ConfigSHA256 = projection.ConfigSHA256()
					if err != nil || capture != plain {
						t.Fatal("projection DNS lost actual config/path binding", err)
					}
					proofs, _ := projection.ProofInventory(candidate)
					expectedProofs, _ := policy.ProofInventory(candidate)
					if !reflect.DeepEqual(proofs, expectedProofs) {
						t.Fatal("projection changed original proof identity")
					}
				}
			})
		}
	}
}

func TestNodeChainExecutionPreparationRejectsReplannedSource(t *testing.T) {
	prep, policy, _ := nodeChainExecutionProjectionFixture(t)
	for name, mutate := range map[string]func(*NodeChainExecutionSource){
		"new-original-bytes":  func(s *NodeChainExecutionSource) { s.LocalSource += " " },
		"different-execution": func(s *NodeChainExecutionSource) { s.Execution = "server" },
	} {
		t.Run(name, func(t *testing.T) {
			var source NodeChainExecutionSource
			if json.Unmarshal([]byte(policy.Source()), &source) != nil {
				t.Fatal("fixture source")
			}
			mutate(&source)
			other, err := NewNodeChainExecutionPolicy(startJSON(t, source))
			if err != nil {
				t.Fatal("must be valid independent changed source before transition", err)
			}
			if _, err := prep.BindExecution(other); err == nil {
				t.Fatal("preparation adopted a replanned source")
			}
		})
	}
	var local NodeChainSource
	_ = json.Unmarshal([]byte(prep.LocalSource()), &local)
	local.IdentitySources = nil
	if _, err := NewNodeChainExecutionPreparation(startJSON(t, local), "auto"); err == nil {
		t.Fatal("preparation discarded original standard-WG identities")
	}
	for _, execution := range []string{"", "local", "compare", "AUTO", "server "} {
		if _, err := NewNodeChainExecutionPreparation(prep.LocalSource(), execution); err == nil {
			t.Fatal("preparation broadened execution", execution)
		}
	}
	if _, err := prep.BindExecution(nil); err == nil {
		t.Fatal("missing execution policy accepted")
	}
}

func TestNodeChainExecutionTransitionRejectsUncapturedGraphChanges(t *testing.T) {
	prep, original, _ := nodeChainExecutionProjectionFixture(t)
	for name, mutate := range map[string]func(map[string]any){
		"tun-mtu":      func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(1234) },
		"entry-key":    func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["private_key"] = "foreign" },
		"device-rules": func(g map[string]any) { g["route"].(map[string]any)["rules"] = []any{} },
		"direct-final": func(g map[string]any) { g["route"].(map[string]any)["final"] = "direct" },
		"dns-query":    func(g map[string]any) { g["dns"].(map[string]any)["strategy"] = "ipv6_only" },
		"dns-detour": func(g map[string]any) {
			g["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] = "direct"
		},
		"selector-close": func(g map[string]any) {
			for _, v := range g["outbounds"].([]any) {
				row := v.(map[string]any)
				if row["tag"] == SelectorTag {
					row["interrupt_exist_connections"] = false
				}
			}
		},
		"original-outbound": func(g map[string]any) {
			for _, v := range g["outbounds"].([]any) {
				row := v.(map[string]any)
				if row["tag"] == original.local.FinalTag() {
					row["server"] = "192.0.2.99"
					return
				}
			}
		},
		"foreign-outbound": func(g map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": "foreign"})
		},
		"duplicate-gate": func(g map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": NodeChainExecutionGateType, "tag": NodeChainExecutionGateTag, "detour": SelectorTag})
		},
		"duplicate-tag": func(g map[string]any) {
			rows := g["outbounds"].([]any)
			rows[len(rows)-1].(map[string]any)["tag"] = rows[0].(map[string]any)["tag"]
		},
		"reorder-original": func(g map[string]any) { rows := g["outbounds"].([]any); rows[0], rows[1] = rows[1], rows[0] },
	} {
		t.Run(name, func(t *testing.T) {
			policy, err := NewNodeChainExecutionPolicy(original.Source())
			if err != nil {
				t.Fatal(err)
			}
			graph := importedPQGraph(t, policy.Config())
			mutate(graph)
			policy.config = startJSON(t, graph)
			policy.configSHA = externalDigest([]byte(policy.config))
			policy.seal = policy.captureSeal() // bypass storage seal to exercise transition structure directly
			if policy.validateCapture() != nil {
				t.Fatal("structural transition witness was masked by storage seal")
			}
			if _, err := prep.BindExecution(policy); err == nil {
				t.Fatal("uncaptured transition changed a retained original native object")
			}
		})
	}
}

func TestNodeChainExecutionProjectionRetainsSealedReceipts(t *testing.T) {
	prep, _, projection := nodeChainExecutionProjectionFixture(t)
	transition, _ := projection.Transition()
	transition.AddedOutbounds[0] = "foreign"
	proofs := prep.ProofInventory()
	proofs[0].Tag = "foreign"
	physical, _ := prep.PhysicalEgress()
	physical[0].Host = "foreign"
	discovery, _ := prep.Discovery()
	discovery.Token = "foreign"
	if prep.validateCapture() != nil || projection.validateCapture() != nil {
		t.Fatal("returned data aliased original capture")
	}
	for name, mutate := range map[string]func(*NodeChainExecutionPreparation, *NodeChainExecutionProjection){
		"prep-source":    func(p *NodeChainExecutionPreparation, _ *NodeChainExecutionProjection) { p.source.LocalSource += " " },
		"prep-config":    func(p *NodeChainExecutionPreparation, _ *NodeChainExecutionProjection) { p.config += " " },
		"prep-discovery": func(p *NodeChainExecutionPreparation, _ *NodeChainExecutionProjection) { p.discovery.Token = "foreign" },
		"prep-dns": func(p *NodeChainExecutionPreparation, _ *NodeChainExecutionProjection) {
			p.dns.DNS.ConfigSHA256 = strings.Repeat("a", 64)
		},
		"final-config": func(_ *NodeChainExecutionPreparation, p *NodeChainExecutionProjection) { p.config += " " },
		"transition": func(_ *NodeChainExecutionPreparation, p *NodeChainExecutionProjection) {
			p.transition.SelectorBeforeJSON = "{}"
		},
		"appended": func(_ *NodeChainExecutionPreparation, p *NodeChainExecutionProjection) {
			p.transition.AddedOutbounds[0] = "{}"
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, _, x := nodeChainExecutionProjectionFixture(t)
			mutate(p, x)
			if _, err := x.Transition(); err == nil {
				t.Fatal("changed original capture published a transition")
			}
			if _, err := x.DNSCapture("local"); err == nil {
				t.Fatal("changed original capture published DNS authority")
			}
		})
	}
}

func TestNodeChainExecutionPreparationKeepsSelectedDNSAndBootstrapOwners(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		for _, hostname := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hostname=%v", protocol, hostname), func(t *testing.T) {
				nodes := nodeChainModeFixtureNodes(t, []string{"awg2-fast", "awg2-strong", "shadowsocks"}, []string{"aes-256-gcm", "", ""})
				identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
				last := nodes[len(nodes)-1]
				profile := predecessorCopy(last.profile)
				profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", protocol, "9.9.9.9", float64(5443)
				profile["dns_server_name"], profile["dns_path"] = "captured-query.example", "/original-query"
				bootstrap := ""
				if hostname {
					profile["dns_host"] = "captured-query.example"
					bootstrap = startJSON(t, map[string]any{"server": map[string]any{"type": "h3", "tag": "external-dns-bootstrap", "server": "1.1.1.1", "server_port": 5553, "detour": "proxy", "tls": map[string]any{"enabled": true, "server_name": "original-bootstrap.example"}, "path": "/original-bootstrap"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "disable_cache": true}})
				}
				var err error
				nodes[len(nodes)-1], err = NewNodeProfile(last.mode, last.inputs.Files, startJSON(t, profile), last.inputs.Start, bootstrap)
				if err != nil {
					t.Fatal(err)
				}
				source := nodeChainExecutionFixtureFromNodes(t, nodes, identities, "auto")
				prep, err := NewNodeChainExecutionPreparation(source.LocalSource, source.Execution)
				if err != nil {
					t.Fatal(err)
				}
				policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				projection, err := prep.BindExecution(policy)
				if err != nil {
					t.Fatal(err)
				}
				before, after := importedPQGraph(t, prep.Config()), importedPQGraph(t, projection.Config())
				if !reflect.DeepEqual(before["dns"], after["dns"]) || !reflect.DeepEqual(before["inbounds"], after["inbounds"]) || !reflect.DeepEqual(before["route"], after["route"]) {
					t.Fatal("discovery transition replaced retained resolver, TUN or original hijack/device rules")
				}
				count := 0
				for _, raw := range before["dns"].(map[string]any)["servers"].([]any) {
					row := raw.(map[string]any)
					if row["detour"] == SelectorTag {
						count++
					}
				}
				want := 1
				if hostname {
					want = 2
				}
				if count != want {
					t.Fatal("selected DNS/bootstrap did not retain same selector", count)
				}
				initial, _ := prep.DNSCapture()
				for _, execution := range []string{"local", "server"} {
					capture, err := projection.DNSCapture(execution)
					if err != nil || capture.DNS.ResolverSHA256 != initial.DNS.ResolverSHA256 || capture.DNS.ResolverTag != initial.DNS.ResolverTag || capture.DNSPolicySHA256 != initial.DNSPolicySHA256 || capture.DNS.ConfigSHA256 == initial.DNS.ConfigSHA256 {
						t.Fatal("same resolver was relabeled as same whole native configuration", err)
					}
				}
			})
		}
	}
}
