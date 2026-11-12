package mobilemultihop

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func desktopExecutionSource(t *testing.T, execution, protocol string, hostname bool) NodeChainExecutionSource {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, []string{"awg2-fast", "awg2-strong", "shadowsocks"}, []string{"aes-256-gcm+xor-whitening", "", ""})
	identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
	for i, node := range nodes {
		profile := predecessorCopy(node.profile)
		profile["kill_switch_policy"] = "on-connect"
		if i == 1 {
			profile["kill_switch_policy"], profile["ipv6_mode"], profile["home_lan_access"] = "always", "off", false
		}
		bootstrap := node.inputs.DNSBootstrap
		if i == len(nodes)-1 && protocol != "" {
			profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", protocol, "9.9.9.9", float64(5443)
			profile["dns_server_name"], profile["dns_path"] = "captured-query.example", "/original-query"
			if hostname {
				profile["dns_host"] = "captured-query.example"
				bootstrap = startJSON(t, map[string]any{"server": map[string]any{"type": "h3", "tag": "external-dns-bootstrap", "server": "1.1.1.1", "server_port": 5553, "detour": "proxy", "tls": map[string]any{"enabled": true, "server_name": "original-bootstrap.example"}, "path": "/original-bootstrap"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "disable_cache": true}})
			}
		}
		var err error
		nodes[i], err = NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, bootstrap)
		if err != nil {
			t.Fatal(err)
		}
	}
	return nodeChainExecutionFixtureFromNodes(t, nodes, identities, execution)
}

func desktopExecutionProjection(t *testing.T, source NodeChainExecutionSource, target, session string, mtu int) (*DesktopNodeChainPolicy, *NodeChainExecutionPreparation, *NodeChainExecutionProjection) {
	t.Helper()
	local, err := NewNodeChain(source.LocalSource)
	if err != nil {
		t.Fatal(err)
	}
	original, err := NewDesktopNodeChainPolicy(local, session, target, mtu)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := NewDesktopNodeChainExecutionPreparation(original, source.Execution)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := preparation.BindExecution(policy)
	if err != nil {
		t.Fatal(err)
	}
	return original, preparation, projection
}

func TestDesktopNodeChainExecutionKeepsActualPhysicalGraph(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, execution := range []string{"server", "auto"} {
			for _, mtu := range []int{0, 1400} {
				t.Run(fmt.Sprintf("%s/%s/%d", target, execution, mtu), func(t *testing.T) {
					source := desktopExecutionSource(t, execution, "", false)
					original, prep, projection := desktopExecutionProjection(t, source, target, desktopNodeTestSession, mtu)
					base, before, after := startObject(t, original.Config()), startObject(t, prep.Config()), startObject(t, projection.Config())
					for _, family := range []string{"inbounds", "endpoints", "services"} {
						if !reflect.DeepEqual(base[family], before[family]) || !reflect.DeepEqual(before[family], after[family]) {
							t.Fatal("execution replaced original physical graph", family)
						}
					}
					if !reflect.DeepEqual(before["dns"], after["dns"]) || !reflect.DeepEqual(before["route"], after["route"]) {
						t.Fatal("server discovery replaced retained DNS or device rules")
					}
					for _, family := range []string{"outbounds", "endpoints"} {
						for _, raw := range base[family].([]any) {
							row := raw.(map[string]any)
							if row["tag"] == SelectorTag {
								continue
							}
							for _, graph := range []map[string]any{before, after} {
								if !reflect.DeepEqual(row, desktopNodeObject(t, graph, family, row["tag"].(string))) {
									t.Fatal("execution changed original lower transport, key or endpoint")
								}
							}
						}
					}
					physical, err := prep.DesktopPhysicalPolicy()
					if err != nil {
						t.Fatal(err)
					}
					retained, err := projection.DesktopPhysicalPolicy()
					if err != nil || retained != physical {
						t.Fatal("adoption replaced original physical pointer", err)
					}
					capturedOriginal, err := physical.OriginalDesktopPolicy()
					if err != nil || capturedOriginal != original {
						t.Fatal("preparation replaced sealed original desktop policy", err)
					}
					config, meta, capture, err := ReadDesktopPhysicalPolicy(physical)
					_, _, oldCapture, _ := original.ReadValidated()
					if err != nil || config != prep.Config() || meta.ConfigSHA256 != prep.ConfigSHA256() ||
						meta.SourceSHA256 != original.Metadata().SourceSHA256 || meta.Kind != "node-chain-execution" || meta.TargetOS != target || meta.SessionID != desktopNodeTestSession || meta.RestoredMTU != mtu ||
						meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess ||
						!reflect.DeepEqual(capture.PhysicalRoots, oldCapture.PhysicalRoots) || !reflect.DeepEqual(capture.PrivateDestinations, oldCapture.PrivateDestinations) {
						t.Fatal("physical reader relabeled actual construction or broadened original policy", err)
					}
					if capture.SelectedDNS.Detour != SelectorTag || capture.SelectedDNS.Physical || capture.SelectedDNS.ConfigSHA256 != prep.dns.DNS.ResolverSHA256 || capture.ConfiguredMTU != oldCapture.ConfiguredMTU {
						t.Fatal("physical preparation lost original DNS or MTU intent")
					}
					if _, _, err := ReadDesktopPhysicalCoverPolicy(physical); err != nil {
						t.Fatal("closed cover reader omitted exact new constructor", err)
					}
					if prep.ConfigSHA256() == original.Metadata().ConfigSHA256 || projection.ConfigSHA256() == prep.ConfigSHA256() || projection.ConfigSHA256() == projection.policy.ConfigSHA256() ||
						projection.SourceSHA256() != projection.policy.SourceSHA256() || projection.Source() != projection.policy.Source() || prep.LocalSource() != source.LocalSource {
						t.Fatal("logical or actual physical identity was replaced by a hash label")
					}
					transition, _ := projection.Transition()
					if transition.PreparationConfigSHA256 != prep.ConfigSHA256() || transition.ConfigSHA256 != projection.ConfigSHA256() || len(transition.AddedOutbounds) != 2 ||
						projection.ValidateTransition(original.Config(), projection.Config()) == nil || projection.ValidateTransition(prep.Config(), projection.policy.Config()) == nil {
						t.Fatal("execution accepted generic or stale actual graph")
					}
					parsed, err := ParseNodeChainExecutionPreparation(prep.Source())
					if err != nil || parsed.Config() != prep.Config() || parsed.SourceSHA256() != prep.SourceSHA256() {
						t.Fatal("physical preparation did not round-trip its original typed derivation", err)
					}
				})
			}
		}
	}
}

func TestDesktopNodeChainExecutionPreservesSelectedDNSBootstrap(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			source := desktopExecutionSource(t, "auto", protocol, true)
			_, prep, projection := desktopExecutionProjection(t, source, "darwin", desktopNodeTestSession, 1400)
			physical, _ := prep.DesktopPhysicalPolicy()
			_, _, capture, err := ReadDesktopPhysicalPolicy(physical)
			if err != nil || len(capture.BootstrapDNS) != 1 || capture.BootstrapDNS[0].Physical || capture.BootstrapDNS[0].Detour != SelectorTag || capture.SelectedDNS.Detour != SelectorTag {
				t.Fatal("selected hostname bootstrap gained another native owner", err, capture.BootstrapDNS)
			}
			before, after := startObject(t, prep.Config()), startObject(t, projection.Config())
			if !reflect.DeepEqual(before["dns"], after["dns"]) {
				t.Fatal("server adoption replaced selected DNS/bootstrap tree")
			}
			for _, selected := range []string{"local", "server"} {
				dns, err := projection.DNSCapture(selected)
				if err != nil || dns.DNS.ConfigSHA256 != projection.ConfigSHA256() || dns.DNS.ResolverSHA256 != capture.SelectedDNS.ConfigSHA256 || dns.DNSPolicySHA256 != source.Server.DNSPolicySHA256 {
					t.Fatal("selected DNS receipt has another actual graph/source", err)
				}
			}
		})
	}
}

type desktopExecutionForgedPhysical struct{ DesktopPhysicalPolicy }

func TestDesktopNodeChainExecutionRefusesForgedPhysicalAuthority(t *testing.T) {
	source := desktopExecutionSource(t, "auto", "", false)
	_, prep, projection := desktopExecutionProjection(t, source, "linux", desktopNodeTestSession, 0)
	physical, _ := prep.DesktopPhysicalPolicy()
	if _, _, _, err := ReadDesktopPhysicalPolicy(&desktopExecutionForgedPhysical{physical}); err == nil {
		t.Fatal("caller wrapper gained original physical authority")
	}
	copy := *physical
	if copy.Validate() == nil {
		t.Fatal("copied physical wrapper replaced retained original pointer")
	}
	generic, err := NewNodeChainExecutionPreparation(source.LocalSource, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(generic).(DesktopPhysicalPolicy); ok {
		t.Fatal("generic preparation acquired physical policy interface")
	}
	if _, err := generic.DesktopPhysicalPolicy(); err == nil {
		t.Fatal("generic graph gained physical constructor authority")
	}
	if _, err := NewDesktopNodeChainExecutionPreparation(nil, "auto"); err == nil {
		t.Fatal("missing original physical source accepted")
	}
	prep.desktop.chain.config += " "
	if physical.Validate() == nil {
		t.Fatal("changed original sealed desktop source stayed current")
	}
	if _, err := projection.DesktopPhysicalPolicy(); err == nil {
		t.Fatal("final projection discarded changed physical owner")
	}
}

func TestDesktopNodeChainExecutionRejectsChangedTypedHandoff(t *testing.T) {
	source := desktopExecutionSource(t, "server", "", false)
	_, prep, _ := desktopExecutionProjection(t, source, "windows", desktopNodeTestSession, 1400)
	for name, change := range map[string]func(*NodeChainExecutionPreparationSource){
		"schema":     func(s *NodeChainExecutionPreparationSource) { s.Schema++ },
		"source":     func(s *NodeChainExecutionPreparationSource) { s.LocalSource += " " },
		"target":     func(s *NodeChainExecutionPreparationSource) { s.Desktop.TargetOS = "darwin" },
		"session":    func(s *NodeChainExecutionPreparationSource) { s.Desktop.SessionID = strings.Repeat("b", 32) },
		"mtu":        func(s *NodeChainExecutionPreparationSource) { s.Desktop.RestoredMTU = 1300 },
		"source-sha": func(s *NodeChainExecutionPreparationSource) { s.Desktop.SourceSHA256 = strings.Repeat("b", 64) },
		"config-sha": func(s *NodeChainExecutionPreparationSource) { s.Desktop.ConfigSHA256 = strings.Repeat("b", 64) },
		"capture-sha": func(s *NodeChainExecutionPreparationSource) {
			s.Desktop.OriginalCaptureSHA256 = strings.Repeat("b", 64)
		},
		"root": func(s *NodeChainExecutionPreparationSource) {
			s.Desktop.Roots[0].DerivedSHA256 = strings.Repeat("b", 64)
		},
		"proof": func(s *NodeChainExecutionPreparationSource) { s.Desktop.Prefixes[0].NodeID = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var input NodeChainExecutionPreparationSource
			if json.Unmarshal([]byte(prep.Source()), &input) != nil {
				t.Fatal("source")
			}
			change(&input)
			if _, err := ParseNodeChainExecutionPreparation(startJSON(t, input)); err == nil {
				t.Fatal("changed typed desktop receipt accepted")
			}
		})
	}
	if _, err := ParseNodeChainExecutionPreparation(prep.Source() + " "); err == nil {
		t.Fatal("noncanonical handoff accepted")
	}
	var generic NodeChainExecutionPreparationSource
	if json.Unmarshal([]byte(prep.Source()), &generic) != nil {
		t.Fatal("source")
	}
	generic.Desktop = nil
	if _, err := ParseDesktopNodeChainExecutionPreparation(startJSON(t, generic)); err == nil {
		t.Fatal("desktop child accepted missing physical family")
	}
}

func TestDesktopNodeChainExecutionRetainsCompleteOriginalState(t *testing.T) {
	source := desktopExecutionSource(t, "server", "", false)
	original, prep, _ := desktopExecutionProjection(t, source, "linux", desktopNodeTestSession, 0)
	physical, _ := prep.DesktopPhysicalPolicy()
	_, _, copied, err := ReadDesktopPhysicalPolicy(physical)
	if err != nil {
		t.Fatal(err)
	}
	copied.PhysicalRoots[0].Networks[0] = "foreign"
	_, _, again, err := ReadDesktopPhysicalPolicy(physical)
	if err != nil || again.PhysicalRoots[0].Networks[0] == "foreign" {
		t.Fatal("physical reader exposed mutable original authority", err)
	}
	for name, change := range map[string]func() func(){
		"derivation-input": func() func() {
			before := original.inputs
			original.inputs.targetOS = "darwin"
			return func() { original.inputs = before }
		},
		"original-source": func() func() {
			before := original.original.sourceJSON
			original.original.sourceJSON += " "
			return func() { original.original.sourceJSON = before }
		},
		"derived-config": func() func() {
			before := original.chain.config
			original.chain.config += " "
			return func() { original.chain.config = before }
		},
		"metadata": func() func() {
			before := original.metadata.ProfileID
			original.metadata.ProfileID = "foreign"
			return func() { original.metadata.ProfileID = before }
		},
		"physical-copy": func() func() {
			before := physical.capture.PhysicalRoots[0].Networks[0]
			physical.capture.PhysicalRoots[0].Networks[0] = "foreign"
			return func() { physical.capture.PhysicalRoots[0].Networks[0] = before }
		},
	} {
		t.Run(name, func(t *testing.T) {
			restore := change()
			defer restore()
			if physical.Validate() == nil {
				t.Fatal("retained physical authority ignored changed original state")
			}
		})
	}
	if physical.Validate() != nil {
		t.Fatal("test did not restore original immutable fixture")
	}
}

func TestDesktopNodeChainExecutionRejectsChangedGenericExtension(t *testing.T) {
	source := desktopExecutionSource(t, "server", "", false)
	_, prep, _ := desktopExecutionProjection(t, source, "darwin", desktopNodeTestSession, 0)
	for name, change := range map[string]func(map[string]any){
		"tun":   func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(1500) },
		"entry": func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["private_key"] = "foreign" },
		"dns":   func(g map[string]any) { g["dns"].(map[string]any)["strategy"] = "ipv6_only" },
	} {
		t.Run(name, func(t *testing.T) {
			policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			graph := startObject(t, policy.Config())
			change(graph)
			policy.config = startJSON(t, graph)
			policy.configSHA = externalDigest([]byte(policy.config))
			policy.seal = policy.captureSeal()
			if policy.validateCapture() != nil {
				t.Fatal("structural witness masked by seal")
			}
			if _, err := prep.BindExecution(policy); err == nil {
				t.Fatal("desktop extension discarded original structural validation")
			}
		})
	}
}

func desktopExecutionRuntimeProjection(t *testing.T, f *nodeChainExecutionRuntimeFixture) NodeChainExecutionSource {
	t.Helper()
	previous := f.runtime.projection
	source := previous.policy.source
	var local NodeChainSource
	if json.Unmarshal([]byte(source.LocalSource), &local) != nil {
		t.Fatal("local source")
	}
	for i, node := range previous.policy.local.nodes {
		profile := predecessorCopy(node.profile)
		profile["kill_switch_policy"] = "on-connect"
		changed, err := NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
		local.Nodes[i], err = changed.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
	}
	source.LocalSource = startJSON(t, local)
	_, _, projection := desktopExecutionProjection(t, source, "linux", desktopNodeTestSession, 0)
	peers := map[string]string{}
	for _, execution := range []string{"local", "server"} {
		oldProofs, _ := previous.ProofInventory(execution)
		newProofs, _ := projection.ProofInventory(execution)
		for i, proof := range oldProofs {
			api, _ := privateAPI(predecessorText(previous.policy.local.nodes[i].profile, "router_api"))
			peers[newProofs[i].Tag+"/"+api.Host] = f.engine.peers[proof.Tag+"/"+api.Host]
		}
	}
	f.engine.projection, f.engine.peers = projection, peers
	f.engine.identity.SourceSHA256, f.engine.identity.ConfigSHA256 = projection.SourceSHA256(), projection.ConfigSHA256()
	f.engine.selected = projection.policy.local.FinalTag()
	var err error
	f.runtime, err = NewNodeChainExecutionRuntime(projection, f.engine)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.testTLS = f.trust
	return source
}

func TestDesktopNodeChainExecutionRestoresFreshPhysicalSession(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	source := desktopExecutionRuntimeProjection(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	capture, err := f.runtime.CaptureRestoreContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, projection := desktopExecutionProjection(t, source, "linux", strings.Repeat("b", 32), 1400)
	next := cloneNodeChainExecutionRuntimeEngine(f.engine)
	next.projection = projection
	next.identity.ConfigSHA256 = projection.ConfigSHA256()
	if _, err := NewDesktopNodeChainExecutionRestoreRuntime(capture, projection, next); err == nil {
		t.Fatal("new physical session bypassed original shared cleanup")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	f.engine.alive = false
	f.engine.mu.Unlock() // native retirement is a separate explicit boundary double
	for name, replacement := range map[string]*NodeChainExecutionProjection{"same-session": capture.projection} {
		if _, err := NewDesktopNodeChainExecutionRestoreRuntime(capture, replacement, next); err == nil {
			t.Fatal("restore accepted", name)
		}
	}
	_, _, wrongTarget := desktopExecutionProjection(t, source, "darwin", strings.Repeat("c", 32), 1400)
	if _, err := NewDesktopNodeChainExecutionRestoreRuntime(capture, wrongTarget, next); err == nil {
		t.Fatal("restore changed original native target")
	}
	changed := source
	changed.Request.Users = append([]multihoprelay.NodeChainUser(nil), source.Request.Users...)
	changed.Request.Users[0].Password = strings.Repeat("a", 48)
	_, _, newUsers := desktopExecutionProjection(t, changed, "linux", strings.Repeat("c", 32), 1400)
	if _, err := NewDesktopNodeChainExecutionRestoreRuntime(capture, newUsers, next); err == nil {
		t.Fatal("restore replanned original credentials")
	}
	restored, err := NewDesktopNodeChainExecutionRestoreRuntime(capture, projection, next)
	if err != nil {
		t.Fatal(err)
	}
	restored.testTLS = f.trust
	t.Cleanup(func() {
		cleanup, finish := context.WithTimeout(context.Background(), 3*time.Second)
		defer finish()
		if err := restored.CloseContext(cleanup); err != nil {
			t.Error(err)
		}
	})
	if err := restored.Run(ctx); err != nil {
		t.Fatal(err)
	}
	progress := restored.Progress()
	if !progress.Ready || progress.Execution != capture.execution || progress.Comparison.Target != capture.result.Target || !reflect.DeepEqual(progress.Comparison.Measurements, capture.result.Measurements) ||
		restored.identity.SourceSHA256 != capture.identity.SourceSHA256 || restored.identity.ConfigSHA256 == capture.identity.ConfigSHA256 || restored.identity.ConfigSHA256 != projection.ConfigSHA256() {
		t.Fatal("physical restore replaced captured result or relabeled actual configuration")
	}
	next.mu.Lock()
	selections := len(next.selections)
	next.mu.Unlock()
	if selections != 1 {
		t.Fatal("physical restore reopened comparison trials", selections)
	}
}
