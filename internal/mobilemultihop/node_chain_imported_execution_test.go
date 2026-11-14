package mobilemultihop

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

func nodeChainImportedServerFixture(t *testing.T, mode, layer string) (NodeChainSource, *NodeChainServerPolicy, multihoprelay.NodeChainCapture) {
	t.Helper()
	localSource := nodeChainImportedFixture(t, mode, layer)
	local, err := NewNodeChain(startJSON(t, localSource))
	if err != nil {
		t.Fatal(err)
	}
	source := NodeChainServerSource{Schema: 2, EntryID: local.proofs[0].ProfileID, EntryNodeID: local.proofs[0].NodeID,
		EntryMode: mode, Nodes: append([]string(nil), localSource.Nodes[1:]...), IdentitySources: append([]string(nil), localSource.IdentitySources[1:]...)}
	server, err := NewNodeChainServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal("actual imported SS server compiler", err)
	}
	return localSource, server, nodeChainServerCaptureFixture(t, server)
}

func nodeChainImportedExecutionFixtureSource(t *testing.T, mode, layer, execution string) NodeChainExecutionSource {
	t.Helper()
	local, server, capture := nodeChainImportedServerFixture(t, mode, layer)
	chain, err := NewNodeChain(startJSON(t, local))
	if err != nil {
		t.Fatal(err)
	}
	key, err := chain.nodes[0].PacketClientPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	request := capture.Request.Clone()
	request.LocalPacketPublicKeys = []string{key}
	request.Peer, request.Port = "10.80.0.2", 32003
	return NodeChainExecutionSource{Schema: 1, Execution: execution, LocalSource: startJSON(t, local), Server: server.Descriptor(),
		Request: request, FirstPort: 32000, LastPort: 32007}
}

func TestNodeChainImportedServerRetainsOriginalTransportProofAndFinalDNS(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				local, server, capture := nodeChainImportedServerFixture(t, mode, layer)
				config, err := server.NativeConfig(capture)
				if err != nil {
					t.Fatal(err)
				}
				graph := importedPQGraph(t, config)
				if len(graph["inbounds"].([]any)) != 0 || len(graph["endpoints"].([]any)) != 0 || server.NativeCarrierRequired() {
					t.Fatal("SS suffix manufactured a packet carrier or TUN")
				}
				proofs := server.ProofInventory()
				middle := externalTestFind(t, graph, proofs[0].Tag)
				if middle["type"] != "shadowsocks" || middle["method"] != NativeStartLayerMethod || middle["detour"] != nil ||
					proofs[0].NodeID != "" || proofs[0].NodeKind != "external" || proofs[0].Kind != "public-path" ||
					server.importedMiddle.input != local.Nodes[1] || server.nodes[0] != nil {
					t.Fatal("imported source was relabeled, substituted or bypassed")
				}
				dns, err := server.DNSCapture(capture)
				if err != nil || !strings.Contains(dns.PolicyJSON, "10.82.0.53") || dns.FinalTag != proofs[1].Tag {
					t.Fatal("final selected DNS changed", err)
				}
				for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
					resolver := raw.(map[string]any)
					if resolver["detour"] != proofs[1].Tag {
						t.Fatal("imported standalone DNS replaced final policy", resolver)
					}
				}
				targets, err := server.ProofTargets(capture)
				if err != nil || targets[0].API != "" || targets[0].Token != "" || targets[0].Address != "1.1.1.1:443" || targets[0].ExpectedPublicIP != "203.0.113.88" || targets[1].Token == "" {
					t.Fatal("public/private proof authority changed", err)
				}
				routes, err := server.FrontRoutes(capture)
				if err != nil || len(routes) != 2 || routes[0].Final || routes[0].UDPOverTCPVersion != 0 || !routes[0].PublicPathBenchmark ||
					!routes[1].Final || routes[1].UDPOverTCPVersion != 2 || routes[1].PublicPathBenchmark {
					t.Fatal("prefix credential gained final/UDP authority", err)
				}
				for _, disallowed := range []struct{ network, address string }{{"udp", "1.1.1.1:443"}, {"tcp", "10.82.0.1:8787"}, {"tcp", "example.com:443"}, {"tcp", "93.184.216.34:443"}} {
					if routes[0].AllowsDestination(disallowed.network, disallowed.address) {
						t.Fatal("imported prefix allowed uncaptured destination", disallowed)
					}
				}
			})
		}
	}
}

func TestNodeChainImportedServerRejectsUnregisteredOrInventedSource(t *testing.T) {
	_, good, _ := nodeChainImportedServerFixture(t, "wg", "")
	for name, mutate := range map[string]func(*NodeChainServerSource){
		"paired-schema": func(s *NodeChainServerSource) { s.Schema = 1 },
		"extra-node": func(s *NodeChainServerSource) {
			s.Nodes = append(s.Nodes, s.Nodes[1])
			s.IdentitySources = append(s.IdentitySources, s.IdentitySources[1])
		},
		"fake-identity":          func(s *NodeChainServerSource) { s.IdentitySources[0] = s.IdentitySources[1] },
		"missing-final-identity": func(s *NodeChainServerSource) { s.IdentitySources[1] = "" },
		"reordered":              func(s *NodeChainServerSource) { s.Nodes[0], s.Nodes[1] = s.Nodes[1], s.Nodes[0] },
		"unbound-config": func(s *NodeChainServerSource) {
			s.Nodes[0] = strings.Replace(s.Nodes[0], "203.0.113.20", "203.0.113.21", 1)
		},
		"router-label": func(s *NodeChainServerSource) {
			s.Nodes[0] = strings.Replace(s.Nodes[0], `\"node_kind\":\"external\"`, `\"node_kind\":\"router\"`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var source NodeChainServerSource
			if json.Unmarshal([]byte(good.Source()), &source) != nil {
				t.Fatal("source")
			}
			before := startJSON(t, source)
			mutate(&source)
			if startJSON(t, source) == before {
				t.Fatal("negative fixture did not change source")
			}
			if _, err := NewNodeChainServerPolicy(startJSON(t, source)); err == nil {
				t.Fatal("invented operator authority accepted")
			}
		})
	}
}

func TestNodeChainImportedExecutionBindsFullSourceAndPositionalKeys(t *testing.T) {
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			source := nodeChainImportedExecutionFixtureSource(t, "awg2-strong", "aes-256-gcm+xor-whitening", execution)
			policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			prep, err := NewNodeChainExecutionPreparation(source.LocalSource, execution)
			if err != nil {
				t.Fatal(err)
			}
			projection, err := prep.BindExecution(policy)
			if err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"local", "server"} {
				proofs, err := projection.ProofInventory(kind)
				if err != nil || len(proofs) != 3 || proofs[1].NodeKind != "external" || proofs[1].Kind != "public-path" || proofs[1].NodeID != "" || proofs[1].SourceSHA256 != source.Server.Members[0].SourceSHA256 {
					t.Fatal("execution lost actual imported proof identity", err)
				}
			}
			if !reflect.DeepEqual(policy.Request().LocalPacketPositions, []int{0}) || len(policy.Request().LocalPacketPublicKeys) != 1 {
				t.Fatal("SS acquired a fake packet pin")
			}
			original := importedPQGraph(t, prep.local.Config())
			graph := importedPQGraph(t, projection.Config())
			if !reflect.DeepEqual(original["inbounds"], graph["inbounds"]) || !reflect.DeepEqual(original["endpoints"], graph["endpoints"]) {
				t.Fatal("execution changed original native TUN or packet transport")
			}
			if _, err := projection.MTUPlan(); err != nil {
				t.Fatal("imported execution lost original MTU bounds", err)
			}
			launch, err := policy.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := ParseNodeChainExecutionLaunchInput(launch)
			if err != nil || reopened.Config() != policy.Config() {
				t.Fatal("exact execution replay changed source", err)
			}
			for _, fault := range []string{"source", "egress", "position", "key", "paired-schema"} {
				var changed NodeChainExecutionSource
				_ = json.Unmarshal([]byte(startJSON(t, source)), &changed)
				switch fault {
				case "source":
					changed.Server.Members[0].SourceSHA256 = strings.Repeat("b", 64)
				case "egress":
					changed.Server.Members[0].ExpectedPublicIP = "203.0.113.89"
				case "position":
					changed.Request.LocalPacketPositions[0] = 1
				case "key":
					changed.Request.LocalPacketPublicKeys[0] = source.Server.EntryNodeID
				case "paired-schema":
					changed.Server.Schema = 1
				}
				if digest, err := changed.Server.Digest(); err == nil {
					changed.Request.DescriptorSHA256 = digest
				}
				if _, err := NewNodeChainExecutionPolicy(startJSON(t, changed)); err == nil {
					t.Fatal("rebound public descriptor borrowed original private member", fault)
				}
			}
		})
	}
}

func TestNodeChainImportedServerProofExecutesPublicTLSBeforeFinalAdmission(t *testing.T) {
	for _, fault := range []string{"none", "wrong-public", "wrong-final", "selected-dns", "changed-owner"} {
		t.Run(fault, func(t *testing.T) {
			_, policy, capture := nodeChainImportedServerFixture(t, "wg", "")
			e := newNodeChainServerProofTestEngine(t, policy, capture)
			switch fault {
			case "wrong-public":
				e.publicBody = "ip=203.0.113.89\n"
			case "wrong-final":
				e.wrongPrefix = 1
			case "selected-dns":
				e.dnsFail = true
			case "changed-owner":
				e.changeOnPublic = true
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			result, err := policy.prove(ctx, capture, e, e.trust)
			if fault != "none" {
				if err == nil || !result.ProvenAt.IsZero() {
					t.Fatal("failed original imported proof granted admission", fault)
				}
				return
			}
			if err != nil || len(result.Prefixes) != 2 || !result.DNSProven || !result.PublicProven || result.Prefixes[0].Proof.NodeID != "" || result.Prefixes[0].ResponseMS <= 0 {
				t.Fatal("complete actual HTTP/TLS proof failed", err)
			}
			e.mu.Lock()
			calls := append([]string(nil), e.calls...)
			e.mu.Unlock()
			if !reflect.DeepEqual(calls, []string{"public", policy.proofs[1].Tag, "public"}) {
				t.Fatal("imported member was not independently proved before final", calls)
			}
		})
	}
}

func TestNodeChainImportedExecutionPreservesMeanComparisonAndCaptureReplay(t *testing.T) {
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			source := nodeChainImportedExecutionFixtureSource(t, "wg", "", execution)
			f := newNodeChainExecutionRuntimeFixtureFromSource(t, source)
			var mu sync.Mutex
			var finalTargets []string
			f.engine.beforeDial = func(_ context.Context, tag, address string) (net.Conn, error, bool) {
				for _, kind := range []string{"local", "server"} {
					proofs, _ := f.runtime.projection.ProofInventory(kind)
					if tag == proofs[2].Tag && (address == "1.1.1.1:443" || address == "1.0.0.1:443") {
						mu.Lock()
						finalTargets = append(finalTargets, address)
						mu.Unlock()
					}
				}
				return nil, nil, false
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			state := f.runtime.Progress()
			if !state.Ready || !state.DNSProven || !state.PublicProven || len(state.Prefixes) != 3 || state.Comparison.Final == nil {
				t.Fatal("imported execution did not prove complete selected path", state)
			}
			for _, m := range append(state.Comparison.Measurements, *state.Comparison.Final) {
				if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != (m.LastNodeMS+m.ExternalMS)/2 {
					t.Fatal("required two-probe average changed", m)
				}
			}
			if execution == "auto" && len(state.Comparison.Measurements) != 2 {
				t.Fatal("Compare omitted a complete candidate")
			}
			mu.Lock()
			targets := append([]string(nil), finalTargets...)
			mu.Unlock()
			if len(targets) == 0 {
				t.Fatal("missing actual external probes")
			}
			for _, target := range targets {
				if target != targets[0] {
					t.Fatal("candidates used different external endpoints", targets)
				}
			}
			last, err := f.runtime.CaptureLastContext(ctx)
			if err != nil || last.Execution() != state.Execution || last.Target() != state.Comparison.Target {
				t.Fatal("proved choice/target was lost", err)
			}
			decoded, err := ParseNodeChainExecutionLast(last.JSON(), f.runtime.projection.preparation)
			if err != nil || decoded.Execution() != last.Execution() {
				t.Fatal("durable imported choice was relabeled", err)
			}
			owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
			measurement, err := f.runtime.NewHopMeasurementContext(ctx, owner)
			if err != nil {
				t.Fatal("imported selected execution lost owned measurement", err)
			}
			if err := measurement.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeChainImportedExecutionLastReprovesCapturedChoiceWithoutCompare(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			source := nodeChainImportedExecutionFixtureSource(t, "wg", "", "auto")
			old := newNodeChainExecutionRuntimeFixtureFromSource(t, source)
			old.engine.localDelay, old.engine.serverDelay = 200*time.Millisecond, time.Millisecond
			if winner == "local" {
				old.engine.localDelay, old.engine.serverDelay = time.Millisecond, 200*time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			if err := old.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			last, err := old.runtime.CaptureLastContext(ctx)
			if err != nil || last.Execution() != winner {
				t.Fatal("imported fixture did not retain the proved concrete winner", err)
			}
			if err := old.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			fresh := newNodeChainExecutionRuntimeFixtureFromSource(t, source)
			prep := fresh.runtime.projection.preparation
			last, err = ParseNodeChainExecutionLast(last.JSON(), prep)
			if err != nil {
				t.Fatal(err)
			}
			fresh.engine.identity = NodeChainIdentity{"cold-imported-box", "cold-imported-session", "cold-imported-network", prep.SourceSHA256(), prep.ConfigSHA256()}
			// A new measurement could choose either candidate. Last must use only
			// the already proved choice and reprove it with a fresh lease owner.
			fresh.engine.localDelay, fresh.engine.serverDelay = time.Millisecond, time.Millisecond
			owner, err := NewNodeChainExecutionDiscoveryOwner(prep, fresh.engine)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, finish := context.WithTimeout(context.Background(), time.Second)
				defer finish()
				if err := owner.Close(cleanup); err != nil {
					t.Error(err)
				}
			})
			if _, err := owner.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			plan, err := owner.PlanLastContext(ctx, last)
			if err != nil {
				t.Fatal(err)
			}
			projection, err := plan.Projection()
			if err != nil {
				t.Fatal(err)
			}
			request := projection.policy.Request()
			if request.Schema != 2 || !reflect.DeepEqual(request.LocalPacketPositions, []int{0}) || request.SessionID == source.Request.SessionID ||
				reflect.DeepEqual(request.Users, source.Request.Users) || len(request.LocalPacketPublicKeys) != 1 {
				t.Fatal("cold imported discovery reused live authority or fabricated packet identity", request)
			}
			if err := owner.Close(ctx); err != nil {
				t.Fatal(err)
			}
			// Explicit native adoption boundary double: retain the same actual
			// private peers and public TLS endpoint for the fresh captured tags.
			e := fresh.engine
			e.mu.Lock()
			previous := e.projection
			for _, execution := range []string{"local", "server"} {
				before, _ := previous.ProofInventory(execution)
				after, _ := projection.ProofInventory(execution)
				for position, proof := range before {
					address := "1.1.1.1:443"
					if node := previous.policy.local.nodes[position]; node != nil {
						api, _ := privateAPI(predecessorText(node.profile, "router_api"))
						address = api.Host
					}
					e.peers[after[position].Tag+"/"+address] = e.peers[proof.Tag+"/"+address]
				}
			}
			e.projection = projection
			e.identity.SourceSHA256, e.identity.ConfigSHA256 = projection.SourceSHA256(), projection.ConfigSHA256()
			e.mu.Unlock()
			runtime, err := NewNodeChainExecutionLastRuntime(ctx, plan, e)
			if err != nil {
				t.Fatal(err)
			}
			runtime.testTLS, fresh.runtime = fresh.trust, runtime
			if _, err := NewNodeChainExecutionLastRuntime(ctx, plan, e); err == nil {
				t.Fatal("cold imported plan was adopted twice")
			}
			if err := runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			state := runtime.Progress()
			e.mu.Lock()
			selections, proofCount := append([]string(nil), e.selections...), len(e.proofCalls)
			e.mu.Unlock()
			proofs, _ := projection.ProofInventory(winner)
			if !state.Ready || !state.DNSProven || !state.PublicProven || state.Execution != winner || state.Comparison.Target != last.Target() ||
				len(state.Comparison.Measurements) != 0 || len(selections) != 1 || selections[0] != proofs[2].Tag || proofCount < 3 {
				t.Fatal("cold imported Last reran Compare or retained an unproved path", state, selections, proofCount)
			}
		})
	}
}

func TestNodeChainImportedBenchmarkResolutionCannotAuthorizeRawDestination(t *testing.T) {
	_, server, capture := nodeChainImportedServerFixture(t, "wg", "")
	routes, err := server.FrontRoutes(capture)
	if err != nil {
		t.Fatal(err)
	}
	route := routes[0]
	if !route.AllowsResolvedDestination("tcp", hopmeasure.PublicAddress, "93.184.216.34:443") || route.AllowsDestination("tcp", "93.184.216.34:443") {
		t.Fatal("owned hostname result either failed or became a raw grant")
	}
	for _, pair := range []struct{ network, original, resolved string }{
		{"udp", hopmeasure.PublicAddress, "93.184.216.34:443"}, {"tcp", "example.com:443", "93.184.216.34:443"},
		{"tcp", hopmeasure.PublicAddress, "93.184.216.34:444"}, {"tcp", hopmeasure.PublicAddress, "10.77.0.1:443"},
		{"tcp", hopmeasure.PublicAddress, "127.0.0.1:443"}, {"tcp", hopmeasure.PublicAddress, "[::ffff:93.184.216.34]:443"},
	} {
		if route.AllowsResolvedDestination(pair.network, pair.original, pair.resolved) {
			t.Fatal("uncaptured benchmark resolution admitted", pair)
		}
	}
	route.PublicPathBenchmark = false
	if route.AllowsResolvedDestination("tcp", hopmeasure.PublicAddress, "93.184.216.34:443") {
		t.Fatal("ordinary prefix gained resolution authority")
	}
}

func TestNodeChainImportedServerIntersectsOriginalMiddleAndFinalPolicy(t *testing.T) {
	local := nodeChainImportedFixture(t, "wg", "")
	var middle nodeChainImportedInput
	if json.Unmarshal([]byte(local.Nodes[1]), &middle) != nil {
		t.Fatal("middle input")
	}
	var selected externalPolicyCapture
	if json.Unmarshal([]byte(middle.Capture), &selected) != nil {
		t.Fatal("middle capture")
	}
	selected.Profile["home_lan_access"], selected.Profile["home_lan_cidrs"], selected.Profile["ipv6_mode"] = false, []any{"192.168.20.0/24"}, "off"
	var err error
	local.Nodes[1], err = NodeChainImportedMemberInput(middle.Config, startJSON(t, selected))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ParseNodeLaunchInput(local.Nodes[2])
	if err != nil {
		t.Fatal(err)
	}
	profile := predecessorCopy(final.profile)
	profile["home_lan_access"], profile["home_lan_cidrs"] = false, []any{"10.20.0.0/16"}
	final, err = NewNodeProfile(final.mode, final.inputs.Files, startJSON(t, profile), final.inputs.Start, final.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	local.Nodes[2], err = final.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewNodeChain(startJSON(t, local))
	if err != nil {
		t.Fatal(err)
	}
	source := NodeChainServerSource{Schema: 2, EntryID: chain.proofs[0].ProfileID, EntryNodeID: chain.proofs[0].NodeID, EntryMode: "wg",
		Nodes: local.Nodes[1:], IdentitySources: local.IdentitySources[1:]}
	server, err := NewNodeChainServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := server.FrontRoutes(nodeChainServerCaptureFixture(t, server))
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if !route.BlockIPv6 || !reflect.DeepEqual(route.BlockedCIDRs, []string{"10.20.0.0/16", "192.168.20.0/24"}) {
			t.Fatal("one original node's restriction disappeared at the shared front", route)
		}
	}
	if routes[0].AllowsResolvedDestination("tcp", hopmeasure.PublicAddress, "[2606:4700:4700::1111]:443") {
		t.Fatal("imported benchmark bypassed middle IPv6-off")
	}
}
