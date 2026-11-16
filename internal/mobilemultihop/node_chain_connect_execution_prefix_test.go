package mobilemultihop

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func connectExecutionPrefixPlanFixture(t *testing.T, count int, mode, protocol string) (*NodeChainCONNECTSource, map[string]any) {
	t.Helper()
	input := nodeChainCONNECTPrefixFixture(t, count-2, mode, protocol, "", NativeStartLayerMethod, "password")
	original, err := NewNodeChainCONNECTSource(startJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	entry := original.pair.nodes[0]
	plan := map[string]any{"schema": 4, "entry_node_id": entry.profile["node_proof_id"], "entry": map[string]any{"bundle": nodeChainServerPlanBundle(t, entry, input.IdentitySources[0]), "profile_id": entry.profile["id"], "mode": mode}}
	rows := make([]any, 0, count-1)
	for position := 1; position < count; position++ {
		if position == count-2 {
			var middle nodeChainImportedInput
			if exactJSON([]byte(input.Nodes[position]), &middle, NodeChainInputLimit) != nil {
				t.Fatal("original import")
			}
			rows = append(rows, map[string]any{"imported": map[string]any{"config": middle.Config, "capture": middle.Capture}})
			continue
		}
		index := position
		if position == count-1 {
			index--
		}
		node := original.pair.nodes[index]
		bundle := nodeChainServerPlanBundle(t, node, input.IdentitySources[position])
		peer := nodeChainServerPlanPeerBundle(t, bundle, position)
		rows = append(rows, map[string]any{"paired": map[string]any{"bundle": bundle, "profile_id": node.profile["id"], "mode": node.mode}, "server_peer": map[string]any{"bundle": peer, "profile_id": "server-" + node.profile["id"].(string)}})
	}
	plan["members"] = rows
	return original, plan
}

func TestNodeChainCONNECTExecutionCompletePrefixes(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, protocol := range []string{"http-connect", "https-connect"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, mode, protocol), func(t *testing.T) {
					original, plan := connectExecutionPrefixPlanFixture(t, count, mode, protocol)
					server, err := NewNodeChainCONNECTServerPlan(startJSON(t, plan))
					if err != nil {
						t.Fatal("complete original typed server plan", err)
					}
					prep, err := NewNodeChainCONNECTExecutionPreparation(original, "auto")
					if err != nil {
						t.Fatal("complete original typed preparation", err)
					}
					capture := nodeChainServerCaptureFixture(t, server)
					request := capture.Request.Clone()
					request.LocalPacketPublicKeys = nil
					request.LocalPacketPositions = nil
					for i, node := range original.pair.nodes[:len(original.pair.nodes)-1] {
						key, err := node.PacketClientPublicKey()
						if err != nil {
							t.Fatal(err)
						}
						request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, key)
						request.LocalPacketPositions = append(request.LocalPacketPositions, i)
					}
					request.Peer, request.Port = "10.80.0.2", 32003
					input := NodeChainExecutionSource{Schema: 4, Execution: "auto", LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
					policy, err := NewNodeChainCONNECTExecutionPolicy(prep, startJSON(t, input))
					if err != nil {
						t.Fatal("complete original execution policy", err)
					}
					if policy.importedPublicPosition() != count-2 || policy.connect != prep.connect || policy.local != prep.local || len(server.connect.prefixes) != count-3 {
						t.Fatal("original graph ownership or public position lost")
					}
					for i, node := range original.pair.nodes {
						position := i
						if i == len(original.pair.nodes)-1 {
							position++
						}
						if policy.local.nodes[position] != node {
							t.Fatal("original paired pointer replaced", position)
						}
					}
					projection, err := prep.BindExecution(policy)
					if err != nil {
						t.Fatal("complete original execution bind", err)
					}
					for _, choice := range []string{"local", "server"} {
						proofs, err := projection.ProofInventory(choice)
						if err != nil || len(proofs) != count || proofs[count-2].Kind != "public-path" || proofs[count-2].NodeID != "" || proofs[count-1].Mode != "shadowsocks" {
							t.Fatal("complete chosen proof inventory", choice, err)
						}
						dns, err := projection.DNSCapture(choice)
						if err != nil || dns.SelectedTag != proofs[count-1].Tag {
							t.Fatal("chosen final DNS", choice, err)
						}
					}
					bound, err := projection.MTUPlan()
					if err != nil || bound.Ceiling != original.metadata.MTU.Ceiling {
						t.Fatal("complete original MTU envelope", err)
					}
					targets, err := server.ProofTargets(capture)
					if err != nil || len(targets) != count-1 || targets[count-3].Token != "" || targets[count-3].ExpectedPublicIP != original.middle.selection.ExpectedPublicIP || targets[count-2].Token == "" {
						t.Fatal("remote original proof target inventory", err)
					}
					config, err := server.NativeConfig(capture)
					if err != nil {
						t.Fatal(err)
					}
					graph := externalTestRead(t, config)
					for i, proof := range server.proofs {
						row := externalTestFind(t, graph, proof.Tag)
						if i > 0 && row["detour"] != server.proofs[i-1].Tag {
							t.Fatal("remote prefix bypass", i)
						}
					}
					if server.NativeCarrierRequired() != (count > 3) {
						t.Fatal("wrong remote first-carrier family")
					}
					if count > 3 {
						snapshot := serverCarrierSnapshotFixture()
						snapshot.InterfaceMTU = 9000 // Configured fixture capacity, never a PMTU proof.
						carrier := serverCarrierCaptureFixture(t, server, &snapshot)
						projected, err := carrier.ProjectContext(context.Background())
						if err != nil || projected.carrier != carrier || projected.connect == server.connect || projected.Source() != server.Source() || projected.Descriptor().Schema != 4 {
							t.Fatal("typed carrier projection", err)
						}
						if projected.validateCapture() != nil {
							t.Fatal("projected typed carrier source invalid")
						}
					}
					if _, err = NewNodeChainServerPolicy(server.Source()); err == nil {
						t.Fatal("generic parser admitted CONNECT")
					}
					if _, err = NewNodeChainSOCKSServerPolicy(server.Source()); err == nil {
						t.Fatal("SOCKS parser admitted CONNECT")
					}
					desktop, err := NewDesktopNodeChainCONNECTPolicy(original, strings.Repeat("c", 32), "linux", 0)
					if err != nil {
						t.Fatal(err)
					}
					desktopPrep, err := NewDesktopNodeChainCONNECTExecutionPreparation(desktop, "server")
					if err != nil {
						t.Fatal("typed complete desktop preparation", err)
					}
					physical, err := desktopPrep.CONNECTDesktopPhysicalPolicy()
					if err != nil {
						t.Fatal(err)
					}
					read, meta, err := physical.ReadOriginalValidated(desktopPrep)
					if err != nil || read != desktop || len(meta.Prefixes) != count {
						t.Fatal("typed complete original physical owner", err)
					}
					_, _, retained, err := physical.PhysicalReadValidated()
					_, _, before, originalErr := desktop.ReadValidated()
					if err != nil || originalErr != nil || !reflect.DeepEqual(retained.PhysicalRoots, before.PhysicalRoots) {
						t.Fatal("first physical tuple replaced", err, originalErr)
					}
				})
			}
		}
	}
}

func connectExecutionPrefixFixtureSource(t *testing.T, count int, execution string) NodeChainExecutionSource {
	t.Helper()
	original, plan := connectExecutionPrefixPlanFixture(t, count, "wg", "https-connect")
	server, err := NewNodeChainCONNECTServerPlan(startJSON(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	capture := nodeChainServerCaptureFixture(t, server)
	request := capture.Request.Clone()
	request.LocalPacketPublicKeys = nil
	request.LocalPacketPositions = nil
	for i, node := range original.pair.nodes[:len(original.pair.nodes)-1] {
		key, err := node.PacketClientPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, key)
		request.LocalPacketPositions = append(request.LocalPacketPositions, i)
	}
	request.Peer, request.Port = "10.80.0.2", 32003
	return NodeChainExecutionSource{Schema: 4, Execution: execution, LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
}

func TestNodeChainCONNECTExecutionPrefixRuntimeAndStop(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, execution), func(t *testing.T) {
				f := newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionPrefixFixtureSource(t, count, execution))
				// Match the existing complete imported-prefix lifecycle fixture.
				// Individual runtime/proof/observation deadlines remain unchanged.
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if err := f.runtime.Run(ctx); err != nil {
					t.Fatal("complete original CONNECT runtime", err)
				}
				if !f.runtime.Progress().Ready {
					t.Fatal("complete original runtime not ready")
				}
				owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
				measurement, err := f.runtime.NewHopMeasurementContext(ctx, owner)
				if err != nil {
					t.Fatal("complete original selected measurement", err)
				}
				latency, err := measurement.NewLatencyBenchmarkContext(ctx, func(call context.Context) error { return f.runtime.HealthyContext(call) })
				if err != nil {
					t.Fatal("complete original latency capture", err)
				}
				if err = latency.Close(); err != nil {
					t.Fatal(err)
				}
				if err = measurement.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := f.runtime.CaptureRestoreContext(ctx); err != nil {
					t.Fatal("complete original restore receipt", err)
				}
				if err := f.runtime.CloseContext(ctx); err != nil {
					t.Fatal("complete original joined stop", err)
				}
				f.runner.mu.Lock()
				defer f.runner.mu.Unlock()
				if len(f.runner.workers) == 0 {
					t.Fatal("original Manager not acquired")
				}
				for _, worker := range f.runner.workers {
					if worker.Alive() {
						t.Fatal("original worker survived joined stop")
					}
				}
			})
		}
	}
}
func TestNodeChainCONNECTExecutionPrefixRestoreKeepsWinner(t *testing.T) {
	for _, count := range []int{4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			testCONNECTPrefixExecutionRestoreKeepsWinner(t, newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionPrefixFixtureSource(t, count, "auto")))
		})
	}
}
func TestNodeChainCONNECTExecutionPrefixOwnershipRefusals(t *testing.T) {
	for _, fault := range []string{"copied-scope", "equal-prefix", "equal-middle", "foreign-first-key", "missing-prefix-key", "wrong-prefix-position", "changed-source", "lost-uot", "missing-native-observer", "carrier-retired", "equal-carrier"} {
		t.Run(fault, func(t *testing.T) {
			original, plan := connectExecutionPrefixPlanFixture(t, 8, "wg", "https-connect")
			server, err := NewNodeChainCONNECTServerPlan(startJSON(t, plan))
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "copied-scope":
				copy := *server.connect
				server.connect = &copy
			case "equal-prefix":
				node := server.nodes[0]
				fresh, err := NewNodeProfile(node.mode, node.inputs.Files, node.inputs.ProfileJSON, node.inputs.Start, node.inputs.DNSBootstrap)
				if err != nil {
					t.Fatal(err)
				}
				server.nodes[0] = fresh
			case "equal-middle":
				fresh, err := parseNodeChainCONNECTMember(server.connect.middle.input)
				if err != nil {
					t.Fatal(err)
				}
				server.connectMiddle = fresh
			case "changed-source":
				server.sourceJSON += " "
			case "lost-uot":
				graph := externalTestRead(t, server.config)
				delete(externalTestFind(t, graph, server.proofs[len(server.proofs)-1].Tag), "udp_over_tcp")
				server.config = startJSON(t, graph)
			case "carrier-retired", "equal-carrier":
				snapshot := serverCarrierSnapshotFixture()
				snapshot.InterfaceMTU = 9000
				carrier := serverCarrierCaptureFixture(t, server, &snapshot)
				projected, err := carrier.ProjectContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if fault == "equal-carrier" {
					equal := serverCarrierCaptureFixture(t, server, &snapshot)
					projected.carrier = equal
					if projected.validateCapture() == nil {
						t.Fatal("equal replacement borrowed original native carrier")
					}
					return
				}
				snapshot.InterfaceIndex++
				if carrier.CurrentContext(context.Background()) == nil || projected.validateCapture() == nil {
					t.Fatal("retired original carrier granted policy authority")
				}
				return
			case "missing-native-observer":
				f := newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionPrefixFixtureSource(t, 8, "server"))
				if _, err := NewNodeChainExecutionRuntime(f.runtime.projection, connectExecutionMissingObserver{f.engine, f.engine}); err == nil {
					t.Fatal("complete CONNECT graph lost original native observer")
				}
				return
			default:
				input := connectExecutionPrefixFixtureSource(t, 8, "server")
				source, err := NewNodeChainCONNECTSource(input.LocalSource)
				if err != nil {
					t.Fatal(err)
				}
				prep, err := NewNodeChainCONNECTExecutionPreparation(source, "server")
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "foreign-first-key":
					input.Request.LocalPacketPublicKeys[0] = input.Server.Members[0].ClientPublicKey
				case "missing-prefix-key":
					input.Request.LocalPacketPublicKeys = input.Request.LocalPacketPublicKeys[:1]
				case "wrong-prefix-position":
					input.Request.LocalPacketPositions[1]++
				}
				if _, err := NewNodeChainCONNECTExecutionPolicy(prep, startJSON(t, input)); err == nil {
					t.Fatal("foreign complete packet authority accepted")
				}
				return
			}
			if server.validateCapture() == nil {
				t.Fatal("replaced complete original server owner accepted")
			}
			if original.validate() != nil {
				t.Fatal("negative mutated independent Local source")
			}
		})
	}
}

func TestNodeChainCONNECTExecutionProjectionSingleObservationOwnership(t *testing.T) {
	for _, fault := range []string{"original", "copied-binding", "equal-preparation", "foreign-local", "key", "proof", "projection-config"} {
		t.Run(fault, func(t *testing.T) {
			f := newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionPrefixFixtureSource(t, 4, "server"))
			projection := f.runtime.projection
			policy, prep := projection.policy, projection.preparation
			switch fault {
			case "copied-binding":
				copied := *policy.connect
				copied.self = &copied
				policy.connect = &copied
			case "equal-preparation":
				equal, err := ParseNodeChainCONNECTExecutionPreparation(prep.Source())
				if err != nil {
					t.Fatal(err)
				}
				projection.preparation = equal
			case "foreign-local":
				fresh, err := NewNodeChainCONNECTRuntime(prep.connect.source)
				if err != nil {
					t.Fatal(err)
				}
				policy.local = fresh.chain
			case "key":
				policy.source.Request.LocalPacketPublicKeys[0] = policy.source.Request.LocalPacketPublicKeys[1]
			case "proof":
				policy.serverProofs[1].NodeID = "foreign-original"
			case "projection-config":
				projection.config += " "
			}
			proofs, proofErr := projection.ProofInventory("server")
			dns, dnsErr := projection.DNSCapture("server")
			if fault != "original" {
				if proofErr == nil || dnsErr == nil {
					t.Fatal("foreign same-observation capture accepted", fault)
				}
				return
			}
			if proofErr != nil || dnsErr != nil || len(proofs) != 4 || proofs[2].Kind != "public-path" || dns.SelectedTag != proofs[3].Tag {
				t.Fatal("original full observation refused", proofErr, dnsErr)
			}
			proofs[0].Tag = "changed-returned-copy"
			again, err := projection.ProofInventory("server")
			if err != nil || again[0].Tag == proofs[0].Tag {
				t.Fatal("returned proof aliased original inventory", err)
			}
		})
	}
}

func testCONNECTPrefixExecutionRestoreKeepsWinner(t *testing.T, f *nodeChainExecutionRuntimeFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	firstStarted := time.Now()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	capture, err := f.runtime.CaptureRestoreContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next := cloneNodeChainExecutionRuntimeEngine(f.engine)
	if _, err := capture.Source(); err == nil {
		t.Fatal("restore handoff preceded positive original cleanup")
	}
	if _, err := NewNodeChainExecutionRestoreRuntime(capture, next); err == nil {
		t.Fatal("restore reused unjoined original owner")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("initial complete Compare and joined stop %.3fs", time.Since(firstStarted).Seconds())
	// Restore is a subsequent operation after the first has positively joined.
	// It retains the same long-prefix operation bound, not the expired startup context.
	cancel()
	restoreContext, finishRestore := context.WithTimeout(context.Background(), 20*time.Second)
	defer finishRestore()
	ctx = restoreContext
	restoreStarted := time.Now()
	// Native retirement is a separate platform responsibility in this fixture.
	f.engine.mu.Lock()
	f.engine.alive = false
	f.engine.mu.Unlock()
	source, err := capture.Source()
	if err != nil || source != f.runtime.projection.Source() {
		t.Fatal("restore changed original private source", err)
	}
	restored, err := NewNodeChainExecutionRestoreRuntime(capture, next)
	if err != nil {
		t.Fatal(err)
	}
	restored.testTLS = f.trust
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := restored.CloseContext(stop); err != nil {
			t.Error(err)
		}
	})
	f.mu.Lock()
	before := len(f.requests)
	f.mu.Unlock()
	if err := restored.Run(ctx); err != nil {
		t.Fatal(err)
	}
	progress := restored.Progress()
	if !progress.Ready || progress.Execution != capture.execution || progress.Comparison.Target != capture.result.Target || !reflect.DeepEqual(progress.Comparison.Measurements, capture.result.Measurements) {
		t.Fatal("restore reran comparison or replaced previous choice", progress)
	}
	next.mu.Lock()
	selections := append([]string(nil), next.selections...)
	next.mu.Unlock()
	if len(selections) != 1 {
		t.Fatal("restoration opened new trial candidates", selections)
	}
	f.mu.Lock()
	after := append([]struct{ method, session string }(nil), f.requests[before:]...)
	all := append([]struct{ method, session string }(nil), f.requests[:before]...)
	f.mu.Unlock()
	var session string
	puts := 0
	for _, q := range after {
		if q.method == "PUT" {
			puts++
			session = q.session
		}
	}
	expectedPuts := 0
	switch capture.execution {
	case "server":
		expectedPuts = 1
	case "local":
	default:
		t.Fatal("restoration lost selected execution", capture.execution)
	}
	if puts != expectedPuts {
		t.Fatal("restoration created extra trials", after)
	}
	for _, q := range all {
		if q.method == "PUT" && q.session == session {
			t.Fatal("restoration reused a tombstoned acquisition")
		}
	}
	if err := restored.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("subsequent selected restore and joined stop %.3fs", time.Since(restoreStarted).Seconds())
}
