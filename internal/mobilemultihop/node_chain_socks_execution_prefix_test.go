package mobilemultihop

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func socksExecutionPrefixPlanFixture(t *testing.T, count int, mode, authentication string) (*NodeChainSOCKSSource, map[string]any) {
	t.Helper()
	input := nodeChainSOCKSPrefixFixture(t, count-2, mode, "", authentication)
	original, err := NewNodeChainSOCKSSource(startJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	entry := original.pair.nodes[0]
	plan := map[string]any{"schema": 3, "entry_node_id": entry.profile["node_proof_id"], "entry": map[string]any{"bundle": nodeChainServerPlanBundle(t, entry, input.IdentitySources[0]), "profile_id": entry.profile["id"], "mode": mode}}
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

func TestNodeChainSOCKSExecutionPrefixesWG(t *testing.T) { testSOCKSExecutionCompletePrefixes(t, "wg") }
func TestNodeChainSOCKSExecutionPrefixesFast(t *testing.T) {
	testSOCKSExecutionCompletePrefixes(t, "awg2-fast")
}
func TestNodeChainSOCKSExecutionPrefixesStrong(t *testing.T) {
	testSOCKSExecutionCompletePrefixes(t, "awg2-strong")
}
func testSOCKSExecutionCompletePrefixes(t *testing.T, mode string) {
	for count := 3; count <= 8; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			auth := "password"
			if count%2 == 0 {
				auth = "none"
			}
			original, plan := socksExecutionPrefixPlanFixture(t, count, mode, auth)
			server, err := NewNodeChainSOCKSServerPlan(startJSON(t, plan))
			if err != nil {
				t.Fatal("complete original typed server plan", err)
			}
			prep, err := NewNodeChainSOCKSExecutionPreparation(original, "auto")
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
			input := NodeChainExecutionSource{Schema: 3, Execution: "auto", LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
			policy, err := NewNodeChainSOCKSExecutionPolicy(prep, startJSON(t, input))
			if err != nil {
				t.Fatal("complete original execution policy", err)
			}
			if policy.importedPublicPosition() != count-2 || policy.socks != prep.socks || policy.local != prep.local || len(server.socks.prefixes) != count-3 {
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
			middle := externalTestFind(t, graph, server.proofs[count-3].Tag)
			final := externalTestFind(t, graph, server.proofs[count-2].Tag)
			if middle["type"] != "socks" || middle["version"] != "5" || middle["udp_over_tcp"] != nil || final["udp_over_tcp"] != nil {
				t.Fatal("original association was converted to UoT")
			}
			device, err := server.SOCKSServerDevice(capture)
			if err != nil || device.Position != count-2 || device.ProfileID != original.metadata.Proofs[count-2].ProfileID {
				t.Fatal("original SOCKS device position changed", err)
			}
			freshConfig, freshDevice, freshProofs, err := server.ReadSOCKSServerCapture(capture)
			if err != nil || freshConfig != config || freshDevice != device || !reflect.DeepEqual(freshProofs, server.ProofInventory()) {
				t.Fatal("fresh original native observation changed", err)
			}
			freshProofs[0].Tag = "changed-returned-proof"
			_, _, readAgain, err := server.ReadSOCKSServerCapture(capture)
			if err != nil || readAgain[0].Tag == freshProofs[0].Tag {
				t.Fatal("fresh native observation aliased its proof inventory", err)
			}
			foreign := capture
			foreign.Request = capture.Request.Clone()
			foreign.Request.LocalPacketPublicKeys[0] = "foreign-original-key"
			badConfig, badDevice, badProofs, err := server.ReadSOCKSServerCapture(foreign)
			if err == nil || badConfig != "" || badDevice != (NodeChainSOCKSDevicePolicy{}) || badProofs != nil {
				t.Fatal("fresh observation borrowed a changed original lease")
			}
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
				if err != nil || projected.carrier != carrier || projected.socks == server.socks || projected.Source() != server.Source() || projected.Descriptor().Schema != 3 {
					t.Fatal("typed carrier projection", err)
				}
				if projected.validateCapture() != nil {
					t.Fatal("projected typed carrier source invalid")
				}
			}
			if _, err = NewNodeChainServerPolicy(server.Source()); err == nil {
				t.Fatal("generic parser admitted SOCKS")
			}
			if _, err = NewNodeChainCONNECTServerPolicy(server.Source()); err == nil {
				t.Fatal("CONNECT parser admitted SOCKS")
			}

		})
	}
}

func socksExecutionPrefixFixtureSource(t *testing.T, count int, execution string) NodeChainExecutionSource {
	t.Helper()
	original, plan := socksExecutionPrefixPlanFixture(t, count, "wg", "password")
	server, err := NewNodeChainSOCKSServerPlan(startJSON(t, plan))
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
	return NodeChainExecutionSource{Schema: 3, Execution: execution, LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
}

func TestNodeChainSOCKSExecutionPrefixRuntimeAndStop(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, execution), func(t *testing.T) {
				f := newNodeChainExecutionRuntimeFixtureFromSource(t, socksExecutionPrefixFixtureSource(t, count, execution))
				// Match the existing complete imported-prefix lifecycle fixture.
				// Individual runtime/proof/observation deadlines remain unchanged.
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if err := f.runtime.Run(ctx); err != nil {
					t.Fatal("complete original SOCKS runtime", err)
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
func TestNodeChainSOCKSExecutionPrefixRestoreKeepsWinner(t *testing.T) {
	for _, count := range []int{4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			testCONNECTPrefixExecutionRestoreKeepsWinner(t, newNodeChainExecutionRuntimeFixtureFromSource(t, socksExecutionPrefixFixtureSource(t, count, "auto")))
		})
	}
}
func TestNodeChainSOCKSExecutionPrefixOwnershipRefusals(t *testing.T) {
	for _, fault := range []string{"copied-scope", "equal-prefix", "equal-middle", "foreign-first-key", "missing-prefix-key", "wrong-prefix-position", "changed-source", "injected-uot", "missing-native-observer", "carrier-retired", "equal-carrier"} {
		t.Run(fault, func(t *testing.T) {
			original, plan := socksExecutionPrefixPlanFixture(t, 8, "wg", "password")
			server, err := NewNodeChainSOCKSServerPlan(startJSON(t, plan))
			if err != nil {
				t.Fatal(err)
			}
			capture := nodeChainServerCaptureFixture(t, server)
			switch fault {
			case "copied-scope":
				copy := *server.socks
				server.socks = &copy
			case "equal-prefix":
				node := server.nodes[0]
				fresh, err := NewNodeProfile(node.mode, node.inputs.Files, node.inputs.ProfileJSON, node.inputs.Start, node.inputs.DNSBootstrap)
				if err != nil {
					t.Fatal(err)
				}
				server.nodes[0] = fresh
			case "equal-middle":
				fresh, err := parseNodeChainSOCKSMember(server.socks.middle.input)
				if err != nil {
					t.Fatal(err)
				}
				server.socksMiddle = fresh
			case "changed-source":
				server.sourceJSON += " "
			case "injected-uot":
				graph := externalTestRead(t, server.config)
				externalTestFind(t, graph, server.proofs[len(server.proofs)-1].Tag)["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
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
				f := newNodeChainExecutionRuntimeFixtureFromSource(t, socksExecutionPrefixFixtureSource(t, 8, "server"))
				if _, err := NewNodeChainExecutionRuntime(f.runtime.projection, socksExecutionMissingObserver{f.engine, f.engine}); err == nil {
					t.Fatal("complete SOCKS graph lost original native observer")
				}
				return
			default:
				input := socksExecutionPrefixFixtureSource(t, 8, "server")
				source, err := NewNodeChainSOCKSSource(input.LocalSource)
				if err != nil {
					t.Fatal(err)
				}
				prep, err := NewNodeChainSOCKSExecutionPreparation(source, "server")
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
				if _, err := NewNodeChainSOCKSExecutionPolicy(prep, startJSON(t, input)); err == nil {
					t.Fatal("foreign complete packet authority accepted")
				}
				return
			}
			if server.validateCapture() == nil {
				t.Fatal("replaced complete original server owner accepted")
			}
			config, device, proofs, err := server.ReadSOCKSServerCapture(capture)
			if err == nil || config != "" || device != (NodeChainSOCKSDevicePolicy{}) || proofs != nil {
				t.Fatal("fresh native observation retained replaced source authority")
			}
			if original.validate() != nil {
				t.Fatal("negative mutated independent Local source")
			}
		})
	}
}

func TestNodeChainSOCKSExecutionProjectionSingleObservationOwnership(t *testing.T) {
	for _, fault := range []string{"original", "copied-binding", "equal-preparation", "foreign-local", "key", "proof", "projection-config"} {
		t.Run(fault, func(t *testing.T) {
			f := newNodeChainExecutionRuntimeFixtureFromSource(t, socksExecutionPrefixFixtureSource(t, 4, "server"))
			projection := f.runtime.projection
			policy, prep := projection.policy, projection.preparation
			switch fault {
			case "copied-binding":
				copied := *policy.socks
				copied.self = &copied
				policy.socks = &copied
			case "equal-preparation":
				equal, err := ParseNodeChainSOCKSExecutionPreparation(prep.Source())
				if err != nil {
					t.Fatal(err)
				}
				projection.preparation = equal
			case "foreign-local":
				fresh, err := NewNodeChainSOCKSRuntime(prep.socks.source)
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
