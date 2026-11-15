package mobilemultihop

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nodeChainImportedPrefixExecutionSource(t *testing.T, count int, mode, execution string) NodeChainExecutionSource {
	t.Helper()
	plan, local := nodeChainImportedServerPrefixPlan(t, count, mode, NativeStartLayerMethod)
	server, err := NewNodeChainServerPlan(startJSON(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewNodeChain(startJSON(t, local))
	if err != nil {
		t.Fatal(err)
	}
	capture := nodeChainServerCaptureFixture(t, server)
	q := capture.Request.Clone()
	q.LocalPacketPublicKeys = nil
	q.LocalPacketPositions = nil
	for position, node := range chain.nodes[:count] {
		key, err := node.PacketClientPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		q.LocalPacketPublicKeys = append(q.LocalPacketPublicKeys, key)
		q.LocalPacketPositions = append(q.LocalPacketPositions, position)
	}
	q.Peer, q.Port = "10.80.0.2", 32003
	return NodeChainExecutionSource{Schema: 1, Execution: execution, LocalSource: startJSON(t, local), Server: server.Descriptor(), Request: q, FirstPort: 32000, LastPort: 32007}
}

func TestNodeChainImportedPrefixExecutionCapturesEveryOriginalPosition(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, count := range []int{2, 3, 6} {
			for _, execution := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%s/%d/%s", mode, count, execution), func(t *testing.T) {
					source := nodeChainImportedPrefixExecutionSource(t, count, mode, execution)
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
					if policy.importedPublicPosition() != count {
						t.Fatal("public proof moved")
					}
					for _, kind := range []string{"local", "server"} {
						proofs, err := projection.ProofInventory(kind)
						if err != nil || len(proofs) != count+2 {
							t.Fatal("complete proof inventory", err)
						}
						for position, proof := range proofs {
							if proof.Position != position || (proof.Kind == "public-path") != (position == count) || (proof.NodeID == "") != (position == count) {
								t.Fatal("captured private/public identity changed", position)
							}
						}
					}
					original := externalTestRead(t, prep.local.Config())
					graph := externalTestRead(t, projection.Config())
					if !reflect.DeepEqual(original["inbounds"], graph["inbounds"]) || !reflect.DeepEqual(original["endpoints"], graph["endpoints"]) {
						t.Fatal("original TUN or packet transport replaced")
					}
					if _, err := projection.MTUPlan(); err != nil {
						t.Fatal(err)
					}
					discovery := nodeChainExecutionDiscoveryFixture(policy, time.Now())
					fresh, err := prep.policyForDiscovery(source.Server, discovery, source.Request.Port)
					if err != nil {
						t.Fatal("authenticated discovery plan", err)
					}
					q := fresh.Request()
					if !reflect.DeepEqual(q.LocalPacketPositions, source.Request.LocalPacketPositions) || !reflect.DeepEqual(q.LocalPacketPublicKeys, source.Request.LocalPacketPublicKeys) || q.SessionID == source.Request.SessionID || reflect.DeepEqual(q.Users, source.Request.Users) {
						t.Fatal("discovery reused session or lost packet positions")
					}
					launch, err := policy.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					replay, err := ParseNodeChainExecutionLaunchInput(launch)
					if err != nil || replay.Config() != policy.Config() {
						t.Fatal("original execution replay changed", err)
					}
				})
			}
		}
	}
}

func TestNodeChainImportedPrefixExecutionRejectsSubstitutedAuthority(t *testing.T) {
	original := nodeChainImportedPrefixExecutionSource(t, 4, "awg2-fast", "auto")
	for name, mutate := range map[string]func(*NodeChainExecutionSource){
		"public-source": func(s *NodeChainExecutionSource) { s.Server.Members[3].SourceSHA256 = strings.Repeat("b", 64) },
		"public-egress": func(s *NodeChainExecutionSource) { s.Server.Members[3].ExpectedPublicIP = "203.0.113.89" },
		"earlier-server-key": func(s *NodeChainExecutionSource) {
			s.Server.Members[1].ClientPublicKey = s.Request.LocalPacketPublicKeys[2]
		},
		"earlier-packet-position": func(s *NodeChainExecutionSource) { s.Request.LocalPacketPositions[1] = 2 },
		"missing-packet-pin": func(s *NodeChainExecutionSource) {
			s.Request.LocalPacketPositions = s.Request.LocalPacketPositions[:3]
			s.Request.LocalPacketPublicKeys = s.Request.LocalPacketPublicKeys[:3]
		},
		"typed-schema": func(s *NodeChainExecutionSource) { s.Server.Schema = 3; s.Request.Schema = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			var source NodeChainExecutionSource
			if json.Unmarshal([]byte(startJSON(t, original)), &source) != nil {
				t.Fatal("source")
			}
			mutate(&source)
			if digest, err := source.Server.Digest(); err == nil {
				source.Request.DescriptorSHA256 = digest
			}
			if _, err := NewNodeChainExecutionPolicy(startJSON(t, source)); err == nil {
				t.Fatal("changed original authority accepted")
			}
		})
	}
}

// The native boundary is an explicit owner double. Actual HTTP/TLS proofs,
// lease validation, Compare scoring, public positioning and cleanup run here;
// encrypted traffic and host carrier admission remain mandatory native gates.
func TestNodeChainImportedPrefixExecutionRunsCompleteComparisonAndMeasurement(t *testing.T) {
	for _, scenario := range []struct {
		count             int
		execution, winner string
	}{{2, "server", "server"}, {3, "auto", "server"}, {3, "auto", "local"}, {6, "server", "server"}} {
		t.Run(fmt.Sprintf("%d/%s/%s", scenario.count, scenario.execution, scenario.winner), func(t *testing.T) {
			source := nodeChainImportedPrefixExecutionSource(t, scenario.count, "wg", scenario.execution)
			f := newNodeChainExecutionRuntimeFixtureFromSource(t, source)
			if scenario.winner == "local" {
				f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 100*time.Millisecond
			} else {
				f.engine.localDelay, f.engine.serverDelay = 100*time.Millisecond, time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			state := f.runtime.Progress()
			if !state.Ready || !state.DNSProven || !state.PublicProven || state.Execution != scenario.winner || len(state.Prefixes) != scenario.count+2 || state.Comparison.Final == nil {
				t.Fatal("complete selected path not proved", state)
			}
			if scenario.execution == "auto" && len(state.Comparison.Measurements) != 2 {
				t.Fatal("Compare omitted original candidate")
			}
			for _, m := range append(state.Comparison.Measurements, *state.Comparison.Final) {
				if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != (m.LastNodeMS+m.ExternalMS)/2 {
					t.Fatal("two-probe mean changed", m)
				}
			}
			saved, err := f.runtime.CaptureLastContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			last, err := ParseNodeChainExecutionLast(saved.JSON(), f.runtime.projection.preparation)
			if err != nil || last.Execution() != state.Execution {
				t.Fatal("captured concrete choice lost", err)
			}
			owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
			measurement, err := f.runtime.NewHopMeasurementContext(ctx, owner)
			if err != nil {
				t.Fatal("positional selected measurement", err)
			}
			latency, err := measurement.NewLatencyBenchmarkContext(ctx, func(call context.Context) error { return f.runtime.HealthyContext(call) })
			if err != nil {
				t.Fatal("positional latency capture", err)
			}
			var capture struct {
				Nodes []nodeChainExecutionLatencyHop `json:"nodes"`
			}
			if json.Unmarshal([]byte(latency.CaptureJSON()), &capture) != nil || len(capture.Nodes) != scenario.count+2 {
				t.Fatal("latency lost complete inventory")
			}
			for i, node := range capture.Nodes {
				if node.Position != i || (node.Kind == "public-path") != (i == scenario.count) {
					t.Fatal("latency relabelled original proof", i)
				}
			}
			if err := latency.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			if err := measurement.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal("joined exact lease cleanup", err)
			}
			f.engine.mu.Lock()
			open, stops := f.engine.open, f.engine.stops
			f.engine.mu.Unlock()
			if open || stops != 0 {
				t.Fatal("retirement lost original native stop", open, stops)
			}
		})
	}
}

func TestNodeChainImportedPrefixExecutionRefusesEarlierPrivateFailure(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixtureFromSource(t, nodeChainImportedPrefixExecutionSource(t, 3, "wg", "server"))
	f.engine.wrongPrefix = 1
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err == nil {
		t.Fatal("wrong earlier private prefix reached application admission")
	}
	f.engine.mu.Lock()
	open := f.engine.open
	f.engine.mu.Unlock()
	if open || f.runtime.Progress().Ready {
		t.Fatal("failed earlier prefix left application open")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("failed proof original lease cleanup", err)
	}
}

func TestNodeChainImportedPrefixExecutionRetainsFailedServerClose(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixtureFromSource(t, nodeChainImportedPrefixExecutionSource(t, 2, "wg", "auto"))
	f.runner.failStop.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err == nil {
		t.Fatal("unjoined longer Server trial started winner")
	}
	f.engine.mu.Lock()
	selections, opens, stops := len(f.engine.selections), f.engine.opens, f.engine.stops
	f.engine.mu.Unlock()
	if selections != 2 || opens != 0 || stops != 1 {
		t.Fatal("failed close dropped original authority", selections, opens, stops)
	}
	if err := f.runtime.CloseContext(ctx); err == nil {
		t.Fatal("unjoined original Server close acknowledged")
	}
	f.runner.failStop.Store(false)
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("same retained close could not retry", err)
	}
	f.engine.mu.Lock()
	stops = f.engine.stops
	f.engine.mu.Unlock()
	if stops != 0 {
		t.Fatal("original native close leaked")
	}
}
