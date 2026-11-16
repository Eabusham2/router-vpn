package mobilemultihop

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func nodeChainHostnameExecutionFixture(t *testing.T, prefixes int, mode, method, execution string) (NodeChainExecutionSource, *NodeChainServerPolicy) {
	t.Helper()
	plan, local := nodeChainImportedServerPrefixPlan(t, prefixes, mode, method)
	hostname := nodeChainHostnameFixture(t, mode, method)
	local.Nodes[prefixes] = hostname.Nodes[1]
	var middle nodeChainImportedInput
	if json.Unmarshal([]byte(local.Nodes[prefixes]), &middle) != nil {
		t.Fatal("original hostname import missing")
	}
	plan["members"].([]any)[prefixes-1] = map[string]any{"imported": map[string]any{"config": middle.Config, "capture": middle.Capture}}
	server, err := NewNodeChainServerPlan(startJSON(t, plan))
	if err != nil {
		t.Fatal("hostname suffix with its original preceding packet node refused", err)
	}
	chain, err := NewNodeChain(startJSON(t, local))
	if err != nil {
		t.Fatal(err)
	}
	capture := nodeChainServerCaptureFixture(t, server)
	request := capture.Request.Clone()
	request.LocalPacketPublicKeys, request.LocalPacketPositions = nil, nil
	for position, node := range chain.nodes[:prefixes] {
		key, err := node.PacketClientPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, key)
		request.LocalPacketPositions = append(request.LocalPacketPositions, position)
	}
	request.Peer, request.Port = "10.80.0.2", 32003
	return NodeChainExecutionSource{Schema: 1, Execution: execution, LocalSource: startJSON(t, local),
		Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}, server
}

func nodeChainRequireHostnamePrefixDNS(t *testing.T, raw, middleTag, previousTag, method, finalHost string) {
	t.Helper()
	graph := externalTestRead(t, raw)
	middle := externalTestFind(t, graph, middleTag)
	if middle["server"] != "middle.example.test" || middle["method"] != method || middle["detour"] != previousTag {
		t.Fatal("hostname transport lost its original packet predecessor", middle)
	}
	query, ok := middle["domain_resolver"].(map[string]any)
	if !ok || query["strategy"] != "ipv4_only" {
		t.Fatal("hostname changed its explicitly captured lookup strategy")
	}
	dns := graph["dns"].(map[string]any)
	found := 0
	for _, value := range dns["servers"].([]any) {
		row := value.(map[string]any)
		if row["tag"] == query["server"] {
			found++
			if row["type"] != "tcp" || row["server"] != "10.81.0.53" || row["server_port"] != float64(5353) || row["detour"] != previousTag || row["tag"] == dns["final"] {
				t.Fatal("hostname DNS escaped the captured preceding packet node", row)
			}
		}
		if row["tag"] == dns["final"] && (finalHost == "" || row["server"] != finalHost || row["server_port"] != float64(53) || row["type"] != "udp") {
			t.Fatal("hostname transport DNS replaced selected Home AdGuard", row)
		}
	}
	if found != 1 {
		t.Fatal("hostname DNS transport is missing or duplicated")
	}
}

func TestNodeChainHostnameExecutionRetainsPacketPrefixDNS(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, prefixes := range []int{2, 6} {
			for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
				t.Run(fmt.Sprintf("%s/%d/%s", mode, prefixes+2, method), func(t *testing.T) {
					source, server := nodeChainHostnameExecutionFixture(t, prefixes, mode, method, "auto")
					if !server.NativeCarrierRequired() || server.importedMiddle.policy != nil || server.importedMiddle.hostname == nil {
						t.Fatal("hostname acquired standalone or unowned physical authority")
					}
					native, err := server.NativeConfig(nodeChainServerCaptureFixture(t, server))
					if err != nil {
						t.Fatal(err)
					}
					finalHost := predecessorText(server.nodes[len(server.nodes)-1].profile, "adguard_ipv4")
					nodeChainRequireHostnamePrefixDNS(t, native, server.proofs[prefixes-1].Tag, server.proofs[prefixes-2].Tag, method, finalHost)
					policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
					if err != nil {
						t.Fatal(err)
					}
					prep, err := NewNodeChainExecutionPreparation(source.LocalSource, source.Execution)
					if err != nil || prep.importedPublic == nil || !prep.importedPublic.current(prep) {
						t.Fatal("hostname preparation lost its original public measurement source", err)
					}
					projection, err := prep.BindExecution(policy)
					if err != nil {
						t.Fatal(err)
					}
					nodeChainRequireHostnamePrefixDNS(t, projection.Config(), prep.local.proofs[prefixes].Tag, prep.local.proofs[prefixes-1].Tag, method, finalHost)
					for _, candidate := range []string{"local", "server"} {
						proofs, err := projection.ProofInventory(candidate)
						if err != nil || len(proofs) != prefixes+2 {
							t.Fatal("hostname candidate lost its complete proof inventory", err)
						}
						tag, ipv6, err := projection.ImportedPublicMeasurementCapture(candidate)
						if err != nil || tag != proofs[prefixes].Tag || ipv6 || policy.importedPublicPosition() != prefixes {
							t.Fatal("hostname measurement substituted a candidate prefix or device policy", err)
						}
					}
					local, projected := externalTestRead(t, prep.local.Config()), externalTestRead(t, projection.Config())
					if !reflect.DeepEqual(local["endpoints"], projected["endpoints"]) || !reflect.DeepEqual(local["inbounds"], projected["inbounds"]) {
						t.Fatal("hostname execution replaced the original TUN or packet endpoints")
					}
					if _, err := projection.MTUPlan(); err != nil {
						t.Fatal("hostname execution lost its original complete MTU plan", err)
					}
				})
			}
		}
	}
}

func TestNodeChainHostnameExecutionRejectsUnownedDNS(t *testing.T) {
	t.Run("no-server-packet-prefix", func(t *testing.T) {
		local := nodeChainHostnameFixture(t, "wg", NativeStartLayerMethod)
		for _, execution := range []string{"server", "auto"} {
			if _, err := NewNodeChainExecutionPreparation(startJSON(t, local), execution); err == nil {
				t.Fatal("hostname without a retained Server packet prefix gained execution authority")
			}
		}
		plan, _ := nodeChainImportedServerPrefixPlan(t, 1, "wg", NativeStartLayerMethod)
		var middle nodeChainImportedInput
		if json.Unmarshal([]byte(local.Nodes[1]), &middle) != nil {
			t.Fatal("hostname source missing")
		}
		plan["members"].([]any)[0] = map[string]any{"imported": map[string]any{"config": middle.Config, "capture": middle.Capture}}
		if _, err := NewNodeChainServerPlan(startJSON(t, plan)); err == nil {
			t.Fatal("hostname without a retained Server packet prefix gained execution authority")
		}
	})
	t.Run("copied-hostname-owner", func(t *testing.T) {
		source, _ := nodeChainHostnameExecutionFixture(t, 2, "wg", NativeStartLayerMethod, "server")
		policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
		if err != nil {
			t.Fatal(err)
		}
		prep, err := NewNodeChainExecutionPreparation(source.LocalSource, source.Execution)
		if err != nil {
			t.Fatal(err)
		}
		projection, err := prep.BindExecution(policy)
		if err != nil {
			t.Fatal(err)
		}
		copied := *prep.local.importedMiddle.hostname
		prep.local.importedMiddle.hostname = &copied
		for _, candidate := range []string{"local", "server"} {
			if _, _, err := projection.ImportedPublicMeasurementCapture(candidate); err == nil {
				t.Fatal("copied hostname owner acquired original measurement authority")
			}
		}
	})
}

// The engine is the existing explicit ownership double. These cases exercise
// real loopback proof/probe requests, candidate scoring and restore ownership;
// the required encrypted Server gate separately witnesses hostname DNS/traffic.
func TestNodeChainHostnameExecutionComparesAndRestores(t *testing.T) {
	for _, scenario := range []struct {
		prefixes int
		setting  string
		winner   string
	}{{2, "server", "server"}, {2, "auto", "local"}, {6, "auto", "server"}} {
		t.Run(fmt.Sprintf("%d/%s/%s", scenario.prefixes+2, scenario.setting, scenario.winner), func(t *testing.T) {
			source, _ := nodeChainHostnameExecutionFixture(t, scenario.prefixes, "wg", NativeStartLayerMethod, scenario.setting)
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
			progress := f.runtime.Progress()
			if !progress.Ready || !progress.DNSProven || !progress.PublicProven || progress.Execution != scenario.winner || len(progress.Prefixes) != scenario.prefixes+2 || progress.Comparison.Final == nil {
				t.Fatal("hostname candidate did not prove its complete captured path", progress)
			}
			if scenario.setting == "auto" && len(progress.Comparison.Measurements) != 2 {
				t.Fatal("hostname Compare omitted a required candidate")
			}
			for _, value := range append(progress.Comparison.Measurements, *progress.Comparison.Final) {
				if !value.Eligible || value.ScoreMS == nil || *value.ScoreMS != (value.LastNodeMS+value.ExternalMS)/2 {
					t.Fatal("hostname Compare replaced the two-probe arithmetic mean")
				}
			}
			last, err := f.runtime.CaptureLastContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseNodeChainExecutionLast(last.JSON(), f.runtime.projection.preparation)
			if err != nil || parsed.Execution() != scenario.winner {
				t.Fatal("hostname durable choice lost its original preparation", err)
			}
			capture, err := f.runtime.CaptureRestoreContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			next := cloneNodeChainExecutionRuntimeEngine(f.engine)
			if _, err := NewNodeChainExecutionRestoreRuntime(capture, next); err == nil {
				t.Fatal("hostname replacement acquired an unjoined original path")
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			cancel()
			f.engine.mu.Lock()
			f.engine.alive = false
			f.engine.mu.Unlock()
			// Restore is a subsequent lifecycle operation after the original
			// has positively joined, with the unchanged long-path test bound.
			restoreContext, finishRestore := context.WithTimeout(t.Context(), 20*time.Second)
			defer finishRestore()
			restored, err := NewNodeChainExecutionRestoreRuntime(capture, next)
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
			if err := restored.Run(restoreContext); err != nil {
				t.Fatal(err)
			}
			fresh := restored.Progress()
			next.mu.Lock()
			selections := append([]string(nil), next.selections...)
			next.mu.Unlock()
			if !fresh.Ready || fresh.Execution != scenario.winner || fresh.Comparison.Target != progress.Comparison.Target || !reflect.DeepEqual(fresh.Comparison.Measurements, progress.Comparison.Measurements) || len(selections) != 1 {
				t.Fatal("hostname restore reran Compare or changed its captured choice", fresh, selections)
			}
			if err := restored.CloseContext(restoreContext); err != nil {
				t.Fatal(err)
			}
			finishRestore()
		})
	}
}

func TestNodeChainHostnameExecutionRejectsFailedOriginalPacketProof(t *testing.T) {
	source, _ := nodeChainHostnameExecutionFixture(t, 2, "wg", NativeStartLayerMethod, "server")
	f := newNodeChainExecutionRuntimeFixtureFromSource(t, source)
	f.engine.wrongPrefix = 1
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err == nil {
		t.Fatal("hostname path opened after an incorrect retained packet proof")
	}
	f.engine.mu.Lock()
	open := f.engine.open
	f.engine.mu.Unlock()
	if open || f.runtime.Progress().Ready {
		t.Fatal("failed hostname packet proof retained application admission")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
}
