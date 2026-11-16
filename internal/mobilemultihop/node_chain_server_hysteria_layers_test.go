package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nodeChainServerHysteriaLayerFixture(t *testing.T, count int, first, prefixLayer, finalLayer string) ([]*NodeProfile, []*NodeProfile, NodeChainServerSource) {
	t.Helper()
	nodes, _ := nodeChainHysteriaLayerFixture(t, count, first, prefixLayer, finalLayer)
	modes, layers := make([]string, count), make([]string, count)
	for i := range modes {
		modes[i] = "wg"
	}
	identities := nodeChainModeFixtureNodes(t, modes, layers)
	// Standard WG is both selected transport and original identity; its exact
	// captured assets include the fixture packet ceiling. AWG/Hysteria2 retain
	// their separate original standard-WG identity inventory.
	for i, node := range nodes {
		if node.mode == "wg" {
			identities[i] = node
		}
	}
	source := NodeChainServerSource{Schema: 1, EntryID: predecessorText(nodes[0].profile, "id"), EntryNodeID: predecessorText(nodes[0].profile, "node_proof_id"), EntryMode: nodes[0].mode}
	for i, node := range nodes[1:] {
		launch, err := node.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes = append(source.Nodes, launch)
		source.IdentitySources = append(source.IdentitySources, identities[i+1].inputs.Files)
	}
	return nodes, identities, source
}

func testNodeChainServerHysteriaFinalLayers(t *testing.T, count int) {
	for layerIndex, finalLayer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for prefixIndex, prefixLayer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			first := []string{"wg", "awg2-fast", "awg2-strong"}[(layerIndex+prefixIndex)%3]
			name := prefixLayer
			if name == "" {
				name = "off"
			}
			t.Run(name+"/"+finalLayer, func(t *testing.T) {
				nodes, _, source := nodeChainServerHysteriaLayerFixture(t, count, first, prefixLayer, finalLayer)
				before := startJSON(t, source)
				policy, err := NewNodeChainServerPolicy(before)
				if err != nil {
					t.Fatal("original independently layered Hysteria2 Server suffix refused", err)
				}
				capture := nodeChainServerCaptureFixture(t, policy)
				config, err := policy.NativeConfig(capture)
				if err != nil {
					t.Fatal(err)
				}
				graph, proofs := importedPQGraph(t, config), policy.ProofInventory()
				if len(proofs) != count-1 || len(graph["inbounds"].([]any)) != 0 || len(graph["endpoints"].([]any)) != count-2 {
					t.Fatal("layered Server suffix lost original positions or gained a TUN")
				}
				preceding := ""
				if len(proofs) > 1 {
					preceding = proofs[len(proofs)-2].Tag
				}
				assertNodeChainHysteriaLayerClosure(t, graph, nodes[count-1], count-2, proofs[len(proofs)-1].Tag, preceding)
				for i, proof := range proofs {
					member := policy.Descriptor().Members[i]
					layer := prefixLayer
					if i == len(proofs)-1 {
						layer = finalLayer
					}
					if layer == "" {
						layer = "off"
					}
					if proof.Position != i+1 || member.Position != i+1 || proof.SourceSHA256 != nodes[i+1].SourceSHA256() || proof.StartLayer != layer || member.StartLayer != layer || member.NodeID != nodes[i+1].profile["node_proof_id"] {
						t.Fatal("Server layered source moved an original position or identity", i)
					}
				}
				final := policy.Descriptor().Members[len(proofs)-1]
				if final.Mode != "hysteria2" || final.ClientPublicKey != "" || final.ServerPublicKey != "" || final.NodeKind != "" || final.ProofKind != "" {
					t.Fatal("layered paired final acquired external or packet identity")
				}
				dns, err := policy.DNSCapture(capture)
				if err != nil || dns.FinalTag != proofs[len(proofs)-1].Tag || dns.PolicySHA256 != capture.Source.DNSPolicySHA256 {
					t.Fatal("layered Server selected DNS source changed", err)
				}
				found := false
				for _, raw := range importedPQGraph(t, dns.RouterJSON)["servers"].([]any) {
					row := raw.(map[string]any)
					if row["tag"] == dns.ResolverTag {
						found = row["server"] == nodes[count-1].profile["adguard_ipv4"] && row["detour"] == dns.FinalTag && row["type"] == "udp"
					}
				}
				if !found {
					t.Fatal("layered Server DNS bypassed the original final")
				}
				routes, err := policy.FrontRoutes(capture)
				if err != nil || len(routes) != len(proofs) {
					t.Fatal("layered Server lost original restricted front", err)
				}
				for i, route := range routes {
					if route.Tag != proofs[i].Tag || route.Final != (i == len(routes)-1) || !route.Final && route.AllowsDestination("tcp", "198.51.100.77:443") || route.Final && route.UDPOverTCPVersion != 2 {
						t.Fatal("layered Server changed captured front authority")
					}
				}
				reopened, err := NewNodeChainServerPolicy(policy.Source())
				if err != nil || !reflect.DeepEqual(reopened.Descriptor(), policy.Descriptor()) || before != startJSON(t, source) {
					t.Fatal("layered Server source could not reopen exactly", err)
				}
				changed := capture.Clone()
				changed.Source.Members[len(proofs)-1].StartLayer = "off"
				if _, err := policy.NativeConfig(changed); err == nil {
					t.Fatal("Off receipt borrowed layered native Server source")
				}
			})
		}
	}
}

func TestNodeChainServerHysteriaFinalLayers2(t *testing.T) {
	testNodeChainServerHysteriaFinalLayers(t, 2)
}
func TestNodeChainServerHysteriaFinalLayers3(t *testing.T) {
	testNodeChainServerHysteriaFinalLayers(t, 3)
}
func TestNodeChainServerHysteriaFinalLayers4(t *testing.T) {
	testNodeChainServerHysteriaFinalLayers(t, 4)
}
func TestNodeChainServerHysteriaFinalLayers5(t *testing.T) {
	testNodeChainServerHysteriaFinalLayers(t, 5)
}
func TestNodeChainServerHysteriaFinalLayers6(t *testing.T) {
	testNodeChainServerHysteriaFinalLayers(t, 6)
}
func TestNodeChainServerHysteriaFinalLayers7(t *testing.T) {
	testNodeChainServerHysteriaFinalLayers(t, 7)
}
func TestNodeChainServerHysteriaFinalLayers8(t *testing.T) {
	testNodeChainServerHysteriaFinalLayers(t, 8)
}

func TestNodeChainServerHysteriaFinalLayersPlan(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(fmt.Sprintf("%d/%s", count, layer), func(t *testing.T) {
				nodes, identities, _ := nodeChainServerHysteriaLayerFixture(t, count, "awg2-strong", "aes-256-gcm", layer)
				bundles := make([]map[string]any, count)
				for i, node := range nodes {
					identity := identities[i].inputs.Files
					if node.mode == "wg" {
						identity = node.inputs.Files
					}
					bundles[i] = nodeChainServerPlanBundle(t, node, identity)
				}
				plan := map[string]any{"schema": float64(1), "entry_node_id": nodes[0].profile["node_proof_id"], "entry": map[string]any{"bundle": bundles[0], "profile_id": nodes[0].profile["id"], "mode": nodes[0].mode}}
				rows := []any{}
				for i := 1; i < count; i++ {
					rows = append(rows, map[string]any{"paired": map[string]any{"bundle": bundles[i], "profile_id": nodes[i].profile["id"], "mode": nodes[i].mode}, "server_peer": map[string]any{"bundle": nodeChainServerPlanPeerBundle(t, bundles[i], i), "profile_id": "server-" + nodes[i].profile["id"].(string)}})
				}
				plan["members"] = rows
				before := startJSON(t, plan)
				policy, err := NewNodeChainServerPlan(before)
				if err != nil || before != startJSON(t, plan) {
					t.Fatal("layered independent operator plan refused or mutated", err)
				}
				var source NodeChainServerSource
				if json.Unmarshal([]byte(policy.Source()), &source) != nil || len(source.Nodes) != count-1 {
					t.Fatal("layered plan lost complete original suffix")
				}
				for i, identity := range source.IdentitySources {
					var original map[string]any
					if json.Unmarshal([]byte(identity), &original) != nil || reflect.DeepEqual(original, bundles[i+1]["profiles"].(map[string]any)["wg"]) {
						t.Fatal("layered plan borrowed Local provider identity", i)
					}
				}
				final, err := ParseNodeLaunchInput(source.Nodes[count-2])
				if err != nil || final.Config() != nodes[count-1].Config() {
					t.Fatal("independent Server identity changed captured final/outer", err)
				}
				for _, mode := range []string{"hysteria2", "shadowsocks"} {
					changed := importedPQGraph(t, before)
					members := changed["members"].([]any)
					peer := members[len(members)-1].(map[string]any)["server_peer"].(map[string]any)["bundle"].(map[string]any)
					assets := peer["profiles"].(map[string]any)[mode].(map[string]any)
					graph := importedPQGraph(t, string(mustDecodeChainAsset(t, assets["sing-box.json"].(string))))
					graph["outbounds"].([]any)[0].(map[string]any)["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
					assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
					if _, err := NewNodeChainServerPlan(startJSON(t, changed)); err == nil {
						t.Fatal("different Server final/outer credential borrowed captured pairing", mode)
					}
				}
			})
		}
	}
}

func TestNodeChainServerHysteriaFinalLayersExecution(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, execution := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, layer, execution), func(t *testing.T) {
					nodes, identities, _ := nodeChainServerHysteriaLayerFixture(t, count, "awg2-fast", "aes-256-gcm", layer)
					source := nodeChainExecutionFixtureFromNodes(t, nodes, identities, execution)
					prep, err := NewNodeChainExecutionPreparation(source.LocalSource, execution)
					if err != nil {
						t.Fatal("layered original execution preparation refused", err)
					}
					policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
					if err != nil {
						t.Fatal(err)
					}
					projection, err := prep.BindExecution(policy)
					if err != nil || projection.ValidateTransition(prep.Config(), projection.Config()) != nil {
						t.Fatal("layered execution lost original closed-gate transition", err)
					}
					for _, candidate := range []string{"local", "server"} {
						proofs, err := projection.ProofInventory(candidate)
						if err != nil || len(proofs) != count || proofs[count-1].Mode != "hysteria2" || proofs[count-1].StartLayer != layer || proofs[count-1].SourceSHA256 != nodes[count-1].SourceSHA256() || proofs[count-1].NodeID != nodes[count-1].profile["node_proof_id"] {
							t.Fatal("layered execution changed candidate final authority", candidate, err)
						}
						dns, err := projection.DNSCapture(candidate)
						if err != nil || dns.SelectedTag != proofs[count-1].Tag || dns.DNSPolicySHA256 != source.Server.DNSPolicySHA256 || dns.DNS.FinalTag != SelectorTag {
							t.Fatal("layered execution changed selected original DNS", candidate, err)
						}
					}
					original, current := importedPQGraph(t, prep.Config()), importedPQGraph(t, projection.Config())
					if !reflect.DeepEqual(original["inbounds"], current["inbounds"]) || !reflect.DeepEqual(original["endpoints"], current["endpoints"]) || current["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
						t.Fatal("layered execution replaced original TUN/packet owners or opened unproved traffic")
					}
					launch, err := policy.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					reopened, err := ParseNodeChainExecutionLaunchInput(launch)
					if err != nil || reopened.Source() != policy.Source() || reopened.Config() != policy.Config() {
						t.Fatal("layered execution launch changed source", err)
					}
				})
			}
		}
	}
}

func TestNodeChainServerHysteriaFinalLayersRestore(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, winner := range []string{"local", "server"} {
			t.Run(layer+"/"+winner, func(t *testing.T) {
				nodes, identities, _ := nodeChainServerHysteriaLayerFixture(t, 4, "awg2-strong", "aes-256-gcm", layer)
				fixture := newNodeChainExecutionRuntimeFixtureFromSource(t, nodeChainExecutionFixtureFromNodes(t, nodes, identities, "auto"))
				fixture.engine.localDelay, fixture.engine.serverDelay = 200*time.Millisecond, time.Millisecond
				if winner == "local" {
					fixture.engine.localDelay, fixture.engine.serverDelay = time.Millisecond, 200*time.Millisecond
				}
				testNodeChainExecutionRestoreKeepsWinner(t, fixture)
				if fixture.runtime.Progress().Execution != winner {
					t.Fatal("layered restore did not exercise its original concrete winner")
				}
			})
		}
	}
}

func TestNodeChainServerHysteriaFinalLayersLast(t *testing.T) {
	for _, count := range []int{2, 8} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(fmt.Sprintf("%d/%s", count, layer), func(t *testing.T) {
				nodes, identities, _ := nodeChainServerHysteriaLayerFixture(t, count, "awg2-fast", "aes-256-gcm", layer)
				testNodeChainExecutionLastPersistsOnlyBindingsAndFreshlyProvesChoice(t, func(t *testing.T) *nodeChainExecutionRuntimeFixture {
					return newNodeChainExecutionRuntimeFixtureFromSource(t, nodeChainExecutionFixtureFromNodes(t, nodes, identities, "auto"))
				})
			})
		}
	}
}
