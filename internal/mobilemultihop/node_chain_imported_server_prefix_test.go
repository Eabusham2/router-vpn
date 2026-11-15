package mobilemultihop

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func nodeChainImportedServerPrefixPlan(t *testing.T, count int, mode, method string, layers ...string) (map[string]any, NodeChainSource) {
	t.Helper()
	local := nodeChainImportedSSPrefixFixture(t, count, mode, method, false)
	if len(layers) > 0 {
		paired := nodeChainSOCKSPrefixFixture(t, count, mode, layers[0], "password")
		paired.Schema, paired.Nodes[count] = 2, local.Nodes[count]
		local = paired
	}
	entry, err := ParseNodeLaunchInput(local.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"schema": 1, "entry_node_id": entry.profile["node_proof_id"], "entry": map[string]any{"bundle": nodeChainServerPlanBundle(t, entry, local.IdentitySources[0]), "profile_id": entry.profile["id"], "mode": entry.mode}}
	var rows []any
	for i := 1; i < len(local.Nodes); i++ {
		if i == count {
			var imported nodeChainImportedInput
			if json.Unmarshal([]byte(local.Nodes[i]), &imported) != nil {
				t.Fatal("missing original import")
			}
			rows = append(rows, map[string]any{"imported": map[string]any{"config": imported.Config, "capture": imported.Capture}})
			continue
		}
		node, err := ParseNodeLaunchInput(local.Nodes[i])
		if err != nil {
			t.Fatal(err)
		}
		bundle := nodeChainServerPlanBundle(t, node, local.IdentitySources[i])
		rows = append(rows, map[string]any{"paired": map[string]any{"bundle": bundle, "profile_id": node.profile["id"], "mode": node.mode}, "server_peer": map[string]any{"bundle": nodeChainServerPlanPeerBundle(t, bundle, i), "profile_id": "server-" + node.profile["id"].(string)}})
	}
	plan["members"] = rows
	return plan, local
}

func TestNodeChainImportedServerCompletePacketPrefixes(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
			for count := 1; count <= 6; count++ {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, method, count), func(t *testing.T) {
					plan, local := nodeChainImportedServerPrefixPlan(t, count, mode, method)
					policy, err := NewNodeChainServerPlan(startJSON(t, plan))
					if err != nil {
						t.Fatal("original independent suffix refused", err)
					}
					capture := nodeChainServerCaptureFixture(t, policy)
					if len(policy.nodes) != count+1 || policy.importedMiddle.input != local.Nodes[count] || policy.nodes[count-1] != nil || policy.NativeCarrierRequired() != (count > 1) {
						t.Fatal("source, position or native carrier lost")
					}
					config, err := policy.NativeConfig(capture)
					if err != nil {
						t.Fatal(err)
					}
					graph := externalTestRead(t, config)
					if len(graph["inbounds"].([]any)) != 0 || len(graph["endpoints"].([]any)) != count-1 {
						t.Fatal("listener-free native prefix inventory changed")
					}
					routes, err := policy.FrontRoutes(capture)
					if err != nil {
						t.Fatal(err)
					}
					for i, proof := range policy.proofs {
						out := externalTestFind(t, graph, proof.Tag)
						if proof.Position != i+1 || i > 0 && out["detour"] != policy.proofs[i-1].Tag || routes[i].Position != i+1 || routes[i].Final != (i == count) {
							t.Fatal("positional proof/front or detour changed", i)
						}
						target := policy.proofTargets[i]
						if i == count-1 {
							if proof.Kind != "public-path" || proof.NodeID != "" || target.API != "" || target.Token != "" || out["method"] != method || !routes[i].PublicPathBenchmark {
								t.Fatal("import borrowed private identity or method")
							}
						} else if target.API == "" || target.Token == "" || proof.NodeID == "" || routes[i].PublicPathBenchmark {
							t.Fatal("paired owner lost private proof", i)
						}
						if i < count-1 {
							original, err := ParseNodeLaunchInput(local.Nodes[i+1])
							if err != nil {
								t.Fatal(err)
							}
							key, _ := original.PacketClientPublicKey()
							serverKey, _ := policy.nodes[i].PacketClientPublicKey()
							if key == serverKey || local.IdentitySources[i+1] == policy.nodes[i].inputs.Files {
								t.Fatal("Local identity copied into Server")
							}
						}
					}
					if policy.dns.FinalTag != policy.proofs[count].Tag || !routes[count].Final || routes[count].UDPOverTCPVersion != 2 {
						t.Fatal("final DNS or authenticated UDP moved")
					}
					if count > 1 {
						snapshot := serverCarrierSnapshotFixture()
						snapshot.InterfaceMTU = 9000
						projected, err := serverCarrierCaptureFixture(t, policy, &snapshot).ProjectContext(context.Background())
						if err != nil {
							t.Fatal("native carrier projection", err)
						}
						if projected.carrier == nil || projected.Source() != policy.Source() || !reflect.DeepEqual(projected.ProofInventory(), policy.ProofInventory()) {
							t.Fatal("carrier projection changed original source/proofs")
						}
						snapshot.NamespaceInode++
						if projected.carrier.CurrentContext(context.Background()) == nil || projected.validateCapture() == nil {
							t.Fatal("changed carrier retained native authority")
						}
					}
				})
			}
		}
	}
}

func TestNodeChainImportedServerPrefixRefusesChangedRolesAndOwners(t *testing.T) {
	plan, _ := nodeChainImportedServerPrefixPlan(t, 4, "awg2-fast", NativeStartLayerMethod)
	policy, err := NewNodeChainServerPlan(startJSON(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	var original NodeChainServerSource
	if json.Unmarshal([]byte(policy.Source()), &original) != nil {
		t.Fatal("source")
	}
	for name, mutate := range map[string]func(*NodeChainServerSource){
		"import-first": func(s *NodeChainServerSource) {
			s.Nodes[0], s.Nodes[3] = s.Nodes[3], s.Nodes[0]
			s.IdentitySources[0], s.IdentitySources[3] = s.IdentitySources[3], s.IdentitySources[0]
		},
		"missing-prefix-identity":  func(s *NodeChainServerSource) { s.IdentitySources[1] = "" },
		"borrowed-import-identity": func(s *NodeChainServerSource) { s.IdentitySources[3] = s.IdentitySources[0] },
		"duplicate-prefix":         func(s *NodeChainServerSource) { s.Nodes[1], s.IdentitySources[1] = s.Nodes[0], s.IdentitySources[0] },
		"missing-final-identity":   func(s *NodeChainServerSource) { s.IdentitySources[4] = "" },
		"foreign-family":           func(s *NodeChainServerSource) { s.Schema = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			s := original
			s.Nodes = append([]string(nil), s.Nodes...)
			s.IdentitySources = append([]string(nil), s.IdentitySources...)
			mutate(&s)
			if _, err := NewNodeChainServerPolicy(startJSON(t, s)); err == nil {
				t.Fatal("changed captured owner accepted")
			}
		})
	}
	capture := nodeChainServerCaptureFixture(t, policy)
	capture.Request.LocalPacketPositions[2] = 3
	if _, err := policy.FrontRoutes(capture); err == nil {
		t.Fatal("import acquired packet-key position")
	}
	rows := plan["members"].([]any)
	rows[0], rows[3] = rows[3], rows[0]
	if _, err := NewNodeChainServerPlan(startJSON(t, plan)); err == nil {
		t.Fatal("bundle plan moved original import")
	}
}

func TestNodeChainImportedServerPrefixStartLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, count := range []int{2, 6} {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, layer, count), func(t *testing.T) {
					plan, local := nodeChainImportedServerPrefixPlan(t, count, mode, NativeStartLayerMethod, layer)
					_, localError := NewNodeChain(startJSON(t, local))
					policy, err := NewNodeChainServerPlan(startJSON(t, plan))
					// This fixture's original interfaces declare 2000 bytes. Deep layered
					// AWG graphs that fail the unchanged Local capacity proof remain refused.
					exhausted := count == 6 && mode != "wg" && layer != ""
					if (localError != nil) != exhausted {
						t.Fatal("original Local capacity boundary changed", localError)
					}
					if localError != nil {
						if err == nil {
							t.Fatal("bundle plan bypassed original complete Local capacity proof")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					wanted := layer
					if wanted == "" {
						wanted = "off"
					}
					for i, proof := range policy.proofs {
						if i == len(policy.proofs)-2 {
							if proof.StartLayer != "off" {
								t.Fatal("import borrowed paired Start Layer")
							}
						} else if proof.StartLayer != wanted {
							t.Fatal("original paired Start Layer lost", i)
						}
					}
					snapshot := serverCarrierSnapshotFixture()
					snapshot.InterfaceMTU = 9000
					projected, err := serverCarrierCaptureFixture(t, policy, &snapshot).ProjectContext(context.Background())
					if err != nil || !projected.NativeCarrierRequired() {
						t.Fatal("original layered carrier refused", err)
					}
					for _, mtu := range serverCarrierEndpointMTUs(t, projected) {
						if mtu < 1280 {
							t.Fatal("unviable complete layered suffix accepted")
						}
					}
				})
			}
		}
	}
}
