package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func nodeChainServerHysteriaFixture(t *testing.T, count int, first, layer string) ([]*NodeProfile, []*NodeProfile, NodeChainServerSource) {
	t.Helper()
	nodes, _ := nodeChainHysteriaFixture(t, count, first, layer)
	modes, layers := make([]string, count), make([]string, count)
	for i := range modes {
		modes[i] = "wg"
	}
	identities := nodeChainModeFixtureNodes(t, modes, layers)
	source := NodeChainServerSource{Schema: 1, EntryID: predecessorText(nodes[0].profile, "id"),
		EntryNodeID: predecessorText(nodes[0].profile, "node_proof_id"), EntryMode: nodes[0].mode}
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

func TestNodeChainServerHysteriaRetainsOriginalFinalClosure(t *testing.T) {
	cases := []struct {
		count        int
		first, layer string
	}{}
	for count := 2; count <= 8; count++ {
		cases = append(cases, struct {
			count        int
			first, layer string
		}{count, "wg", ""})
	}
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		cases = append(cases, struct {
			count        int
			first, layer string
		}{4, "awg2-strong", layer})
	}
	for _, test := range cases {
		name := test.layer
		if name == "" {
			name = "off"
		}
		t.Run(fmt.Sprintf("%d/%s/%s", test.count, test.first, name), func(t *testing.T) {
			nodes, _, source := nodeChainServerHysteriaFixture(t, test.count, test.first, test.layer)
			before := startJSON(t, source)
			policy, err := NewNodeChainServerPolicy(before)
			if err != nil {
				t.Fatal("original paired Hysteria2 server suffix refused", err)
			}
			capture := nodeChainServerCaptureFixture(t, policy)
			config, err := policy.NativeConfig(capture)
			if err != nil {
				t.Fatal(err)
			}
			graph := importedPQGraph(t, config)
			proofs := policy.ProofInventory()
			if len(graph["inbounds"].([]any)) != 0 || len(graph["endpoints"].([]any)) != test.count-2 || len(proofs) != test.count-1 {
				t.Fatal("Hysteria2 suffix added a TUN/front or lost a captured prefix")
			}
			last := nodes[test.count-1]
			original, err := nodeMultihopPredecessor(last)
			if err != nil {
				t.Fatal(err)
			}
			want := predecessorCopy(original.final)
			want["tag"] = proofs[len(proofs)-1].Tag
			if len(proofs) > 1 {
				want["detour"] = proofs[len(proofs)-2].Tag
			}
			actual := externalTestFind(t, graph, proofs[len(proofs)-1].Tag)
			if !reflect.DeepEqual(actual, want) || actual["type"] != "hysteria2" {
				t.Fatal("server changed original Hysteria2 TLS/CA/password/Salamander or predecessor")
			}
			member := policy.Descriptor().Members[len(proofs)-1]
			if member.Mode != "hysteria2" || member.StartLayer != "off" || member.ClientPublicKey != "" || member.ServerPublicKey != "" ||
				member.NodeID != last.profile["node_proof_id"] || member.ProfileID != last.profile["id"] || member.ProofKind != "" {
				t.Fatal("server final descriptor replaced private Router identity or acquired packet keys")
			}
			dns, err := policy.DNSCapture(capture)
			if err != nil || dns.FinalTag != proofs[len(proofs)-1].Tag || dns.PolicySHA256 != capture.Source.DNSPolicySHA256 {
				t.Fatal("server final lost exact selected DNS binding", err)
			}
			selected := false
			for _, raw := range importedPQGraph(t, dns.RouterJSON)["servers"].([]any) {
				row := raw.(map[string]any)
				if row["tag"] == dns.ResolverTag {
					selected = row["type"] == "udp" && row["server"] == last.profile["adguard_ipv4"] && row["detour"] == dns.FinalTag
				}
			}
			if !selected {
				t.Fatal("server substituted or bypassed final Home AdGuard")
			}
			routes, err := policy.FrontRoutes(capture)
			if err != nil || len(routes) != len(proofs) {
				t.Fatal("server lost captured authenticated front routes", err)
			}
			for i, route := range routes {
				if route.Final != (i == len(routes)-1) || route.Tag != proofs[i].Tag ||
					!route.Final && route.AllowsDestination("tcp", "198.51.100.77:443") ||
					route.Final && route.UDPOverTCPVersion != 2 {
					t.Fatal("Hysteria2 final broadened prefix traffic or changed the client front transport")
				}
			}
			if startJSON(t, source) != before {
				t.Fatal("server compilation mutated original private input")
			}
			reopened, err := NewNodeChainServerPolicy(policy.Source())
			if err != nil || !reflect.DeepEqual(policy.Descriptor(), reopened.Descriptor()) {
				t.Fatal("server Hysteria2 source did not reopen exactly", err)
			}
		})
	}
}

func TestNodeChainServerHysteriaExecutionRetainsBothOriginalPaths(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, execution), func(t *testing.T) {
				nodes, identities, _ := nodeChainServerHysteriaFixture(t, count, "awg2-fast", "")
				source := nodeChainExecutionFixtureFromNodes(t, nodes, identities, execution)
				prep, err := NewNodeChainExecutionPreparation(source.LocalSource, execution)
				if err != nil {
					t.Fatal("original Hysteria2 Server/Compare preparation refused", err)
				}
				policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				projection, err := prep.BindExecution(policy)
				if err != nil || projection.ValidateTransition(prep.Config(), projection.Config()) != nil {
					t.Fatal("Hysteria2 execution lost the original closed-gate transition", err)
				}
				for _, candidate := range []string{"local", "server"} {
					proofs, err := projection.ProofInventory(candidate)
					if err != nil || len(proofs) != count || proofs[count-1].Mode != "hysteria2" || proofs[count-1].StartLayer != "off" ||
						proofs[count-1].NodeID != nodes[count-1].profile["node_proof_id"] || proofs[count-1].SourceSHA256 != nodes[count-1].SourceSHA256() {
						t.Fatal("Hysteria2 candidate proof substituted final source or identity", candidate, err)
					}
					dns, err := projection.DNSCapture(candidate)
					if err != nil || dns.SelectedTag != proofs[count-1].Tag || dns.DNSPolicySHA256 != source.Server.DNSPolicySHA256 || dns.DNS.FinalTag != SelectorTag {
						t.Fatal("candidate lost selected exit-routed DNS", candidate, err)
					}
				}
				original, current := importedPQGraph(t, prep.Config()), importedPQGraph(t, projection.Config())
				if !reflect.DeepEqual(original["inbounds"], current["inbounds"]) || !reflect.DeepEqual(original["endpoints"], current["endpoints"]) ||
					current["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
					t.Fatal("Hysteria2 extension replaced the original TUN/packet owners or opened application traffic")
				}
				launch, err := policy.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				reopened, err := ParseNodeChainExecutionLaunchInput(launch)
				if err != nil || reopened.Source() != policy.Source() || reopened.Config() != policy.Config() {
					t.Fatal("Hysteria2 execution launch lost captured original source", err)
				}
			})
		}
	}
}

func nodeChainServerHysteriaPlanFixture(t *testing.T, count int, first string) (map[string]any, NodeChainSource) {
	t.Helper()
	nodes, identities, _ := nodeChainServerHysteriaFixture(t, count, first, "")
	local := nodeChainFixtureSource(t, nodes)
	for i, node := range nodes {
		identity := identities[i].inputs.Files
		if node.mode == "wg" {
			identity = node.inputs.Files
		}
		local.IdentitySources = append(local.IdentitySources, identity)
	}
	entry := nodeChainServerPlanBundle(t, nodes[0], local.IdentitySources[0])
	plan := map[string]any{"schema": float64(1), "entry_node_id": nodes[0].profile["node_proof_id"],
		"entry": map[string]any{"bundle": entry, "profile_id": nodes[0].profile["id"], "mode": nodes[0].mode}}
	rows := []any{}
	for i := 1; i < count; i++ {
		bundle := nodeChainServerPlanBundle(t, nodes[i], local.IdentitySources[i])
		rows = append(rows, map[string]any{"paired": map[string]any{"bundle": bundle, "profile_id": nodes[i].profile["id"], "mode": nodes[i].mode},
			"server_peer": map[string]any{"bundle": nodeChainServerPlanPeerBundle(t, bundle, i), "profile_id": "server-" + nodes[i].profile["id"].(string)}})
	}
	plan["members"] = rows
	return plan, local
}

func TestNodeChainServerHysteriaPlanRetainsIndependentIdentity(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, first := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(fmt.Sprintf("%d/%s", count, first), func(t *testing.T) {
				plan, local := nodeChainServerHysteriaPlanFixture(t, count, first)
				before := startJSON(t, plan)
				policy, err := NewNodeChainServerPlan(before)
				if err != nil {
					t.Fatal("original independently provisioned Hysteria2 plan refused", err)
				}
				var actual NodeChainServerSource
				if json.Unmarshal([]byte(policy.Source()), &actual) != nil || actual.Schema != 1 || len(actual.Nodes) != count-1 || before != startJSON(t, plan) {
					t.Fatal("private Hysteria2 plan changed source or suffix shape")
				}
				for i, identity := range actual.IdentitySources {
					if identity == "" || identity == local.IdentitySources[i+1] {
						t.Fatal("Hysteria2 plan copied Local identity secrets into Server")
					}
				}
				originalFinal, _ := ParseNodeLaunchInput(local.Nodes[count-1])
				serverFinal, err := ParseNodeLaunchInput(actual.Nodes[count-2])
				if err != nil || originalFinal == nil || serverFinal.Config() != originalFinal.Config() || serverFinal.mode != "hysteria2" {
					t.Fatal("independent WG identity changed original Hysteria2 transport", err)
				}
			})
		}
	}
}

func TestNodeChainServerHysteriaRejectsChangedTransportAuthority(t *testing.T) {
	for _, fault := range []string{"password", "sni", "trust", "mask", "endpoint", "dns", "identity-key", "identity-node", "final-layer"} {
		t.Run(fault, func(t *testing.T) {
			plan, _ := nodeChainServerHysteriaPlanFixture(t, 3, "awg2-strong")
			original, err := NewNodeChainServerPlan(startJSON(t, plan))
			if err != nil {
				t.Fatal("original independently provisioned plan refused", err)
			}
			rows := plan["members"].([]any)
			last := rows[len(rows)-1].(map[string]any)
			paired := last["paired"].(map[string]any)["bundle"].(map[string]any)
			peer := last["server_peer"].(map[string]any)["bundle"].(map[string]any)
			modes := peer["profiles"].(map[string]any)
			files := modes["hysteria2"].(map[string]any)
			profile := paired["routerProfiles"].([]any)[0].(map[string]any)
			graph := importedPQGraph(t, string(mustDecodeChainAsset(t, files["sing-box.json"].(string))))
			final := graph["outbounds"].([]any)[0].(map[string]any)
			switch fault {
			case "password":
				final["password"] = "another-valid-private-Hysteria2-password"
			case "sni":
				final["tls"].(map[string]any)["server_name"] = "another-private-final.example"
			case "trust":
				files["cert.pem"] = base64.StdEncoding.EncodeToString([]byte(entryCertificate(t)))
			case "mask":
				final["obfs"].(map[string]any)["password"] = "another-valid-private-Salamander-mask"
			case "endpoint":
				final["server"] = "198.51.100.191"
			case "dns":
				// DNS belongs to the captured Local selection. A separately
				// valid peer's defaults cannot change that selected profile.
				profile["adguard_ipv4"] = "192.168.50.134"
			case "identity-key":
				modes["wg"] = paired["profiles"].(map[string]any)["wg"]
			case "identity-node":
				peer["nodeProofId"] = plan["entry_node_id"]
			case "final-layer":
				profile["start_layer"] = "aes-256-gcm"
			}
			files["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
			if fault == "dns" {
				// Changing the captured Local DNS is a new valid plan, not an
				// invalid packet source. It must change the descriptor policy
				// rather than borrowing the old selected resolver receipt.
				fresh, err := NewNodeChainServerPlan(startJSON(t, plan))
				if err != nil {
					t.Fatal("new captured Home DNS plan refused", err)
				}
				if fresh.Descriptor().DNSPolicySHA256 == original.Descriptor().DNSPolicySHA256 || fresh.SourceSHA256() == original.SourceSHA256() {
					t.Fatal("changed selected Home DNS borrowed original Hysteria2 receipt", err)
				}
				if _, err := fresh.NativeConfig(nodeChainServerCaptureFixture(t, original)); err == nil {
					t.Fatal("changed Hysteria2 DNS source accepted old capture")
				}
			} else if _, err := NewNodeChainServerPlan(startJSON(t, plan)); err == nil {
				t.Fatal("changed private Hysteria2 transport or identity acquired original plan authority")
			}
		})
	}
}

func TestNodeChainServerHysteriaRestoresProvedChoice(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			nodes, identities, _ := nodeChainServerHysteriaFixture(t, 3, "awg2-strong", "")
			source := nodeChainExecutionFixtureFromNodes(t, nodes, identities, "auto")
			fixture := newNodeChainExecutionRuntimeFixtureFromSource(t, source)
			fixture.engine.localDelay, fixture.engine.serverDelay = 200*time.Millisecond, time.Millisecond
			if winner == "local" {
				fixture.engine.localDelay, fixture.engine.serverDelay = time.Millisecond, 200*time.Millisecond
			}
			testNodeChainExecutionRestoreKeepsWinner(t, fixture)
			if fixture.runtime.Progress().Execution != winner {
				t.Fatal("Hysteria2 restoration test did not exercise its captured concrete winner")
			}
		})
	}
}

func TestNodeChainServerHysteriaLastFreshlyProvesCapturedWinner(t *testing.T) {
	for _, count := range []int{2, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			nodes, identities, _ := nodeChainServerHysteriaFixture(t, count, "awg2-fast", "")
			// Reuse the original cold-store, authenticated discovery, lease,
			// same-choice restoration and one-shot adoption assertions. Only
			// the complete original source factory changes to Hysteria2. The
			// private TLS bundle is captured once and reopened by each fresh
			// runtime, rather than generating a different CA on cold restore.
			testNodeChainExecutionLastPersistsOnlyBindingsAndFreshlyProvesChoice(t, func(t *testing.T) *nodeChainExecutionRuntimeFixture {
				return newNodeChainExecutionRuntimeFixtureFromSource(t, nodeChainExecutionFixtureFromNodes(t, nodes, identities, "auto"))
			})
		})
	}
}
