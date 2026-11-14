package mobilemultihop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nodeChainServerPlanBundle(t *testing.T, node *NodeProfile, identity string) map[string]any {
	t.Helper()
	var files, wg map[string]any
	if json.Unmarshal([]byte(node.inputs.Files), &files) != nil || json.Unmarshal([]byte(identity), &wg) != nil {
		t.Fatal("original generated bundle assets")
	}
	profiles := map[string]any{node.mode: files, "wg": wg}
	if node.inputs.Start != "" {
		var start map[string]any
		if json.Unmarshal([]byte(node.inputs.Start), &start) != nil {
			t.Fatal("original Start Layer assets")
		}
		profiles["shadowsocks"] = start
	}
	return map[string]any{"profiles": profiles, "routerProfiles": []any{predecessorCopy(node.profile)},
		"selectedRouterID": "deliberately-unrelated-default", "nodeProofId": node.profile["node_proof_id"]}
}

func nodeChainServerPlanPeerBundle(t *testing.T, original map[string]any, position int) map[string]any {
	t.Helper()
	peer := importedPQGraph(t, startJSON(t, original))
	profile := peer["routerProfiles"].([]any)[0].(map[string]any)
	profile["id"] = "server-" + profile["id"].(string)
	for mode, value := range peer["profiles"].(map[string]any) {
		if !NodeChainPrefixMode(mode) {
			continue
		}
		assets := value.(map[string]any)
		name := "wg.conf"
		if mode != "wg" {
			name = "awg.conf"
		}
		raw := string(mustDecodeChainAsset(t, assets[name].(string)))
		for _, line := range strings.Split(raw, "\n") {
			if strings.HasPrefix(line, "PrivateKey = ") {
				seed := byte(151 + position)
				if mode != "wg" {
					seed += 20
				}
				raw = strings.Replace(raw, line, "PrivateKey = "+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32)), 1)
			}
		}
		raw = strings.ReplaceAll(raw, fmt.Sprintf("10.%d.0.2", 80+position), fmt.Sprintf("10.%d.0.3", 80+position))
		raw = strings.ReplaceAll(raw, fmt.Sprintf("fd80:%x::2", position+1), fmt.Sprintf("fd80:%x::3", position+1))
		assets[name] = base64.StdEncoding.EncodeToString([]byte(raw))
	}
	return peer
}

func nodeChainServerPlanFixture(t *testing.T, mode, layer string, imported bool) (map[string]any, NodeChainSource) {
	t.Helper()
	modes := []string{mode, mode, "shadowsocks"}
	layers := []string{layer, layer, layer}
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
	local := nodeChainFixtureSource(t, nodes)
	for i, node := range nodes {
		identity := identities[i].inputs.Files
		if node.mode == "wg" {
			identity = node.inputs.Files
		}
		local.IdentitySources = append(local.IdentitySources, identity)
	}
	entryBundle := nodeChainServerPlanBundle(t, nodes[0], local.IdentitySources[0])
	plan := map[string]any{"schema": float64(1), "entry_node_id": nodes[0].profile["node_proof_id"],
		"entry": map[string]any{"bundle": entryBundle, "profile_id": nodes[0].profile["id"], "mode": mode}}
	members := []any{}
	for i := 1; i < len(nodes); i++ {
		if imported && i == 1 {
			config, capture, _, _ := importedEntryFixture(t, "", "")
			original, err := NodeChainImportedMemberInput(config, capture)
			if err != nil {
				t.Fatal(err)
			}
			local.Schema, local.Nodes[1], local.IdentitySources[1] = 2, original, ""
			members = append(members, map[string]any{"imported": map[string]any{"config": config, "capture": capture}})
			continue
		}
		bundle := nodeChainServerPlanBundle(t, nodes[i], local.IdentitySources[i])
		peer := nodeChainServerPlanPeerBundle(t, bundle, i)
		members = append(members, map[string]any{"paired": map[string]any{"bundle": bundle, "profile_id": nodes[i].profile["id"], "mode": nodes[i].mode},
			"server_peer": map[string]any{"bundle": peer, "profile_id": "server-" + nodes[i].profile["id"].(string)}})
	}
	plan["members"] = members
	return plan, local
}

func TestNodeChainServerPlanUsesCompleteIndependentBundles(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, imported := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/imported-%t", mode, layer, imported), func(t *testing.T) {
					plan, localSource := nodeChainServerPlanFixture(t, mode, layer, imported)
					raw := startJSON(t, plan)
					policy, err := NewNodeChainServerPlan(raw)
					if err != nil {
						t.Fatal("complete original bundle plan refused", err)
					}
					if raw != startJSON(t, plan) {
						t.Fatal("builder mutated original private bundle input")
					}
					local, err := NewNodeChain(startJSON(t, localSource))
					if err != nil {
						t.Fatal(err)
					}
					capture := nodeChainServerCaptureFixture(t, policy)
					capture.Request.LocalPacketPublicKeys = nil
					capture.Request.LocalPacketPositions = nil
					for position, node := range local.nodes[:len(local.nodes)-1] {
						if node == nil {
							continue
						}
						key, err := node.PacketClientPublicKey()
						if err != nil {
							t.Fatal(err)
						}
						capture.Request.LocalPacketPublicKeys = append(capture.Request.LocalPacketPublicKeys, key)
						if imported {
							capture.Request.LocalPacketPositions = append(capture.Request.LocalPacketPositions, position)
						}
					}
					capture.Request.Peer, capture.Request.Port = "10.80.0.2", 26240
					execution, err := NewNodeChainExecutionPolicy(startJSON(t, NodeChainExecutionSource{Schema: 1, Execution: "auto",
						LocalSource: startJSON(t, localSource), Server: policy.Descriptor(), Request: capture.Request, FirstPort: 26240, LastPort: 26247}))
					if err != nil || execution.Descriptor().SourceSHA256 != policy.SourceSHA256() {
						t.Fatal("actual client descriptor did not match independently provisioned server source", err)
					}
					var source NodeChainServerSource
					if json.Unmarshal([]byte(policy.Source()), &source) != nil || source.Schema != localSource.Schema || len(source.Nodes) != 2 {
						t.Fatal("server source lost typed suffix shape")
					}
					if imported && (source.Nodes[0] != localSource.Nodes[1] || source.IdentitySources[0] != "") {
						t.Fatal("imported bytes changed or acquired a fabricated Router identity")
					}
					for i, identity := range source.IdentitySources {
						if identity != "" && identity == localSource.IdentitySources[i+1] {
							t.Fatal("Local WG identity secret copied into Server, including final SS")
						}
					}
					if strings.Contains(policy.Source(), `captured-chain-token-0`) {
						t.Fatal("entry private launch leaked into suffix source")
					}
					replay, err := NewNodeChainServerPolicy(policy.Source())
					if err != nil || !reflect.DeepEqual(replay.Descriptor(), policy.Descriptor()) {
						t.Fatal("staged original source did not recompile exactly", err)
					}
				})
			}
		}
	}
}

func TestNodeChainServerPlanRejectsBorrowedOrChangedPrivateAuthority(t *testing.T) {
	faults := []string{"schema", "unknown", "case-alias", "entry-node", "entry-default", "entry-profile", "entry-duplicate", "missing-peer", "peer-profile", "peer-node", "peer-endpoint", "peer-api", "packet-key", "packet-address", "packet-port", "packet-awg", "packet-layer", "final-wg-key", "final-wg-alias", "final-wg-node", "final-ss-key", "foreign-mode", "extra-member", "null", "oversized"}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			plan, _ := nodeChainServerPlanFixture(t, "awg2-strong", "aes-256-gcm+xor-whitening", false)
			entry := plan["entry"].(map[string]any)
			rows := plan["members"].([]any)
			middle, final := rows[0].(map[string]any), rows[1].(map[string]any)
			paired := middle["paired"].(map[string]any)
			peer := middle["server_peer"].(map[string]any)
			peerBundle := peer["bundle"].(map[string]any)
			peerProfile := peerBundle["routerProfiles"].([]any)[0].(map[string]any)
			peerModes := peerBundle["profiles"].(map[string]any)
			localModes := paired["bundle"].(map[string]any)["profiles"].(map[string]any)
			switch fault {
			case "schema":
				plan["schema"] = float64(2)
			case "unknown":
				plan["private_secret"] = "never-echo-this-value"
			case "case-alias":
				plan["Schema"] = plan["schema"]
				delete(plan, "schema")
			case "entry-node":
				plan["entry_node_id"] = strings.Repeat("b", 64)
			case "entry-default":
				delete(entry, "profile_id")
			case "entry-profile":
				entry["profile_id"] = "foreign-profile"
			case "entry-duplicate":
				bundle := entry["bundle"].(map[string]any)
				bundle["routerProfiles"] = append(bundle["routerProfiles"].([]any), bundle["routerProfiles"].([]any)[0])
			case "missing-peer":
				delete(final, "server_peer")
			case "peer-profile":
				peer["profile_id"] = "foreign"
			case "peer-node":
				peerProfile["node_proof_id"] = strings.Repeat("b", 64)
			case "peer-endpoint":
				peerProfile["endpoint"] = "198.51.100.99"
			case "peer-api":
				peerProfile["router_api"] = "http://10.99.0.1:8787"
			case "packet-key":
				peerModes["awg2-strong"] = localModes["awg2-strong"]
			case "packet-address", "packet-port", "packet-awg":
				assets := peerModes["awg2-strong"].(map[string]any)
				raw := string(mustDecodeChainAsset(t, assets["awg.conf"].(string)))
				before, after := "10.81.0.3", "10.81.0.2"
				if fault == "packet-port" {
					before, after = ":51820", ":51821"
				} else if fault == "packet-awg" {
					before, after = "Jc=3", "Jc=4"
				}
				if !strings.Contains(raw, before) {
					t.Fatal("causal fixture lacks original field", fault)
				}
				assets["awg.conf"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(raw, before, after, 1)))
			case "packet-layer":
				peerModes["shadowsocks"] = final["paired"].(map[string]any)["bundle"].(map[string]any)["profiles"].(map[string]any)["shadowsocks"]
			case "final-wg-key", "final-wg-alias", "final-wg-node", "final-ss-key":
				server := final["server_peer"].(map[string]any)["bundle"].(map[string]any)["profiles"].(map[string]any)
				original := final["paired"].(map[string]any)["bundle"].(map[string]any)["profiles"].(map[string]any)
				if fault == "final-wg-key" {
					server["wg"] = original["wg"]
				} else if fault == "final-wg-alias" {
					assets := server["wg"].(map[string]any)
					raw := string(mustDecodeChainAsset(t, assets["wg.conf"].(string)))
					local := string(mustDecodeChainAsset(t, original["wg"].(map[string]any)["wg.conf"].(string)))
					var alias string
					for _, line := range strings.Split(local, "\n") {
						if strings.HasPrefix(line, "PrivateKey = ") {
							key := mustDecodeChainAsset(t, strings.TrimPrefix(line, "PrivateKey = "))
							key[0] ^= 1 // X25519 clamps this bit; it is the same actual peer.
							alias = base64.StdEncoding.EncodeToString(key)
							clear(key)
						}
					}
					if alias == "" {
						t.Fatal("canonical alias fixture has no original key")
					}
					for _, line := range strings.Split(raw, "\n") {
						if strings.HasPrefix(line, "PrivateKey = ") {
							raw = strings.Replace(raw, line, "PrivateKey = "+alias, 1)
						}
					}
					assets["wg.conf"] = base64.StdEncoding.EncodeToString([]byte(raw))
				} else if fault == "final-wg-node" {
					server["wg"] = entry["bundle"].(map[string]any)["profiles"].(map[string]any)["wg"]
				} else {
					server["shadowsocks"] = peerModes["shadowsocks"]
				}
			case "foreign-mode":
				paired["mode"] = "wg-pq"
			case "extra-member":
				plan["members"] = append(rows, rows[1])
			case "null":
				peer["profile_id"] = nil
			case "oversized":
				entry["dns_bootstrap"] = strings.Repeat("x", NodeChainInputLimit)
			}
			policy, err := NewNodeChainServerPlan(startJSON(t, plan))
			if err == nil || policy != nil || strings.Contains(err.Error(), "never-echo-this-value") {
				t.Fatal("changed private authority produced a server plan")
			}
		})
	}
}

func TestNodeChainServerPlanRetainsExactImportedCaptureAndPolicy(t *testing.T) {
	plan, _ := nodeChainServerPlanFixture(t, "wg", "", true)
	for _, fault := range []string{"foreign-kind", "paired-label", "changed-config", "extra-imported", "missing-final-peer", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			value := importedPQGraph(t, startJSON(t, plan))
			rows := value["members"].([]any)
			member := rows[0].(map[string]any)
			imported := member["imported"].(map[string]any)
			switch fault {
			case "foreign-kind":
				imported["capture"] = strings.Replace(imported["capture"].(string), `"protocol":"shadowsocks"`, `"protocol":"socks5"`, 1)
			case "paired-label":
				member["paired"] = rows[1].(map[string]any)["paired"]
			case "changed-config":
				imported["config"] = strings.Replace(imported["config"].(string), "203.0.113.20", "203.0.113.21", 1)
			case "extra-imported":
				value["members"] = append(rows, rows[0])
			case "missing-final-peer":
				delete(rows[1].(map[string]any), "server_peer")
			case "duplicate":
				if _, err := NewNodeChainServerPlan(strings.Replace(startJSON(t, value), `"schema":1`, `"schema":1,"schema":1`, 1)); err == nil {
					t.Fatal("duplicate plan field accepted")
				}
				return
			}
			if startJSON(t, value) == startJSON(t, plan) {
				t.Fatal("negative imported fixture did not change original source")
			}
			if _, err := NewNodeChainServerPlan(startJSON(t, value)); err == nil {
				t.Fatal("changed imported authority accepted")
			}
		})
	}
}

func TestNodeChainServerPlanPreservesSelectedDNSAndPolicyUnion(t *testing.T) {
	plan, _ := nodeChainServerPlanFixture(t, "awg2-fast", "aes-256-gcm", false)
	rows := plan["members"].([]any)
	for position, row := range rows {
		member := row.(map[string]any)
		bundle := member["paired"].(map[string]any)["bundle"].(map[string]any)
		profile := bundle["routerProfiles"].([]any)[0].(map[string]any)
		profile["home_lan_access"] = false
		profile["home_lan_cidrs"] = []any{fmt.Sprintf("192.168.%d.0/24", 50+position)}
		if position == 0 {
			profile["ipv6_mode"] = "off"
		} else {
			profile["dns_mode"], profile["dns_protocol"] = "custom", "tcp"
			profile["dns_host"], profile["dns_port"] = "9.9.9.9", float64(5353)
		}
	}
	policy, err := NewNodeChainServerPlan(startJSON(t, plan))
	if err != nil {
		t.Fatal("captured policy refused", err)
	}
	if !policy.blockIPv6 || !reflect.DeepEqual(policy.blockedCIDRs, []string{"192.168.50.0/24", "192.168.51.0/24"}) ||
		!strings.Contains(policy.dns.PolicyJSON, `"server":"9.9.9.9"`) || !strings.Contains(policy.dns.PolicyJSON, `"server_port":5353`) ||
		!strings.Contains(policy.dns.PolicyJSON, `"type":"tcp"`) {
		t.Fatal("server bundle defaults replaced selected DNS or per-member device policy")
	}
	for _, member := range policy.Descriptor().Members {
		if member.StartLayer != "aes-256-gcm" {
			t.Fatal("selected Start Layer replaced by server bundle defaults")
		}
	}
}

func TestNodeChainServerPlanSavedSelectionMatchesAppExecutionProjection(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(mode+"/"+execution, func(t *testing.T) {
				plan, localSource := nodeChainServerPlanFixture(t, mode, "", true)
				local, err := NewNodeChain(startJSON(t, localSource))
				if err != nil {
					t.Fatal(err)
				}
				selection := []any{}
				for _, proof := range local.ProofInventory() {
					selection = append(selection, map[string]any{"id": proof.ProfileID, "mode": proof.Mode})
				}
				for position, node := range local.nodes {
					if node == nil {
						continue
					}
					chosen := plan["entry"].(map[string]any)
					if position > 0 {
						chosen = plan["members"].([]any)[position-1].(map[string]any)["paired"].(map[string]any)
					}
					profile := chosen["bundle"].(map[string]any)["routerProfiles"].([]any)[0].(map[string]any)
					profile["startup_mode"], profile["auto_connect"] = "last", true
					profile["kill_switch_policy"], profile["kill_switch"] = "always", true
					if position == len(local.nodes)-1 {
						profile["multihop_enabled"], profile["multihop_execution"], profile["multihop_nodes"] = true, execution, selection
					}
					// IOSNodeChainCapture.executionProfile removes exactly these
					// two app scheduling keys. Topology, DNS and protection stay.
					projected := predecessorCopy(profile)
					delete(projected, "startup_mode")
					delete(projected, "auto_connect")
					member, err := NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, projected), node.inputs.Start, node.inputs.DNSBootstrap)
					if err != nil {
						t.Fatal(err)
					}
					localSource.Nodes[position], err = member.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
				}
				raw := startJSON(t, plan)
				policy, err := NewNodeChainServerPlan(raw)
				if err != nil || raw != startJSON(t, plan) {
					t.Fatal("saved app selection was changed or refused", err)
				}
				var source NodeChainServerSource
				if json.Unmarshal([]byte(policy.Source()), &source) != nil {
					t.Fatal("private source")
				}
				final, err := ParseNodeLaunchInput(source.Nodes[len(source.Nodes)-1])
				if err != nil || final.profile["multihop_execution"] != execution || final.profile["multihop_enabled"] != true ||
					final.profile["startup_mode"] != "last" || final.profile["auto_connect"] != true || final.profile["kill_switch_policy"] != "always" ||
					!reflect.DeepEqual(final.profile["multihop_nodes"], selection) {
					t.Fatal("builder silently normalized saved topology, scheduling or protection", err)
				}
				capture := nodeChainServerCaptureFixture(t, policy)
				key, err := local.nodes[0].PacketClientPublicKey()
				if err != nil {
					t.Fatal(err)
				}
				capture.Request.LocalPacketPublicKeys, capture.Request.LocalPacketPositions = []string{key}, []int{0}
				capture.Request.Peer, capture.Request.Port = "10.80.0.2", 26240
				compiled, err := NewNodeChainExecutionPolicy(startJSON(t, NodeChainExecutionSource{Schema: 1, Execution: execution,
					LocalSource: startJSON(t, localSource), Server: policy.Descriptor(), Request: capture.Request, FirstPort: 26240, LastPort: 26247}))
				if err != nil || compiled.Descriptor().SourceSHA256 != policy.SourceSHA256() {
					t.Fatal("app scheduling projection broke actual server descriptor matching", err)
				}
			})
		}
	}
}
