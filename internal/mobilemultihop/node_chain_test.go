package mobilemultihop

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nodeChainFixtureNodes(t *testing.T, count int, layer string) []*NodeProfile {
	t.Helper()
	modes, layers := make([]string, count), make([]string, count)
	for position := 0; position < count; position++ {
		modes[position], layers[position] = "wg", layer
		if position == count-1 {
			modes[position] = "shadowsocks"
		}
	}
	return nodeChainModeFixtureNodes(t, modes, layers)
}

func nodeChainModeFixtureNodes(t *testing.T, modes, layers []string) []*NodeProfile {
	t.Helper()
	if len(modes) != len(layers) {
		t.Fatal("every selected fixture member needs its own Start Layer")
	}
	nodes := make([]*NodeProfile, 0, len(modes))
	for position, mode := range modes {
		layer := layers[position]
		files, profile, start := nodeProfileFixture(t, mode, layer)
		endpoint := fmt.Sprintf("198.51.100.%d", position+10)
		private := bytes.Repeat([]byte{byte(21 + position)}, 32)
		server, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(71 + position)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		public := base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())
		profile["id"], profile["endpoint"] = fmt.Sprintf("chain-node-%d", position), endpoint
		profile["node_proof_id"] = externalDigest([]byte("router-vpn-node-proof-v1\n" + public))
		profile["router_api"], profile["api_token"] = fmt.Sprintf("http://10.%d.0.1:8787", 80+position), fmt.Sprintf("captured-chain-token-%d", position)
		profile["adguard_ipv4"] = fmt.Sprintf("10.%d.0.53", 80+position)
		if mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" {
			asset := "wg.conf"
			if mode != "wg" {
				asset = "awg.conf"
			}
			var assets map[string]string
			_ = json.Unmarshal([]byte(files), &assets)
			raw, _ := base64.StdEncoding.DecodeString(assets[asset])
			text := string(raw)
			for before, after := range map[string]string{
				base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 32)): base64.StdEncoding.EncodeToString(private),
				base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("b"), 32)): public,
				base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("c"), 32)): base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(101 + position)}, 32)),
				"192.0.2.1:51820": endpoint + ":51820",
				"MTU = 1420":      "MTU = 2000",
				"10.77.0.2":       fmt.Sprintf("10.%d.0.2", 80+position),
				"fd77:77::2":      fmt.Sprintf("fd80:%x::2", position+1),
			} {
				text = strings.ReplaceAll(text, before, after)
			}
			assets[asset] = base64.StdEncoding.EncodeToString([]byte(text))
			files = startJSON(t, assets)
		} else {
			var assets map[string]string
			_ = json.Unmarshal([]byte(files), &assets)
			graph := importedPQGraph(t, string(mustDecodeChainAsset(t, assets["sing-box.json"])))
			out := graph["outbounds"].([]any)[0].(map[string]any)
			out["server"], out["password"] = endpoint, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(141 + position)}, 32))
			assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
			files = startJSON(t, assets)
		}
		if start != "" {
			var assets map[string]string
			_ = json.Unmarshal([]byte(start), &assets)
			graph := importedPQGraph(t, string(mustDecodeChainAsset(t, assets["sing-box.json"])))
			out := graph["outbounds"].([]any)[0].(map[string]any)
			out["server"], out["password"] = endpoint, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(171 + position)}, 32))
			assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
			start = startJSON(t, assets)
		}
		node, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
		if err != nil {
			t.Fatal("complete independent node capture", position, err)
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func mustDecodeChainAsset(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nodeChainFixtureSource(t *testing.T, nodes []*NodeProfile) NodeChainSource {
	t.Helper()
	source := NodeChainSource{Schema: 1, Execution: "local"}
	for _, node := range nodes {
		input, err := node.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes = append(source.Nodes, input)
	}
	return source
}

func nodeChainFixture(t *testing.T, count int, layer string) *NodeChain {
	t.Helper()
	source := nodeChainFixtureSource(t, nodeChainFixtureNodes(t, count, layer))
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal("ordered complete chain", err)
	}
	return chain
}

func TestNodeChainCompleteCapturedPaths(t *testing.T) {
	for _, test := range []struct {
		count int
		layer string
	}{{2, ""}, {3, ""}, {4, ""}, {8, ""}, {3, "aes-256-gcm"}, {4, "aes-256-gcm+xor-whitening"}} {
		t.Run(fmt.Sprintf("%d/%s", test.count, test.layer), func(t *testing.T) {
			nodes := nodeChainFixtureNodes(t, test.count, test.layer)
			source := nodeChainFixtureSource(t, nodes)
			before := append([]string(nil), source.Nodes...)
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			graph := importedPQGraph(t, chain.Config())
			if len(graph["inbounds"].([]any)) != 1 || len(graph["endpoints"].([]any)) != test.count-1 {
				t.Fatal("chain substituted additional TUNs or lost native WG endpoints")
			}
			if chain.Progress().Ready || len(chain.ProofInventory()) != test.count || chain.SelectorTag() != "proxy" {
				t.Fatal("capture invented readiness or omitted a selected node")
			}
			dns := graph["dns"].(map[string]any)
			var selected map[string]any
			for _, raw := range dns["servers"].([]any) {
				row := raw.(map[string]any)
				if row["tag"] == dns["final"] {
					selected = row
				}
			}
			if selected == nil || selected["server"] != nodes[test.count-1].profile["adguard_ipv4"] ||
				selected["detour"] != chain.FinalTag() || selected["type"] != "udp" {
				t.Fatal("final selected Home UDP escaped its complete final prefix")
			}
			physical, err := chain.PhysicalEgress()
			first, firstErr := nodes[0].PhysicalEgress()
			if err != nil || firstErr != nil || !reflect.DeepEqual(physical, first) {
				t.Fatal("a middle or final socket became a physical exception", err, firstErr)
			}
			plan, err := chain.MTUPlan()
			if err != nil || plan.Original != 1280 || len(plan.Prefixes) != test.count || plan.Ceiling < 1280 {
				t.Fatal("chain lost a packet envelope or promoted historical MTU", plan, err)
			}
			launch, err := chain.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := ParseNodeChainLaunchInput(launch)
			if err != nil || reopened.Config() != chain.Config() || reopened.SourceSHA256() != chain.SourceSHA256() ||
				!reflect.DeepEqual(reopened.ProofInventory(), chain.ProofInventory()) {
				t.Fatal("child did not reproduce the complete original ordered source", err)
			}
			replayed, physicalPolicy, replayErr := parseNodeChainLaunchInput(launch)
			if replayErr != nil || replayed == nil || physicalPolicy != nil || replayed.Config() != reopened.Config() ||
				replayed.Metadata() != reopened.Metadata() {
				t.Fatal("ordinary replay changed its graph or acquired desktop authority", replayErr)
			}
			actual, replayErr := reopened.LaunchInput()
			if replayErr != nil || actual != launch {
				t.Fatal("ordinary replay changed canonical launch bytes", replayErr)
			}
			for i, node := range nodes {
				input, _ := node.LaunchInput()
				if input != before[i] {
					t.Fatal("composition changed a captured original node")
				}
			}
			proofs, tags := chain.ProofInventory(), chain.PrefixTags()
			proofs[0].Tag, tags[0], physical[0].Host = "foreign", "foreign", "203.0.113.99"
			after, _ := chain.PhysicalEgress()
			if chain.ProofInventory()[0].Tag == "foreign" || chain.PrefixTags()[0] == "foreign" || !reflect.DeepEqual(after, first) {
				t.Fatal("public accessor changed a retained capture")
			}
		})
	}
}

func TestNodeChainOrderSourceAndBounds(t *testing.T) {
	nodes := nodeChainFixtureNodes(t, 4, "")
	source := nodeChainFixtureSource(t, nodes)
	original, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"reorder", "remove", "relabel"} {
		t.Run(fault, func(t *testing.T) {
			changed := source
			changed.Nodes = append([]string(nil), source.Nodes...)
			switch fault {
			case "reorder":
				changed.Nodes[1], changed.Nodes[2] = changed.Nodes[2], changed.Nodes[1]
			case "remove":
				changed.Nodes = append(changed.Nodes[:1], changed.Nodes[2:]...)
			case "relabel":
				input := nodes[1].inputs
				profile := predecessorCopy(nodes[1].profile)
				profile["id"] = "relinked-middle"
				node, err := NewNodeProfile(input.Mode, input.Files, startJSON(t, profile), input.Start, input.DNSBootstrap)
				if err != nil {
					t.Fatal(err)
				}
				changed.Nodes[1], _ = node.LaunchInput()
			}
			next, err := NewNodeChain(startJSON(t, changed))
			if err != nil || next.SourceSHA256() == original.SourceSHA256() || next.ConfigSHA256() == original.ConfigSHA256() {
				t.Fatal("changed order or middle source retained the previous path identity", err)
			}
			launch, _ := original.LaunchInput()
			var receipt nodeChainLaunchRecord
			_ = json.Unmarshal([]byte(launch), &receipt)
			receipt.NodeChainSource = changed
			if _, err := ParseNodeChainLaunchInput(startJSON(t, receipt)); err == nil {
				t.Fatal("stale receipt adopted a substituted middle path")
			}
		})
	}
	for _, count := range []int{0, 1, 9} {
		changed := source
		changed.Nodes = make([]string, count)
		for i := range changed.Nodes {
			changed.Nodes[i] = source.Nodes[0]
		}
		if _, err := NewNodeChain(startJSON(t, changed)); err == nil {
			t.Fatal("ordered node bound was silently truncated", count)
		}
	}
	for _, execution := range []string{"", "server", "auto", "LOCAL"} {
		changed := source
		changed.Execution = execution
		if _, err := NewNodeChain(startJSON(t, changed)); err == nil {
			t.Fatal("unimplemented execution gained chain authority", execution)
		}
	}
	for _, raw := range []string{
		strings.Repeat(" ", NodeChainInputLimit+1),
		strings.Replace(startJSON(t, source), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.TrimSuffix(startJSON(t, source), "}") + `,"entry":"legacy-pair"}`,
	} {
		if _, err := NewNodeChain(raw); err == nil {
			t.Fatal("ambiguous, mixed or oversized chain source was accepted")
		}
	}
}

func TestNodeChainCanonicalIndependentPeers(t *testing.T) {
	nodes := nodeChainFixtureNodes(t, 3, "")
	for _, fault := range []string{"duplicate-profile", "duplicate-peer", "clamped-client-alias", "server-high-bit-alias"} {
		t.Run(fault, func(t *testing.T) {
			copies := append([]*NodeProfile(nil), nodes...)
			switch fault {
			case "duplicate-profile":
				copies[1] = copies[0]
			default:
				input := copies[1].inputs
				profile := predecessorCopy(copies[1].profile)
				var assets map[string]string
				_ = json.Unmarshal([]byte(input.Files), &assets)
				raw := string(mustDecodeChainAsset(t, assets["wg.conf"]))
				firstGraph := importedPQGraph(t, copies[0].Config())
				first := firstGraph["endpoints"].([]any)[0].(map[string]any)
				second := importedPQGraph(t, copies[1].Config())["endpoints"].([]any)[0].(map[string]any)
				if fault == "clamped-client-alias" {
					key := mustDecodeChainAsset(t, first["private_key"].(string))
					key[0] ^= 7
					key[31] ^= 128
					raw = strings.Replace(raw, second["private_key"].(string), base64.StdEncoding.EncodeToString(key), 1)
				} else {
					public := first["peers"].([]any)[0].(map[string]any)["public_key"].(string)
					if fault == "server-high-bit-alias" {
						key := mustDecodeChainAsset(t, public)
						key[31] ^= 128
						public = base64.StdEncoding.EncodeToString(key)
					}
					raw = strings.Replace(raw, second["peers"].([]any)[0].(map[string]any)["public_key"].(string), public, 1)
					profile["node_proof_id"] = externalDigest([]byte("router-vpn-node-proof-v1\n" + public))
				}
				assets["wg.conf"] = base64.StdEncoding.EncodeToString([]byte(raw))
				node, err := NewNodeProfile(input.Mode, startJSON(t, assets), startJSON(t, profile), input.Start, input.DNSBootstrap)
				if err != nil {
					t.Fatal("control needs a valid original single-node source", err)
				}
				copies[1] = node
			}
			if _, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, copies))); err == nil {
				t.Fatal("duplicate or aliased peer became another selected node", fault)
			}
		})
	}
}
