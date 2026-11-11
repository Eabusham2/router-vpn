package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNodeChainAWGAdmissionKeepsExactModesAndFinal(t *testing.T) {
	for _, mode := range append(append([]string(nil), predecessorFamilies...), "", "WG", " awg2-fast", "awg2-strong ", "AWG2 Fast", "awg", "awg2", "awg2-max") {
		want := mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong"
		if NodeChainPrefixMode(mode) != want {
			t.Fatal("prefix admission broadened or normalized the selected raw mode", mode)
		}
	}
	baseline := nodeChainModeFixtureNodes(t, []string{"awg2-fast", "shadowsocks"}, []string{"", ""})
	for _, mode := range predecessorFamilies {
		files, profile, start := nodeProfileFixture(t, mode, "")
		node, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
		if err != nil {
			t.Fatal("admission control needs a complete valid single-node capture", mode, err)
		}
		if mode != "wg" && mode != "awg2-fast" && mode != "awg2-strong" {
			t.Run("prefix/"+mode, func(t *testing.T) {
				if _, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, []*NodeProfile{node, baseline[1]}))); err == nil {
					t.Fatal("unimplemented prefix acquired ordered-path authority", mode)
				}
			})
		}
		if mode != "shadowsocks" {
			t.Run("final/"+mode, func(t *testing.T) {
				if _, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, []*NodeProfile{baseline[0], node}))); err == nil {
					t.Fatal("AWG prefix support broadened the captured SS2022 final", mode)
				}
			})
		}
	}
}

func TestNodeChainAWGPrefixesPreserveOriginalNodesAndLayers(t *testing.T) {
	cases := [][]string{
		{"awg2-fast", "shadowsocks"},
		{"awg2-strong", "shadowsocks"},
		{"wg", "awg2-fast", "shadowsocks"},
		{"awg2-strong", "wg", "shadowsocks"},
		{"awg2-fast", "awg2-strong", "shadowsocks"},
		{"awg2-strong", "awg2-fast", "shadowsocks"},
		{"wg", "awg2-fast", "awg2-strong", "shadowsocks"},
		{"awg2-strong", "wg", "awg2-fast", "wg", "awg2-strong", "awg2-fast", "wg", "shadowsocks"},
	}
	for _, modes := range cases {
		t.Run(strings.Join(modes, "/"), func(t *testing.T) {
			nodeChainAWGCapture(t, modes, make([]string, len(modes)))
		})
	}
	// Independent node layers must remain in forwarding order, including a
	// layer around an intermediate AWG peer and the final SS2022's own layer.
	for _, first := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, middle := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, last := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run("layers/"+first+"/"+middle+"/"+last, func(t *testing.T) {
					nodeChainAWGCapture(t, []string{"awg2-fast", "awg2-strong", "shadowsocks"}, []string{first, middle, last})
				})
			}
		}
	}
}

func TestNodeChainAWGChangedModeOrPaddingRequiresNewCapture(t *testing.T) {
	nodes := nodeChainModeFixtureNodes(t, []string{"wg", "awg2-fast", "shadowsocks"}, []string{"", "aes-256-gcm", ""})
	original, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
	if err != nil {
		t.Fatal(err)
	}
	launch, err := original.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"mode", "padding", "missing-padding", "plain-wg-source"} {
		t.Run(fault, func(t *testing.T) {
			input := nodes[1].inputs
			if fault == "mode" {
				input.Mode = "awg2-strong"
			} else {
				var assets map[string]string
				if err := json.Unmarshal([]byte(input.Files), &assets); err != nil {
					t.Fatal(err)
				}
				raw := string(mustDecodeChainAsset(t, assets["awg.conf"]))
				switch fault {
				case "padding":
					raw = strings.Replace(raw, "S4=32\n", "S4=48\n", 1)
				case "missing-padding":
					raw = strings.Replace(raw, "S4=32\n", "", 1)
				case "plain-wg-source":
					first, last := strings.Index(raw, "Jc=3\n"), strings.Index(raw, "[Peer]")
					if first < 0 || last < first {
						t.Fatal("missing original AWG fixture parameters")
					}
					raw = raw[:first] + raw[last:]
				}
				assets["awg.conf"] = base64.StdEncoding.EncodeToString([]byte(raw))
				input.Files = startJSON(t, assets)
			}
			node, err := NewNodeProfile(input.Mode, input.Files, input.ProfileJSON, input.Start, input.DNSBootstrap)
			if fault == "missing-padding" || fault == "plain-wg-source" {
				if err == nil {
					t.Fatal("ordered AWG source silently downgraded missing native parameters", fault)
				}
				return
			}
			if err != nil {
				t.Fatal("valid changed AWG source must remain independently capturable", err)
			}
			changed := append([]*NodeProfile(nil), nodes...)
			changed[1] = node
			source := nodeChainFixtureSource(t, changed)
			next, err := NewNodeChain(startJSON(t, source))
			if err != nil || next.SourceSHA256() == original.SourceSHA256() || next.ConfigSHA256() == original.ConfigSHA256() {
				t.Fatal("different AWG mode or native padding reused the old path identity", err)
			}
			var receipt nodeChainLaunchRecord
			if err := json.Unmarshal([]byte(launch), &receipt); err != nil {
				t.Fatal(err)
			}
			receipt.NodeChainSource = source
			if _, err := ParseNodeChainLaunchInput(startJSON(t, receipt)); err == nil {
				t.Fatal("stale launch receipt adopted a different AWG mode or native padding")
			}
		})
	}
}

func nodeChainAWGCapture(t *testing.T, modes, layers []string) *NodeChain {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	source := nodeChainFixtureSource(t, nodes)
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal("complete captured WG/AWG ordered path", err)
	}
	graph := importedPQGraph(t, chain.Config())
	endpoints := graph["endpoints"].([]any)
	if len(endpoints) != len(nodes)-1 || len(graph["inbounds"].([]any)) != 1 || chain.Progress().Ready {
		t.Fatal("ordered AWG path lost a prefix, added a TUN or invented live proof")
	}
	proofs := chain.ProofInventory()
	for position, node := range nodes {
		layer := layers[position]
		if layer == "" {
			layer = "off"
		}
		if proofs[position].Mode != modes[position] || proofs[position].StartLayer != layer ||
			proofs[position].SourceSHA256 != node.SourceSHA256() {
			t.Fatal("a selected raw mode, independent layer or source identity changed", position)
		}
		input, err := node.LaunchInput()
		if err != nil || input != source.Nodes[position] {
			t.Fatal("composition rewrote an original node capture", position, err)
		}
		if position == len(nodes)-1 {
			continue
		}
		original := importedPQGraph(t, node.Config())["endpoints"].([]any)[0].(map[string]any)
		actual := endpoints[position].(map[string]any)
		want := "wireguard"
		if modes[position] != "wg" {
			want = AmneziaType
		}
		if actual["type"] != want || actual["tag"] != proofs[position].Tag {
			t.Fatal("a selected AWG endpoint was downgraded or replaced", position)
		}
		for _, field := range []string{"type", "private_key", "address", "peers", "amnezia"} {
			if !reflect.DeepEqual(original[field], actual[field]) {
				t.Fatal("composition changed captured packet identity or AWG parameters", position, field)
			}
		}
		if want == AmneziaType {
			if _, err := AmneziaRuntimeConfig(startJSON(t, actual)); err != nil {
				t.Fatal("composed endpoint lost its native AWG ownership", err)
			}
		}
	}
	physical, err := chain.PhysicalEgress()
	first, firstErr := nodes[0].PhysicalEgress()
	if err != nil || firstErr != nil || !reflect.DeepEqual(physical, first) {
		t.Fatal("an AWG middle or final acquired an independent physical exception", err, firstErr)
	}
	dns := graph["dns"].(map[string]any)
	found := false
	for _, raw := range dns["servers"].([]any) {
		resolver := raw.(map[string]any)
		if resolver["tag"] == dns["final"] {
			found = resolver["detour"] == chain.FinalTag() && resolver["server"] == nodes[len(nodes)-1].profile["adguard_ipv4"]
		}
	}
	if !found {
		t.Fatal("selected final DNS escaped the complete WG/AWG prefix")
	}
	launch, err := chain.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := ParseNodeChainLaunchInput(launch)
	if err != nil || reopened.Config() != chain.Config() || reopened.Metadata() != chain.Metadata() {
		t.Fatal("child replay did not retain the complete mixed packet graph", err)
	}
	return chain
}

func TestNodeChainAWGCanonicalIndependentPacketPeers(t *testing.T) {
	for _, pair := range [][2]string{{"wg", "awg2-fast"}, {"awg2-strong", "wg"}, {"awg2-fast", "awg2-strong"}, {"awg2-strong", "awg2-fast"}} {
		for _, fault := range []string{"client", "clamped-client-alias", "server", "server-high-bit-alias"} {
			t.Run(pair[0]+"/"+pair[1]+"/"+fault, func(t *testing.T) {
				nodes := nodeChainModeFixtureNodes(t, []string{pair[0], pair[1], "shadowsocks"}, []string{"", "", ""})
				// An AWG peer key need not be the Router's separate WG proof
				// identity. Keep those identities distinct so duplicate server
				// rejection exercises the packet key inventory itself.
				if pair[0] != "wg" {
					profile := predecessorCopy(nodes[0].profile)
					profile["node_proof_id"] = externalDigest([]byte("independent-original-Router-identity"))
					input := nodes[0].inputs
					var err error
					nodes[0], err = NewNodeProfile(input.Mode, input.Files, startJSON(t, profile), input.Start, input.DNSBootstrap)
					if err != nil {
						t.Fatal(err)
					}
				}
				first := importedPQGraph(t, nodes[0].Config())["endpoints"].([]any)[0].(map[string]any)
				second := importedPQGraph(t, nodes[1].Config())["endpoints"].([]any)[0].(map[string]any)
				input := nodes[1].inputs
				profile := predecessorCopy(nodes[1].profile)
				var assets map[string]string
				if err := json.Unmarshal([]byte(input.Files), &assets); err != nil {
					t.Fatal(err)
				}
				asset := "awg.conf"
				if pair[1] == "wg" {
					asset = "wg.conf"
				}
				raw := string(mustDecodeChainAsset(t, assets[asset]))
				if fault == "client" || fault == "clamped-client-alias" {
					key := mustDecodeChainAsset(t, first["private_key"].(string))
					if fault == "clamped-client-alias" {
						key[0] ^= 7
						key[31] ^= 128
					}
					raw = strings.Replace(raw, second["private_key"].(string), base64.StdEncoding.EncodeToString(key), 1)
				} else {
					public := first["peers"].([]any)[0].(map[string]any)["public_key"].(string)
					if fault == "server-high-bit-alias" {
						key := mustDecodeChainAsset(t, public)
						key[31] ^= 128
						public = base64.StdEncoding.EncodeToString(key)
					}
					raw = strings.Replace(raw, second["peers"].([]any)[0].(map[string]any)["public_key"].(string), public, 1)
					if pair[1] == "wg" {
						profile["node_proof_id"] = externalDigest([]byte("router-vpn-node-proof-v1\n" + public))
					}
				}
				assets[asset] = base64.StdEncoding.EncodeToString([]byte(raw))
				changed, err := NewNodeProfile(input.Mode, startJSON(t, assets), startJSON(t, profile), input.Start, input.DNSBootstrap)
				if err != nil {
					t.Fatal("control requires a valid original single-node packet source", err)
				}
				nodes[1] = changed
				if nodes[0].profile["node_proof_id"] == changed.profile["node_proof_id"] {
					t.Fatal("packet key control accidentally duplicated the separate Router identity")
				}
				if _, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes))); err == nil {
					t.Fatal("duplicate or noncanonical WG/AWG key became another selected prefix", fault)
				}
			})
		}
	}
}

func TestNodeChainAWGProjectionAndMTUPreserveCapturedPadding(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				chain := nodeChainAWGCapture(t, []string{"wg", mode, "shadowsocks"}, []string{"", layer, ""})
				plan, err := chain.MTUPlan()
				if err != nil || len(plan.Prefixes) != 3 || plan.Ceiling < 1280 {
					t.Fatal("mixed packet graph lost a prefix envelope", err)
				}
				graph := importedPQGraph(t, chain.Config())
				endpoint := graph["endpoints"].([]any)[1].(map[string]any)
				if endpoint["amnezia"].(map[string]any)["s4"] != "32" {
					t.Fatal("original AWG transport padding was lost")
				}
				for _, target := range []string{"linux", "windows", "darwin", "ios", "android"} {
					projected, err := ProjectNodeChain(chain, target, 1280)
					if err != nil {
						t.Fatal(target, err)
					}
					actual := importedPQGraph(t, projected.Config())
					for _, field := range []string{"endpoints", "outbounds", "route", "dns"} {
						if !reflect.DeepEqual(graph[field], actual[field]) {
							t.Fatal("platform projection changed an original AWG policy", target, field)
						}
					}
					launch, err := projected.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					reopened, err := ParseNodeChainLaunchInput(launch)
					if err != nil || reopened.Config() != projected.Config() || reopened.SourceSHA256() != chain.SourceSHA256() {
						t.Fatal("platform replay lost its selected AWG mode", err)
					}
				}
				controllerPlan, err := chain.PlanForMTU(chain.Config(), plan.Original)
				if err != nil || controllerPlan.Ceiling != plan.Ceiling {
					t.Fatal("the captured AWG envelope lost its controller plan", err)
				}
				for _, mtu := range controllerPlan.Candidates(plan.Ceiling) {
					candidate, err := controllerPlan.Config(mtu)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := chain.PlanForMTU(candidate, mtu); err != nil {
						t.Fatal("TUN-only readback lost its AWG owners", err)
					}
				}
				endpoint["amnezia"].(map[string]any)["s4"] = "0"
				if _, err := chain.PlanForMTU(startJSON(t, graph), plan.Original); err == nil {
					t.Fatal("MTU readback silently discarded the captured AWG padding")
				}
			})
		}
	}
	// The same original first-node capacity must reserve AWG's extra S4
	// transport padding before admitting the middle endpoint's packet MTU.
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(fmt.Sprint("fixed/", mode), func(t *testing.T) {
			nodes := nodeChainModeFixtureNodes(t, []string{"wg", mode, "shadowsocks"}, []string{"", "", ""})
			input := nodes[0].inputs
			profile := predecessorCopy(nodes[0].profile)
			profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1408)
			var err error
			nodes[0], err = NewNodeProfile(input.Mode, input.Files, startJSON(t, profile), input.Start, input.DNSBootstrap)
			if err != nil {
				t.Fatal(err)
			}
			chain, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := chain.MTUPlan()
			want := 1344
			if mode != "wg" {
				want = 1312
			}
			if err != nil || plan.Ceiling != want {
				t.Fatal("AWG packet envelope was calculated as plain WG", mode, plan, err)
			}
			middle := importedPQGraph(t, chain.Config())["endpoints"].([]any)[1].(map[string]any)
			if middle["mtu"] != float64(want) {
				t.Fatal("compiled middle endpoint did not reserve its captured AWG padding", mode, middle["mtu"])
			}
			if _, err := ProjectNodeChain(chain, "android", want+16); err == nil {
				t.Fatal("restored TUN exceeded its captured mixed packet ceiling")
			}
		})
	}
}
