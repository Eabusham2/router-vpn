package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func importedMTUChangePacket(t *testing.T, source *NodeChainSource, position int, change func(*nodeProfileInputs, map[string]any)) {
	t.Helper()
	node, err := ParseNodeLaunchInput(source.Nodes[position])
	if err != nil {
		t.Fatal(err)
	}
	input := node.inputs
	profile := predecessorCopy(node.profile)
	change(&input, profile)
	updated, err := NewNodeProfile(input.Mode, input.Files, startJSON(t, profile), input.Start, input.DNSBootstrap)
	if err != nil {
		t.Fatal("invalid independent packet fixture", err)
	}
	source.Nodes[position], err = updated.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	if input.Mode == "wg" {
		source.IdentitySources[position] = input.Files
	}
}

func importedMTUReplaceAsset(t *testing.T, input *nodeProfileInputs, before, after string) {
	t.Helper()
	var assets map[string]string
	if json.Unmarshal([]byte(input.Files), &assets) != nil {
		t.Fatal("lost packet assets")
	}
	name := "wg.conf"
	if input.Mode != "wg" {
		name = "awg.conf"
	}
	raw := string(mustDecodeChainAsset(t, assets[name]))
	if strings.Count(raw, before) != 1 {
		t.Fatal("missing exact fixture input", before)
	}
	assets[name] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(raw, before, after, 1)))
	input.Files = startJSON(t, assets)
}

func importedMTUChangeSS(t *testing.T, source *NodeChainSource, position int, method, host string, keys int) {
	t.Helper()
	var input nodeChainImportedInput
	if json.Unmarshal([]byte(source.Nodes[position]), &input) != nil {
		t.Fatal("lost imported input")
	}
	graph, capture := externalTestRead(t, input.Config), externalTestRead(t, input.Capture)
	profile := capture["profile"].(map[string]any)
	external := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
	out := externalTestFind(t, graph, ExternalFinalTag)
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", size)))
	password := strings.TrimSuffix(strings.Repeat(key+":", keys), ":")
	out["method"], out["password"], out["server"] = method, password, host
	external["method"], external["password"], external["server"] = method, password, host
	var err error
	source.Nodes[position], err = NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
	if keys > 1 {
		// The existing ordered imported-member grammar deliberately refuses
		// identity chains. Envelope arithmetic must not widen that authority.
		if err == nil {
			t.Fatal("ordered import identity-chain boundary disappeared")
		}
		input.Config, input.Capture = startJSON(t, graph), startJSON(t, capture)
		source.Nodes[position] = startJSON(t, input)
		return
	}
	if err != nil {
		t.Fatal("invalid independently imported variant", err)
	}
}

func TestNodeChainMultipleImportedMTUConsecutiveAndLayeredPacket(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+fmt.Sprint(layer), func(t *testing.T) {
				source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"two-before-packet", 5, []int{1, 2}}, mode, "")
				if layer != "" {
					// Reuse the same node's complete layer assets, preserving its
					// inner identity and all independent imported sources.
					layered := nodeChainModeFixtureNodes(t, []string{mode, mode, mode, mode, "shadowsocks"}, []string{"", "", "", layer, ""})
					var err error
					source.Nodes[3], err = layered[3].LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
				}
				raw := startJSON(t, source)
				chain, err := NewNodeChain(raw)
				if err != nil {
					t.Fatal("complete imported packet MTU refused", err)
				}
				graph := externalTestRead(t, chain.Config())
				packet := externalTestFind(t, graph, chain.proofs[3].Tag)
				want := 1824
				if mode != "wg" {
					want = 1792
				}
				if layer != "" {
					want -= 64
				}
				if packet["mtu"] != float64(want) {
					t.Fatal("wrong cumulative original packet cap", packet["mtu"], want)
				}
				if chain.sourceJSON != raw || chain.Progress().Ready {
					t.Fatal("projection changed immutable source or fabricated native readiness")
				}
				plan, err := chain.MTUPlan()
				if err != nil || plan.Original != 1280 {
					t.Fatal("proxy TUN baseline became packet capacity", plan, err)
				}
				for _, position := range []int{1, 2} {
					member := chain.importedSSMemberAt(position)
					closure, err := member.closure()
					if err != nil || closure.tun["mtu"] != float64(1280) {
						t.Fatal("original imported TUN was raised", err)
					}
				}
				input, err := chain.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				reopened, _, err := parseNodeChainLaunchInput(input)
				if err != nil || reopened.Config() != chain.Config() {
					t.Fatal("sealed reparse changed MTU projection", err)
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedMTURetainsCipherAddressAndKeys(t *testing.T) {
	for _, row := range []struct {
		name, method, host string
		keys, want         int
	}{
		{"aes128", "2022-blake3-aes-128-gcm", "203.0.113.42", 1, 1824},
		{"chacha", "2022-blake3-chacha20-poly1305", "203.0.113.42", 1, 1792},
		{"identity-chain-refused", "2022-blake3-aes-256-gcm", "203.0.113.42", 3, 0},
		{"ipv6", "2022-blake3-aes-256-gcm", "2001:db8::42", 1, 1808},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"two-before-packet", 5, []int{1, 2}}, "wg", "")
			importedMTUChangeSS(t, &source, 2, row.method, row.host, row.keys)
			chain, err := NewNodeChain(startJSON(t, source))
			if row.want == 0 {
				if err == nil {
					t.Fatal("packet projection widened the ordered import key grammar")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			graph := externalTestRead(t, chain.Config())
			if got := externalTestFind(t, graph, chain.proofs[3].Tag)["mtu"]; got != float64(row.want) {
				t.Fatal("original carrier details omitted", got, row.want)
			}
			if chain.importedSSMemberAt(2).input != source.Nodes[2] {
				t.Fatal("original imported credentials changed")
			}
		})
	}
}

func TestNodeChainMultipleImportedMTURefusesFixedAndInsufficientBudget(t *testing.T) {
	for _, name := range []string{"fixed-overflow", "too-small-entry", "control-overflow", "fixed-fit"} {
		t.Run(name, func(t *testing.T) {
			mode := "wg"
			if name == "control-overflow" {
				mode = "awg2-fast"
			}
			source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"two-before-packet", 5, []int{1, 2}}, mode, "")
			switch name {
			case "fixed-overflow", "fixed-fit":
				importedMTUChangePacket(t, &source, 3, func(_ *nodeProfileInputs, p map[string]any) {
					p["mtu_policy"] = "fixed"
					p["manual_mtu"] = float64(2000)
					if name == "fixed-fit" {
						p["manual_mtu"] = float64(1280)
					}
				})
			case "too-small-entry":
				importedMTUChangePacket(t, &source, 0, func(in *nodeProfileInputs, _ map[string]any) {
					importedMTUReplaceAsset(t, in, "MTU = 2000", "MTU = 1400")
				})
			case "control-overflow":
				importedMTUChangePacket(t, &source, 0, func(in *nodeProfileInputs, _ map[string]any) {
					importedMTUReplaceAsset(t, in, "MTU = 2000", "MTU = 1500")
				})
				importedMTUChangePacket(t, &source, 3, func(in *nodeProfileInputs, _ map[string]any) {
					importedMTUReplaceAsset(t, in, "S1=56", "S1=1280")
					importedMTUReplaceAsset(t, in, "S4=32", "S4=0")
				})
			}
			chain, err := NewNodeChain(startJSON(t, source))
			if name == "fixed-fit" {
				if err != nil {
					t.Fatal("fitting Fixed request refused", err)
				}
				g := externalTestRead(t, chain.Config())
				if externalTestFind(t, g, chain.proofs[3].Tag)["mtu"] != float64(1280) {
					t.Fatal("fitting Fixed request changed")
				}
			} else if err == nil {
				t.Fatal("unsafe captured packet budget admitted", chain.ConfigSHA256())
			} else if name == "control-overflow" && !strings.Contains(err.Error(), "handshake or control") {
				t.Fatal("control fixture failed before the actual envelope witness", err)
			}
		})
	}
}
