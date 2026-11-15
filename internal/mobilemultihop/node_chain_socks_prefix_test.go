package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNodeChainSOCKSCompletePacketPrefixes(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, authentication := range []string{"password", "none"} {
			for count := 1; count <= 6; count++ {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, authentication, count), func(t *testing.T) {
					input := nodeChainSOCKSPrefixFixture(t, count, mode, "", authentication)
					source, err := NewNodeChainSOCKSSource(startJSON(t, input))
					if err != nil {
						t.Fatal(err)
					}
					config, meta, err := source.ReadValidated()
					if err != nil {
						t.Fatal(err)
					}
					if len(meta.Proofs) != count+2 || len(meta.Devices) != count+2 || len(meta.MTU.Prefixes) != count+2 || meta.MTU.Ceiling < 1280 {
						t.Fatal("original complete inventory/bounds lost", meta.MTU)
					}
					if len(source.pair.nodes) != count+1 || len(meta.Physical) != 1 || meta.Proofs[count].Mode != "socks5" || meta.Proofs[count].NodeID != "" {
						t.Fatal("original typed source changed")
					}
					graph := externalTestRead(t, config)
					for i, proof := range meta.Proofs {
						if proof.Position != i {
							t.Fatal("ordered position changed")
						}
						node := externalTestFind(t, graph, proof.Tag)
						if i > 0 && node["detour"] != meta.Proofs[i-1].Tag {
							t.Fatal("prefix was bypassed", i, node)
						}
						if i < count && proof.Mode != mode {
							t.Fatal("captured packet prefix changed", i)
						}
					}
					if meta.DNS.FinalTag != meta.Proofs[count+1].Tag || meta.Devices[count].KillSwitchPolicy != "always" {
						t.Fatal("final DNS or middle protection replaced")
					}
					runtime, err := NewNodeChainSOCKSRuntime(source)
					if err != nil {
						t.Fatal(err)
					}
					if runtime.chain.nodes[count] != nil {
						t.Fatal("imported member borrowed paired identity")
					}
					for i := 0; i < count; i++ {
						if runtime.chain.nodes[i] != source.pair.nodes[i] {
							t.Fatal("original prefix pointer replaced")
						}
					}
					bound, err := runtime.MTUPlan()
					if err != nil {
						t.Fatal(err)
					}
					plan, err := runtime.PlanForMTU(config, bound.Original)
					if err != nil || plan.Ceiling != bound.Ceiling {
						t.Fatal("actual per-prefix MTU plan changed", err)
					}
					for _, target := range []string{"linux", "windows", "darwin"} {
						policy, err := NewDesktopNodeChainSOCKSPolicy(source, strings.Repeat("a", 32), target, 0)
						if err != nil {
							t.Fatal(target, err)
						}
						_, desktop, physical, err := policy.ReadValidated()
						if err != nil || len(desktop.Prefixes) != count+2 || len(physical.PhysicalRoots) != 1 || desktop.KillSwitchPolicy != "always" || desktop.FinalTag != meta.Proofs[count+1].Tag || desktop.ProfileID != meta.Proofs[count+1].ProfileID || desktop.NodeID != meta.Proofs[count+1].NodeID {
							t.Fatal("desktop owner omitted original member", target, err)
						}
					}
					replay, err := NewNodeChainSOCKSSource(startJSON(t, input))
					if err != nil {
						t.Fatal(err)
					}
					replayConfig, replayMeta, _ := replay.ReadValidated()
					if replayConfig != config || !reflect.DeepEqual(meta, replayMeta) {
						t.Fatal("exact replay changed original source")
					}
				})
			}
		}
	}
}

func TestNodeChainSOCKSPrefixIntegrityAndSourceRefusal(t *testing.T) {
	for _, name := range []string{"foreign-prefix-owner", "prefix-order", "prefix-omission", "prefix-credential", "foreign-middle-owner", "foreign-final-owner", "wrong-final-key", "metadata-order", "runtime-pointer"} {
		t.Run(name, func(t *testing.T) {
			input := nodeChainSOCKSPrefixFixture(t, 3, "wg", "", "password")
			source, err := NewNodeChainSOCKSSource(startJSON(t, input))
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "foreign-prefix-owner":
				copy := *source.pair.nodes[1]
				source.pair.nodes[1] = &copy
			case "prefix-order":
				source.pair.nodes[0], source.pair.nodes[1] = source.pair.nodes[1], source.pair.nodes[0]
			case "prefix-omission":
				source.pair.nodes = source.pair.nodes[1:]
			case "prefix-credential":
				source.pair.nodes[1].profile["api_token"] = "foreign"
			case "foreign-middle-owner":
				copy := *source.middle
				source.middle = &copy
			case "foreign-final-owner":
				copy := *source.pair.nodes[3]
				source.pair.nodes[3] = &copy
			case "wrong-final-key":
				source.pair.nodes[3].inputs.Files += " "
			case "metadata-order":
				source.metadata.Proofs[0], source.metadata.Proofs[1] = source.metadata.Proofs[1], source.metadata.Proofs[0]
			case "runtime-pointer":
				runtime, err := NewNodeChainSOCKSRuntime(source)
				if err != nil {
					t.Fatal(err)
				}
				copy := *runtime.chain.nodes[1]
				runtime.chain.nodes[1] = &copy
				if runtime.chain.validateSOCKSSource() == nil {
					t.Fatal("same-content runtime prefix replaced original")
				}
				return
			}
			if _, _, err := source.ReadValidated(); err == nil {
				t.Fatal("original captured prefix mutation accepted", name)
			}
		})
	}
	for _, name := range []string{"too-short", "too-long", "nonlocal", "middle-first", "middle-not-penultimate", "middle-identity", "missing-prefix-identity", "duplicate-prefix", "wrong-final-mode"} {
		t.Run(name, func(t *testing.T) {
			input := nodeChainSOCKSPrefixFixture(t, 3, "wg", "", "password")
			switch name {
			case "too-short":
				input.Nodes = input.Nodes[3:]
				input.IdentitySources = input.IdentitySources[3:]
			case "too-long":
				for len(input.Nodes) < 9 {
					input.Nodes = append(input.Nodes, input.Nodes[0])
					input.IdentitySources = append(input.IdentitySources, input.IdentitySources[0])
				}
			case "nonlocal":
				input.Execution = "server"
			case "middle-first":
				input.Nodes[0], input.Nodes[3] = input.Nodes[3], input.Nodes[0]
				input.IdentitySources[0], input.IdentitySources[3] = input.IdentitySources[3], input.IdentitySources[0]
			case "middle-not-penultimate":
				input.Nodes[1], input.Nodes[3] = input.Nodes[3], input.Nodes[1]
				input.IdentitySources[1], input.IdentitySources[3] = input.IdentitySources[3], input.IdentitySources[1]
			case "middle-identity":
				input.IdentitySources[3] = input.IdentitySources[0]
			case "missing-prefix-identity":
				input.IdentitySources[1] = ""
			case "duplicate-prefix":
				input.Nodes[1] = input.Nodes[0]
				input.IdentitySources[1] = input.IdentitySources[0]
			case "wrong-final-mode":
				input.Nodes[4] = input.Nodes[1]
				input.IdentitySources[4] = input.IdentitySources[1]
			}
			if _, err := NewNodeChainSOCKSSource(startJSON(t, input)); err == nil {
				t.Fatal("unowned expanded source accepted", name)
			}
		})
	}
}

func TestNodeChainSOCKSPrefixPreservesNativeMTUCeiling(t *testing.T) {
	input := nodeChainSOCKSPrefixFixture(t, 6, "wg", "", "password")
	node, err := ParseNodeLaunchInput(input.Nodes[3])
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if json.Unmarshal([]byte(node.inputs.ProfileJSON), &profile) != nil {
		t.Fatal("profile")
	}
	profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1280)
	changed, err := NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
	if err == nil {
		input.Nodes[3], err = changed.LaunchInput()
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNodeChainSOCKSSource(startJSON(t, input)); err == nil {
		t.Fatal("IPv6 minimum bypassed insufficient captured packet-prefix capacity")
	}
}

func TestNodeChainSOCKSPrefixEveryOriginalOwner(t *testing.T) {
	for position := 0; position < 7; position++ {
		t.Run(fmt.Sprint(position), func(t *testing.T) {
			source, err := NewNodeChainSOCKSSource(startJSON(t, nodeChainSOCKSPrefixFixture(t, 6, "wg", "", "password")))
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := NewNodeChainSOCKSRuntime(source)
			if err != nil {
				t.Fatal(err)
			}
			original := source.pair.nodes[position]
			copy := *original
			source.pair.nodes[position] = &copy
			if _, _, err = source.ReadValidated(); err == nil {
				t.Fatal("same-content member replaced original captured owner", position)
			}
			if _, err = NewNodeChainSOCKSRuntime(source); err == nil {
				t.Fatal("foreign original member acquired new runtime", position)
			}
			source.pair.nodes[position] = original
			if _, _, err = source.ReadValidated(); err != nil {
				t.Fatal("rejected substitution lost original source", err)
			}
			index := position
			if position == 6 {
				index++
			}
			runtime.chain.nodes[index] = &copy
			if runtime.chain.validateCapture() == nil {
				t.Fatal("same-content runtime member replaced original", position)
			}
		})
	}
}
