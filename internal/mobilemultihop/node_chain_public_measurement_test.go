package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestNodeChainPublicMeasurementCaptureRetainsEveryDevicePolicy(t *testing.T) {
	for _, off := range []int{-1, 0, 1, 2} {
		t.Run(fmt.Sprint(off), func(t *testing.T) {
			source := nodeChainImportedFixture(t, "wg", "")
			original, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			for position, node := range original.nodes {
				mode := "on"
				if position == off {
					mode = "off"
				}
				if position == 1 {
					var member nodeChainImportedInput
					if err := json.Unmarshal([]byte(source.Nodes[1]), &member); err != nil {
						t.Fatal(err)
					}
					capture := externalTestRead(t, member.Capture)
					capture["profile"].(map[string]any)["ipv6_mode"] = mode
					source.Nodes[1], err = NodeChainImportedMemberInput(member.Config, startJSON(t, capture))
				} else {
					input := node.inputs
					profile := predecessorCopy(node.profile)
					profile["ipv6_mode"] = mode
					changed, e := NewNodeProfile(input.Mode, input.Files, startJSON(t, profile), input.Start, input.DNSBootstrap)
					if e != nil {
						t.Fatal(e)
					}
					source.Nodes[position], err = changed.LaunchInput()
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			beforeSource, beforeConfig, beforeDNS := chain.SourceSHA256(), chain.ConfigSHA256(), chain.DNSCapture()
			tag, ipv6, err := chain.PublicMeasurementCapture()
			if err != nil || tag != chain.ProofInventory()[1].Tag || ipv6 != (off < 0) {
				t.Fatalf("wrong sealed middle policy tag=%s ipv6=%t off=%d err=%v", tag, ipv6, off, err)
			}
			if chain.SourceSHA256() != beforeSource || chain.ConfigSHA256() != beforeConfig || chain.DNSCapture() != beforeDNS {
				t.Fatal("measurement capture replaced source or selected DNS")
			}
		})
	}
}

func TestNodeChainPublicMeasurementCaptureRefusesForeignAuthority(t *testing.T) {
	for count := 2; count <= 8; count++ {
		chain := nodeChainFixture(t, count, "")
		tag, ipv6, err := chain.PublicMeasurementCapture()
		if err != nil || tag != "" || ipv6 {
			t.Fatal("private path acquired public hostname authority", count, tag, ipv6, err)
		}
	}
	var absent *NodeChain
	if _, _, err := absent.PublicMeasurementCapture(); err == nil {
		t.Fatal("nil source gained public capture")
	}
	chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
	if err != nil {
		t.Fatal(err)
	}
	chain.proofs[1].Tag = "foreign-middle"
	if _, _, err := chain.PublicMeasurementCapture(); err == nil {
		t.Fatal("mutated proof gained public capture")
	}
}
