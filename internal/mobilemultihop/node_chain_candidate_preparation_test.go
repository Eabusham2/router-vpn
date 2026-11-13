package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func candidatePreparationFixture(t *testing.T, modes, layers []string, position int) (*NodeChainCandidatePreparation, []*NodeProfile, string) {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	target, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	inventory := candidateInventoryFixture(t, "original-candidate-catalog", target)
	p, err := NewNodeChainCandidatePreparation(startJSON(t, nodeChainFixtureSource(t, nodes)), position, inventory)
	if err != nil {
		t.Fatal("original prefix preparation", err)
	}
	return p, nodes, inventory
}

func TestNodeChainCandidatePreparationProjectsOnlySelectedPrefix(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, count := range []int{2, 3, 4, 8} {
			modes, layers := make([]string, count), make([]string, count)
			for i := range modes {
				modes[i] = mode
			}
			modes[count-1] = "shadowsocks"
			for position := 0; position < count-1; position++ {
				p, nodes, _ := candidatePreparationFixture(t, modes, layers, position)
				graph := externalTestRead(t, p.Config())
				original := externalTestRead(t, p.original.Config())
				if !reflect.DeepEqual(graph["inbounds"], original["inbounds"]) || !reflect.DeepEqual(graph["route"].(map[string]any)["rules"], original["route"].(map[string]any)["rules"]) {
					t.Fatal("temporary prefix replaced saved TUN/policy")
				}
				if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
					t.Fatal("candidate source opened application/DNS ingress")
				}
				gate := externalTestFind(t, graph, NodeChainExecutionGateTag)
				if len(gate) != 3 || gate["type"] != NodeChainExecutionGateType || gate["detour"] != SelectorTag {
					t.Fatal("candidate source replaced default-closed native gate", gate)
				}
				selector := externalTestFind(t, graph, SelectorTag)
				if !reflect.DeepEqual(selector["outbounds"], []any{p.proofs[position].Tag}) || selector["default"] != p.proofs[position].Tag {
					t.Fatal("preparation selector reached an unselected suffix")
				}
				for i, node := range nodes {
					for _, secret := range []string{predecessorText(node.profile, "router_api"), predecessorText(node.profile, "api_token")} {
						if strings.Contains(p.Metadata(), secret) {
							t.Fatal("public preparation metadata leaked private proof")
						}
					}
					if i > position && (strings.Contains(p.Config(), predecessorText(node.profile, "endpoint")) || strings.Contains(p.Config(), p.original.proofs[i].Tag)) {
						t.Fatal("preparation constructed unreachable suffix endpoint", i, position)
					}
				}
				if len(p.ProofInventory()) != position+1 || !reflect.DeepEqual(p.proofs, p.original.proofs[:position+1]) {
					t.Fatal("preparation fabricated/omitted selected prefix proofs")
				}
				physical, err := p.PhysicalEgress()
				if err != nil || !nodeChainSamePhysical(physical, p.original.physical) {
					t.Fatal("prefix acquired another physical route", err)
				}
				mtu, err := p.MTUPlan()
				if err != nil || len(mtu.Prefixes) != position+1 || mtu.Original > mtu.Ceiling {
					t.Fatal("prefix lost configured actual/ceiling separation", mtu, err)
				}
				meta := externalTestRead(t, p.Metadata())
				if meta["ready"] != false || meta["application_open"] != false || meta["dns_open"] != false || meta["stage"] != "pending-prefix-proof" {
					t.Fatal("socket-free capture became live connected proof")
				}
				round, err := ParseNodeChainCandidatePreparation(p.Source())
				if err != nil || round.Config() != p.Config() || round.CaptureSHA256() != p.CaptureSHA256() {
					t.Fatal("private launch did not reconstruct original prefix", err)
				}
			}
		}
	}
}

func TestNodeChainCandidatePreparationRetainsIndependentLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			p, _, _ := candidatePreparationFixture(t, []string{mode, mode, "shadowsocks"}, []string{layer, layer, ""}, 1)
			expected := layer
			if expected == "" {
				expected = "off"
			}
			for _, proof := range p.proofs {
				if proof.StartLayer != expected {
					t.Fatal("prefix discarded independently captured layer", proof)
				}
			}
		}
	}
}

func TestNodeChainCandidatePreparationSuffixIsOnlySaveProvenance(t *testing.T) {
	p, nodes, inventory := candidatePreparationFixture(t, []string{"wg", "awg2-fast", "shadowsocks"}, []string{"", "", ""}, 0)
	last := nodes[len(nodes)-1]
	profile := predecessorCopy(last.profile)
	profile["router_api"], profile["api_token"] = "http://10.199.0.1:8787", "unreachable-saved-final-token"
	changed, err := NewNodeProfile(last.mode, last.inputs.Files, startJSON(t, profile), last.inputs.Start, "")
	if err != nil {
		t.Fatal(err)
	}
	nodes[len(nodes)-1] = changed
	other, err := NewNodeChainCandidatePreparation(startJSON(t, nodeChainFixtureSource(t, nodes)), 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if other.Config() != p.Config() || other.SourceSHA256() == p.SourceSHA256() || other.CaptureSHA256() == p.CaptureSHA256() || other.OriginalSourceSHA256() == p.OriginalSourceSHA256() {
		t.Fatal("uncontacted final provenance was lost or became runtime suffix dependency")
	}
	if strings.Contains(other.Config(), "unreachable-saved-final-token") || strings.Contains(other.Config(), "10.199.0.1") {
		t.Fatal("preparation attempted to configure old final proof")
	}
}

func TestNodeChainCandidatePreparationRejectsChangedAuthority(t *testing.T) {
	p, _, inventory := candidatePreparationFixture(t, []string{"wg", "awg2-strong", "shadowsocks"}, []string{"", "", ""}, 1)
	for _, position := range []int{-1, 2, 3, NodeChainMaximumNodes} {
		if _, err := NewNodeChainCandidatePreparation(p.original.sourceJSON, position, inventory); err == nil {
			t.Fatal("unsupported/foreign prefix admitted", position)
		}
	}
	for _, change := range []string{"unknown", "kind", "schema", "position", "source", "inventory"} {
		record := externalTestRead(t, p.Source())
		switch change {
		case "unknown":
			record["config"] = p.Config()
		case "kind":
			record["kind"] = "routervpn-node-chain-launch-input"
		case "schema":
			record["schema"] = 2
		case "position":
			record["prefix_position"] = 2
		case "source":
			record["original_source"] = "{}"
		case "inventory":
			record["inventory"] = "{}"
		}
		raw, _ := json.Marshal(record)
		if _, err := ParseNodeChainCandidatePreparation(string(raw)); err == nil {
			t.Fatal("mutated private capture admitted", change)
		}
	}
	if _, err := ParseNodeChainCandidatePreparation(" " + p.Source()); err == nil {
		t.Fatal("noncanonical private source admitted")
	}
	for _, mutate := range []func(*NodeChainCandidatePreparation){
		func(v *NodeChainCandidatePreparation) {
			v.config = strings.Replace(v.config, NodeChainExecutionGateTag, SelectorTag, 1)
		},
		func(v *NodeChainCandidatePreparation) { v.proofs[0].Tag = "other" },
		func(v *NodeChainCandidatePreparation) { v.mtu.Ceiling = 9000 },
		func(v *NodeChainCandidatePreparation) { v.position = 0 },
		func(v *NodeChainCandidatePreparation) { v.candidates.targets[0].Address = "192.0.2.99:443" },
	} {
		fresh, err := ParseNodeChainCandidatePreparation(p.Source())
		if err != nil {
			t.Fatal(err)
		}
		mutate(fresh)
		if fresh.validate() == nil || fresh.Config() != "" || fresh.Metadata() != "" || fresh.Source() != "" {
			t.Fatal("changed sealed preparation remained usable")
		}
	}
	proofs := p.ProofInventory()
	proofs[0].Tag = "other"
	mtu, _ := p.MTUPlan()
	mtu.Prefixes[0].Ceiling = 1
	if p.validate() != nil || p.ProofInventory()[0].Tag == "other" {
		t.Fatal("read-only preparation getter leaked mutable authority")
	}
}
