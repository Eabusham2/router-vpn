package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"router-vpn/internal/hopmeasure"
)

func TestNodeChainCompareLocalImportedResponseCandidate(t *testing.T) {
	input, err := nodeChainFixtureNodes(t, 8, "")[7].LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	inventory := candidateInventoryFixture(t, "distinct-private-response-candidate", input)
	for _, outcome := range []string{"compare-local", "compare-server", "server"} {
		t.Run(outcome, func(t *testing.T) {
			requested := "auto"
			if outcome == "server" {
				requested = "server"
			}
			f := newNodeChainExecutionRuntimeFixtureFromSource(t, nodeChainImportedPrefixExecutionSource(t, 1, "wg", requested))
			entryRun(t, f, outcome)
			runtime := f.runtime
			trial := runtime.active
			if p, err := runtime.NewRemoteCandidatePlanContext(t.Context(), 1, inventory); p != nil || err == nil {
				t.Fatal("an imported stream acquired a remote connect-only candidate grant")
			}
			p, err := runtime.NewLocalCandidatePlanContext(t.Context(), 1, inventory)
			if outcome != "compare-local" {
				if p != nil || err == nil {
					t.Fatal("a Server winner acquired a Local response plan")
				}
				return
			}
			if err != nil || p == nil {
				t.Fatal("original Compare Local winner refused its three-member response candidate", err)
			}
			var meta struct {
				Requested string `json:"requested_execution"`
				Execution string `json:"execution"`
				Metric    string `json:"measurement"`
				Epoch     uint64 `json:"selection_epoch"`
			}
			if json.Unmarshal([]byte(p.Metadata()), &meta) != nil || meta.Requested != "auto" || meta.Execution != "local" || meta.Metric != hopmeasure.CandidatePrivateResponseMeasurement || meta.Epoch != trial.selectionEpoch || p.trial != trial || trial.tag == "" || runtime.active != trial {
				t.Fatal("response plan changed its original winner, epoch or metric", meta)
			}
			if !strings.Contains(p.MetadataForCandidate(p.plan.targets[0].ID), hopmeasure.CandidatePrivateResponseMeasurement) {
				t.Fatal("paged candidate metadata lost its authenticated response metric")
			}
			currentFinal, err := p.plan.chain.nodes[2].LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			if duplicate, err := runtime.NewLocalCandidatePlanContext(t.Context(), 1, candidateInventoryFixture(t, "same-final", currentFinal)); err == nil || duplicate != nil {
				t.Fatal("an existing final was accepted as its own replacement")
			}
		})
	}
}

func TestCompareLocalPrivatePenultimateCandidate(t *testing.T) {
	input, err := nodeChainFixtureNodes(t, 17, "")[16].LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	inventory := candidateInventoryFixture(t, "separate-private-final", input)
	for _, shape := range []struct{ nodes, private int }{{4, 2}, {9, 7}, {16, 14}, {4, 0}, {9, 0}, {16, 0}, {5, 2}, {9, 2}, {16, 2}} {
		n := shape.nodes
		group := fmt.Sprint(n)
		if shape.private != n-2 {
			group += fmt.Sprintf("/private-%d", shape.private)
		}
		for _, outcome := range []string{"compare-local", "compare-server", "server"} {
			t.Run(group+"/"+outcome, func(t *testing.T) {
				requested := "auto"
				if outcome == "server" {
					requested = "server"
				}
				position := n - 2
				f := multipleImportedExecutionRuntimeFixture(t, selectedPrivateStreamLayout(n, shape.private), requested)
				prep := f.runtime.projection.preparation
				for i := 0; i < n; i++ {
					eligible := i > 0 && i <= position
					if prep.SupportsCompareLocalResponseCandidate(i) != (requested == "auto" && eligible) {
						t.Fatal("source advertised another metric or stop", i)
					}
				}
				entryRun(t, f, outcome)
				t.Cleanup(func() {
					if err := closeRemoteCandidateRuntime(f.runtime); err != nil {
						t.Error(err)
					}
				})
				if p, err := f.runtime.NewRemoteCandidatePlanContext(t.Context(), position, inventory); err == nil || p != nil {
					t.Fatal("private prefix obtained a Server packet stop")
				}
				p, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), position, inventory)
				if outcome != "compare-local" {
					if p != nil || err == nil {
						t.Fatal("private response plan without active Compare Local winner")
					}
					return
				}
				if err != nil || p.plan.multiple == nil || p.plan.multiple.registry != prep.multiple.owners || p.plan.prefix != prep.local.proofs[position] ||
					p.trial != f.runtime.active || p.plan.measurement != hopmeasure.CandidatePrivateResponseMeasurement {
					t.Fatal("lost the original private prefix or sealed source", err)
				}
				originalPaired := []int{n - 1}
				if shape.private > 0 {
					originalPaired = append(originalPaired, shape.private)
				}
				for _, i := range originalPaired {
					duplicate, err := prep.local.nodes[i].LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					if alt, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), position, candidateInventoryFixture(t, "original-member", duplicate)); err == nil || alt != nil {
						t.Fatal("accepted an original member", i)
					}
				}
				target, err := ParseNodeLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"id", "node_proof_id"} {
					value := target.profile[field]
					target.profile[field] = prep.local.nodes[n-1].profile[field]
					alias, err := NewNodeProfile(target.mode, target.inputs.Files, startJSON(t, target.profile), target.inputs.Start, target.inputs.DNSBootstrap)
					if err != nil {
						t.Fatal(err)
					}
					renamed, err := alias.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					if alt, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), position, candidateInventoryFixture(t, "aliased-final", renamed)); err == nil || alt != nil {
						t.Fatal("accepted original final alias", field)
					}
					target.profile[field] = value
				}
				registry := p.plan.multiple.registry
				copy := *registry
				p.plan.multiple.registry = &copy
				if p.CaptureSHA256() != "" {
					t.Fatal("copied registry acquired an original capture")
				}
				p.plan.multiple.registry = registry
				epoch := p.trial.selectionEpoch
				p.trial.selectionEpoch++
				if p.CaptureSHA256() != "" {
					t.Fatal("capture survived a changed selection epoch")
				}
				p.trial.selectionEpoch = epoch
				if p.CaptureSHA256() == "" {
					t.Fatal("original epoch was not restored")
				}
			})
		}
	}
}

func TestCompareLocalImportedIntermediateCandidate(t *testing.T) {
	input, err := nodeChainFixtureNodes(t, 17, "")[16].LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	inventory := candidateInventoryFixture(t, "separate-paired-intermediate", input)
	for _, spec := range []struct{ count, stop int }{{4, 1}, {9, 3}, {16, 12}} {
		for _, outcome := range []string{"compare-local", "compare-server", "server"} {
			t.Run(fmt.Sprintf("%d/%d/%s", spec.count, spec.stop, outcome), func(t *testing.T) {
				requested := "auto"
				if outcome == "server" {
					requested = "server"
				}
				f := multipleImportedExecutionRuntimeFixture(t, selectedPrivateStreamLayout(spec.count, 0), requested)
				entryRun(t, f, outcome)
				t.Cleanup(func() {
					if err := closeRemoteCandidateRuntime(f.runtime); err != nil {
						t.Error(err)
					}
				})
				plan, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), spec.stop, inventory)
				if outcome != "compare-local" {
					if plan != nil || err == nil {
						t.Fatal("unselected trial received intermediate response grant")
					}
					return
				}
				if err != nil || plan == nil {
					t.Fatal(err)
				}
				original := f.runtime.projection.preparation.local
				if plan.plan.prefix != original.proofs[spec.stop] || plan.trial != f.runtime.active || plan.plan.multiple.registry != original.importedNodes || plan.plan.measurement != hopmeasure.CandidatePrivateResponseMeasurement {
					t.Fatal("intermediate plan lost captured stop or owner")
				}
				other, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), spec.stop+1, inventory)
				if err != nil || other.CaptureSHA256() == plan.CaptureSHA256() {
					t.Fatal("two eligible stops shared measurement authority", err)
				}
				target, err := ParseNodeLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
				for _, member := range original.proofs[spec.stop+1:] {
					for field, value := range map[string]string{"id": member.ProfileID, "node_proof_id": member.NodeID} {
						if value == "" {
							continue
						}
						old := target.profile[field]
						target.profile[field] = value
						alias, err := NewNodeProfile(target.mode, target.inputs.Files, startJSON(t, target.profile), target.inputs.Start, target.inputs.DNSBootstrap)
						if err != nil {
							t.Fatal(err)
						}
						source, err := alias.LaunchInput()
						if err != nil {
							t.Fatal(err)
						}
						if p, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), spec.stop, candidateInventoryFixture(t, "suffix-alias", source)); p != nil || err == nil {
							t.Fatalf("accepted unmeasured suffix %s at %d", field, member.Position)
						}
						target.profile[field] = old
					}
				}
			})
		}
	}
}

func TestCompareLocalImportedInsertionCapacity(t *testing.T) {
	for _, n := range []int{95, 96} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			_, preparation, _ := multipleImportedExecutionFixture(t, selectedPrivateStreamLayout(n, 0), "wg", "", "auto", "")
			for _, k := range []int{1, n - 3} {
				if preparation.SupportsCompareLocalResponseCandidate(k) != (n == 95) {
					t.Fatal("insertion exceeds retained source capacity", n, k)
				}
			}
			if !preparation.SupportsCompareLocalResponseCandidate(n - 2) {
				t.Fatal("a full route lost its final replacement")
			}
		})
	}
}
