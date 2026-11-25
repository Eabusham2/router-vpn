package mobilemultihop

import (
	"encoding/json"
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
