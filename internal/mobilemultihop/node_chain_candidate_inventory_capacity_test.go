package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func completeCandidateInventoryFixture(t *testing.T, count int) []string {
	t.Helper()
	input, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	var original nodeChainImportedInput
	if err := json.Unmarshal([]byte(input), &original); err != nil {
		t.Fatal(err)
	}
	inputs := make([]string, count)
	for i := range inputs {
		capture := externalTestRead(t, original.Capture)
		id := fmt.Sprintf("linked-candidate-%04d", i)
		capture["profile"].(map[string]any)["id"], capture["exit_id"] = id, id
		var err error
		inputs[i], err = NodeChainImportedMemberInput(original.Config, startJSON(t, capture))
		if err != nil {
			t.Fatal(err)
		}
	}
	return inputs
}

func TestNodeChainCandidateInventoryKeepsEveryLinkedSource(t *testing.T) {
	chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
	if err != nil {
		t.Fatal(err)
	}
	inputs := completeCandidateInventoryFixture(t, 129)
	for _, count := range []int{0, 1, 63, 64, 65, 128, 129} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			inventory := candidateInventoryFixture(t, "whole-linked-revision", inputs[:count]...)
			plan, err := chain.NewCandidatePlan(0, inventory)
			if count == 0 {
				if err == nil {
					t.Fatal("empty inventory gained a measurement owner")
				}
				return
			}
			if err != nil {
				t.Fatal("complete bounded inventory rejected", err)
			}
			var metadata struct {
				Targets []struct {
					ID string `json:"id"`
				} `json:"targets"`
			}
			if json.Unmarshal([]byte(plan.Metadata()), &metadata) != nil || len(metadata.Targets) != count {
				t.Fatal("catalog silently omitted a linked source")
			}
			for i, target := range metadata.Targets {
				if target.ID != fmt.Sprintf("linked-candidate-%04d", i) {
					t.Fatal("candidate order or original identity changed", i, target.ID)
				}
			}
			if plan.inventory != inventory || plan.chain != chain || plan.prefix != chain.proofs[0] {
				t.Fatal("large inventory borrowed a new chain or a partial source")
			}
			if strings.Contains(plan.Metadata(), "198.51.100.") || strings.Contains(plan.Metadata(), "password") {
				t.Fatal("public catalog contains private source material")
			}
		})
	}
}

func TestOrdinaryCandidateSnapshotRejectsChangedOriginals(t *testing.T) {
	inputs := completeCandidateInventoryFixture(t, 65)
	for name, mutate := range map[string]func(*NodeChainCandidatePlan){
		"last-address":  func(p *NodeChainCandidatePlan) { p.targets[64].Address = "203.0.113.29:8443" },
		"last-identity": func(p *NodeChainCandidatePlan) { p.targets[64].ID += "-changed" },
		"last-source":   func(p *NodeChainCandidatePlan) { p.targets[64].SourceSHA256 = strings.Repeat("e", 64) },
		"omitted-last":  func(p *NodeChainCandidatePlan) { p.targets = p.targets[:64] },
		"target-order": func(p *NodeChainCandidatePlan) {
			p.targets[0], p.targets[64] = p.targets[64], p.targets[0]
		},
		"inventory": func(p *NodeChainCandidatePlan) { p.inventory += " " },
		"revision":  func(p *NodeChainCandidatePlan) { p.revision += "-new-generation" },
		"capture":   func(p *NodeChainCandidatePlan) { p.capture = strings.Repeat("a", 64) },
		"prefix":    func(p *NodeChainCandidatePlan) { p.prefix.ProfileID += "-changed" },
		"source":    func(p *NodeChainCandidatePlan) { p.chain.sourceJSON += " " },
	} {
		t.Run(name, func(t *testing.T) {
			chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "immutable-linked-revision", inputs...))
			if err != nil || plan.validate() != nil || plan.Metadata() == "" {
				t.Fatal("original complete catalog was refused", err)
			}
			mutate(plan)
			if plan.validate() == nil || plan.Metadata() != "" {
				t.Fatal("cached candidate digest accepted changed original source")
			}
		})
	}
}

func TestNodeChainExecutionLargeCatalogRetainsOneSelectedTrial(t *testing.T) {
	inputs := completeCandidateInventoryFixture(t, 65)
	for _, outcome := range []string{"server", "compare-local", "compare-server"} {
		t.Run(outcome, func(t *testing.T) {
			f, _, _, _ := entryFixture(t, outcome)
			entryMaintainServerProof(t, f)
			inventory := candidateInventoryFixture(t, "complete-linked-selected-revision", inputs...)
			p, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 0, inventory)
			if err != nil {
				t.Fatal("selected owner rejected complete inventory", err)
			}
			o := &executionEntryOwner{nodeChainExecutionMeasurementTestOwner: &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}, capture: p.CaptureSHA256()}
			count := entryTarget(t, f, p, p.plan.targets[0].Address)
			s := entryMeasurement(t, p, o)
			for _, i := range []int{0, 64} {
				id := fmt.Sprintf("%032x", i+1)
				if err := s.Start(id, p.plan.targets[i].ID); err != nil {
					t.Fatal(err)
				}
				entryWait(t, s)
				if err := s.Drain(id); err != nil {
					t.Fatal(err)
				}
				state := entryStatus(t, s)
				if !state.Complete || !state.Drained || state.Failure != "" || len(state.Results) != 1 || !state.Results[0].Ready ||
					state.CandidateID != p.plan.targets[i].ID || state.CandidateSourceSHA256 != p.plan.targets[i].SourceSHA256 ||
					state.Results[0].Benchmark == nil || state.Results[0].Benchmark.Attempts != 50 {
					t.Fatal("large selected inventory lost an original fifty-sample result", state)
				}
				if f.runtime.active != p.trial || f.runtime.engine != p.native || f.runtime.Progress().Execution != p.trial.execution {
					t.Fatal("moving beyond candidate 64 replaced the selected trial")
				}
			}
			if count.Load() != 100 || o.active.Load() || o.releases.Load() != 2 {
				t.Fatal("selected inventory did not join both actual fifty-connection measurements", count.Load())
			}
			o.catalogErr.Store(true)
			if err := s.Start(strings.Repeat("c", 32), p.plan.targets[32].ID); err == nil {
				_ = s.Drain(strings.Repeat("c", 32))
			}
			if count.Load() != 100 {
				t.Fatal("changed catalog revived the original selected inventory")
			}
		})
	}
}

func TestNodeChainCandidateMetadataPagesPreserveCompleteOriginalCatalog(t *testing.T) {
	chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
	if err != nil {
		t.Fatal(err)
	}
	inputs := completeCandidateInventoryFixture(t, 513)
	source := candidateInventoryFixture(t, "full-original-source-revision", inputs...)
	p, err := chain.NewCandidatePlan(0, source)
	if err != nil {
		t.Fatal(err)
	}
	var complete struct {
		Targets json.RawMessage `json:"targets"`
	}
	if json.Unmarshal([]byte(p.Metadata()), &complete) != nil || len(p.targets) != len(inputs) {
		t.Fatal("full source inventory missing")
	}
	hash := externalDigest(complete.Targets)
	var all []json.RawMessage
	pages := 0
	for offset := 0; offset < len(inputs); {
		wire := p.MetadataPage(int32(offset))
		var frame struct {
			Schema  int
			Capture string            `json:"capture_sha256"`
			Offset  int               `json:"target_offset"`
			Total   int               `json:"target_total"`
			Digest  string            `json:"targets_sha256"`
			Targets []json.RawMessage `json:"targets"`
		}
		if len(wire) > 12<<10 || json.Unmarshal([]byte(wire), &frame) != nil || frame.Schema != 2 || frame.Capture != p.CaptureSHA256() || frame.Offset != offset || frame.Total != len(inputs) || frame.Digest != hash || len(frame.Targets) == 0 {
			t.Fatal("foreign, incomplete or oversized frame", offset)
		}
		offset += len(frame.Targets)
		pages++
		all = append(all, frame.Targets...)
	}
	reconstructed, _ := json.Marshal(all)
	if pages < 2 || !bytes.Equal(reconstructed, complete.Targets) || p.MetadataPage(-1) != "" || p.MetadataPage(int32(len(inputs))) != "" {
		t.Fatal("page reconstruction/offset guard")
	}
	id := p.targets[len(p.targets)-1].ID
	single := p.wireMetadata("packet", p.capture, p.Metadata, 0, id)
	var last struct {
		Offset  int               `json:"target_offset"`
		Targets []json.RawMessage `json:"targets"`
		Digest  string            `json:"targets_sha256"`
	}
	if json.Unmarshal([]byte(single), &last) != nil || last.Offset != len(inputs)-1 || last.Digest != hash || len(last.Targets) != 1 || !bytes.Equal(last.Targets[0], all[len(all)-1]) {
		t.Fatal("selected candidate lost full source binding")
	}
	p.targets[len(p.targets)-1].SourceSHA256 = strings.Repeat("f", 64)
	if p.MetadataPage(0) != "" {
		t.Fatal("changed off-page input retained cache authority")
	}
	t.Logf("%d original sources, %d contiguous native pages, full digest and last-selection membership verified", len(all), pages)
}
