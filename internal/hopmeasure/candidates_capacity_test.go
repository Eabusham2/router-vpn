package hopmeasure

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestPrefixCandidateLargeInventoryMeasuresFirstAndLast(t *testing.T) {
	_, engine := newCandidateFixture(t)
	targets := make([]CandidateTarget, 129)
	for i := range targets {
		targets[i] = CandidateTarget{ID: fmt.Sprintf("linked-%04d", i), SourceSHA256: fmt.Sprintf("%064x", i+1), Address: engine.target.Address}
	}
	service, err := NewPrefixCandidatesContext(context.Background(), engine, engine.prefix, targets)
	if err != nil {
		t.Fatal("complete linked inventory rejected", err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, i := range []int{0, 128} {
		request := fmt.Sprintf("%032x", i+1)
		if err := service.Start(request, targets[i].ID); err != nil {
			t.Fatal(err)
		}
		if err := service.Drain(request); err != nil {
			t.Fatal(err)
		}
		status := candidateStatus(t, service)
		if !status.Complete || !status.Drained || status.Failure != "" || status.CandidateID != targets[i].ID ||
			status.CandidateSourceSHA256 != targets[i].SourceSHA256 || len(status.Results) != 1 ||
			status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 {
			t.Fatal("boundary candidate did not retain fifty original handshakes", status)
		}
	}
	if engine.dials.Load() != 100 || engine.closed.Load() != 100 || engine.released.Load() != 2 || engine.held.Load() {
		t.Fatal("complete linked inventory changed the original measurement and retirement ownership")
	}
	engine.current.Store(false)
	if err := service.Start(strings.Repeat("e", 32), targets[64].ID); err == nil {
		_ = service.Drain(strings.Repeat("e", 32))
	}
	if engine.dials.Load() != 100 {
		t.Fatal("large inventory revived an invalidated original owner")
	}
}

func TestPrefixCandidateInventoryStillRejectsResourceOverflow(t *testing.T) {
	_, engine := newCandidateFixture(t)
	var targets []CandidateTarget
	for i := 0; CandidateTargetsWithinBudget(targets) || len(targets) == 0; i++ {
		targets = append(targets, CandidateTarget{ID: fmt.Sprintf("linked-%04d", i), SourceSHA256: fmt.Sprintf("%064x", i+1), Address: engine.target.Address})
	}
	if service, err := NewPrefixCandidatesContext(context.Background(), engine, engine.prefix, targets); err == nil || service != nil {
		t.Fatal("native retained inventory exceeded its original message budget")
	}
	if engine.dials.Load() != 0 || engine.held.Load() {
		t.Fatal("oversized inventory acquired a native measurement")
	}
}
