package hopmeasure

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOrderedLatencyCommittedHistoryNeverObservesOrAdopts(t *testing.T) {
	facade, engine := orderedLatencyFixture(t)
	var observations atomic.Int32
	var refuse atomic.Bool
	engine.before = func(ctx context.Context) error {
		observations.Add(1)
		if refuse.Load() {
			return errors.New("original native receipt unavailable")
		}
		return ctx.Err()
	}
	hop, first := facade.service.hops[0].ID, strings.Repeat("1", 32)
	if err := facade.Start(first, hop); err != nil {
		t.Fatal(err)
	}
	if err := facade.DrainContext(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	before := observations.Load()
	if facade.CommittedJSON(hop) != "" || observations.Load() != before {
		t.Fatal("historical read observed or adopted the pending fifty result")
	}
	refuse.Store(true)
	if facade.SavedJSON(hop) != "" {
		t.Fatal("pending receipt committed without fresh original native proof")
	}
	refuse.Store(false)
	saved := facade.SavedJSON(hop)
	if saved == "" {
		t.Fatal("joined original fifty result did not commit")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	engine.releaseHook = func() { close(entered); <-release }
	second := strings.Repeat("2", 32)
	if err := facade.Start(second, hop); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("second fifty worker never entered original release")
	}
	before = observations.Load()
	if facade.CommittedJSON(hop) != saved || observations.Load() != before {
		t.Fatal("pending release changed historical bytes or invoked native observation")
	}
	facade.Invalidate()
	if facade.CommittedJSON(hop) != saved || observations.Load() != before {
		t.Fatal("invalidation erased or reobserved committed history")
	}
	unblock()
	if err := facade.Close(); err != nil {
		t.Fatal(err)
	}
	if facade.CommittedJSON(hop) != saved {
		t.Fatal("cancelled second result replaced the original historical receipt")
	}
}

func TestOrderedLatencyDrainContextKeepsOriginalCallerBudget(t *testing.T) {
	for _, fault := range []string{"nil", "cancelled", "deadline"} {
		t.Run(fault, func(t *testing.T) {
			facade, _ := orderedLatencyFixture(t)
			var ctx context.Context
			var expected error
			if fault == "cancelled" {
				call, cancel := context.WithCancel(t.Context())
				cancel()
				ctx, expected = call, context.Canceled
			} else if fault == "deadline" {
				call, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
				defer cancel()
				ctx, expected = call, context.DeadlineExceeded
			}
			facade.service.mu.Lock()
			var once sync.Once
			unlock := func() { once.Do(facade.service.mu.Unlock) }
			defer unlock()
			done := make(chan error, 1)
			go func() { done <- facade.DrainContext(ctx, strings.Repeat("3", 32)) }()
			select {
			case err := <-done:
				if err == nil || expected != nil && !errors.Is(err, expected) {
					t.Fatal("drain lost the original caller's refusal", err)
				}
			case <-time.After(time.Second):
				unlock()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("drain did not join after releasing the original lock")
				}
				t.Fatal("cancelled drain waited for an unrelated original service lock")
			}
		})
	}
}
