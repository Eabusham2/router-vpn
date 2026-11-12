package mobilemultihop

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Native observation and retirement are explicit boundary doubles. The real
// runtime, pause/resume, authenticated HTTP and exact remote cleanup execute.
type nodeChainExecutionHealthEngine struct {
	*nodeChainExecutionMTUEngine
	observations, revocations atomic.Int32
	holdObservation           atomic.Bool
	holdRevoke                atomic.Bool
	observationEntered        chan struct{}
	observationRelease        chan struct{}
	revokeEntered             chan struct{}
	revokeRelease             chan struct{}
}

func (e *nodeChainExecutionHealthEngine) ObserveChainContext(ctx context.Context) (NodeChainIdentity, error) {
	e.observations.Add(1)
	if e.holdObservation.CompareAndSwap(true, false) {
		close(e.observationEntered)
		<-e.observationRelease
	}
	return e.nodeChainExecutionMTUEngine.ObserveChainContext(ctx)
}

func (e *nodeChainExecutionHealthEngine) RevokeApplicationContext(ctx context.Context) error {
	e.revocations.Add(1)
	if e.holdRevoke.CompareAndSwap(true, false) {
		close(e.revokeEntered)
		<-e.revokeRelease
	}
	return e.nodeChainExecutionMTUEngine.RevokeApplicationContext(ctx)
}

func nodeChainExecutionHealthFixture(t *testing.T) (*nodeChainExecutionRuntimeFixture, *nodeChainExecutionHealthEngine, context.Context) {
	t.Helper()
	var original *nodeChainExecutionHealthEngine
	f, _, ctx := nodeChainExecutionMTUFixture(t, "server", func(f *nodeChainExecutionRuntimeFixture, e *nodeChainExecutionMTUEngine) {
		original = &nodeChainExecutionHealthEngine{nodeChainExecutionMTUEngine: e,
			observationEntered: make(chan struct{}), observationRelease: make(chan struct{}),
			revokeEntered: make(chan struct{}), revokeRelease: make(chan struct{})}
		f.runtime.engine = original
	})
	return f, original, ctx
}

func TestNodeChainExecutionHealthyRetainsLateObservationAndRevokeBeforeResume(t *testing.T) {
	f, e, ctx := nodeChainExecutionHealthFixture(t)
	var observationOnce, revokeOnce sync.Once
	releaseObservation := func() { observationOnce.Do(func() { close(e.observationRelease) }) }
	releaseRevoke := func() { revokeOnce.Do(func() { close(e.revokeRelease) }) }
	t.Cleanup(releaseObservation)
	t.Cleanup(releaseRevoke)
	e.holdObservation.Store(true)
	done := make(chan error, 1)
	go func() { done <- f.runtime.HealthyContext(ctx) }()
	select {
	case <-e.observationEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("original health observation did not enter")
	}

	binding, err := f.runtime.PauseMTUContext(ctx)
	if err == nil || binding.Nonce() == "" {
		t.Fatal("MTU pause acknowledged an entered original health observation", err)
	}
	if binding.ValidateClosedContext(ctx) == nil || e.change(ctx, binding) == nil {
		t.Fatal("unjoined original observation admitted native reader replacement")
	}
	if _, err := NewNodeChainExecutionMTUResumeRuntime(ctx, binding); err == nil || e.admitted.Load() != 0 {
		t.Fatal("unjoined original observation admitted same-Box successor")
	}

	// Close has already joined its own watch/trial. The delayed health failure
	// now enters its own revoke; that last native call must remain owned too.
	e.holdRevoke.Store(true)
	releaseObservation()
	select {
	case <-e.revokeEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("late original health failure did not revoke")
	}
	if err := f.runtime.CloseContext(ctx); err == nil {
		t.Fatal("runtime acknowledged cleanup before late health revoke joined")
	}
	if binding.ValidateClosedContext(ctx) == nil {
		t.Fatal("late health revoke lost original pause ownership")
	}
	releaseRevoke()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("retired late observation reported healthy")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original health observation did not join")
	}
	again, err := f.runtime.PauseMTUContext(ctx)
	if err != nil || again != binding || binding.ValidateClosedContext(ctx) != nil {
		t.Fatal("joined health observation lost exact pause retry", err)
	}
	if err := e.change(ctx, binding); err != nil {
		t.Fatal(err)
	}
	resumed := nodeChainExecutionMTUResume(t, f, ctx, binding)
	if err := resumed.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := resumed.HealthyContext(ctx); err != nil || !resumed.Progress().Ready {
		t.Fatal("joined original observation prevented fresh selected proof", err)
	}
}

func TestNodeChainExecutionHealthyStaleEntryCannotRevokeResumedOwner(t *testing.T) {
	f, e, ctx := nodeChainExecutionHealthFixture(t)
	binding, err := f.runtime.PauseMTUContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.change(ctx, binding); err != nil {
		t.Fatal(err)
	}
	resumed := nodeChainExecutionMTUResume(t, f, ctx, binding)
	if err := resumed.Run(ctx); err != nil {
		t.Fatal(err)
	}
	observations, revocations := e.observations.Load(), e.revocations.Load()
	if err := f.runtime.HealthyContext(ctx); err == nil {
		t.Fatal("closed original runtime reported healthy")
	}
	if e.observations.Load() != observations || e.revocations.Load() != revocations {
		t.Fatal("stale health entry touched native state owned by resumed runtime")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := resumed.HealthyContext(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled health caller acquired an observation", err)
	}
	if e.observations.Load() != observations || e.revocations.Load() != revocations {
		t.Fatal("canceled health entry touched original native owner")
	}
	if err := resumed.HealthyContext(ctx); err != nil || !resumed.Progress().Ready {
		t.Fatal("stale or canceled health read revoked resumed native owner", err)
	}
}

func TestNodeChainExecutionHealthyCancellationRetainsEnteredObservation(t *testing.T) {
	f, e, ctx := nodeChainExecutionHealthFixture(t)
	var once sync.Once
	release := func() { once.Do(func() { close(e.observationRelease) }) }
	t.Cleanup(release)
	e.holdObservation.Store(true)
	call, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- f.runtime.HealthyContext(call) }()
	select {
	case <-e.observationEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelable original health observation did not enter")
	}
	cancel()
	if err := f.runtime.CloseContext(ctx); err == nil {
		t.Fatal("cancellation discarded an entered original health observation")
	}
	release()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("canceled original observation returned success", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled original health observation did not join")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("joined canceled health observation blocked original cleanup", err)
	}
}
