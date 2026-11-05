package mobilemtu

import (
	"context"
	"errors"
	"router-vpn/internal/hopmeasure"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOperationSharedCleanupProviderSingleActivation(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	defer stop()
	var calls atomic.Int32
	var once sync.Once
	entered := make(chan struct{})
	release := make(chan struct{})
	work, finish, err := WithOperationContextProvider(parent, time.Second, time.Second, func(ctx context.Context) (time.Time, error) {
		calls.Add(1)
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		}
		d, _ := ctx.Deadline()
		return d, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	const n = 8
	results := make(chan context.Context, n)
	errs := make(chan error, n)
	for range n {
		go func() { ctx, e := OperationCleanupContext(work); results <- ctx; errs <- e }()
	}
	<-entered
	stop()
	close(release)
	var first context.Context
	for range n {
		ctx := <-results
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = ctx
		}
		if ctx != first || ctx.Err() != nil || !SameOperationContext(work, ctx) {
			t.Fatal("shared cleanup replaced original authority or inherited expired work")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("provider activated repeatedly", calls.Load())
	}
	finish()
	if first.Err() == nil {
		t.Fatal("finished run retained cleanup authority")
	}
}
func TestOperationSharedCleanupProviderCannotRenewOrRetryFailure(t *testing.T) {
	for _, kind := range []string{"renew", "failure", "expired"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			work, finish, err := WithOperationContextProvider(context.Background(), time.Second, 50*time.Millisecond, func(ctx context.Context) (time.Time, error) {
				calls++
				d, _ := ctx.Deadline()
				switch kind {
				case "renew":
					return d.Add(time.Second), nil
				case "failure":
					return time.Time{}, errors.New("captured FD11 unavailable")
				default:
					return time.Now().Add(-time.Second), nil
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			for range 2 {
				if _, err := OperationCleanupContext(work); err == nil {
					t.Fatal("invalid shared cleanup accepted")
				}
			}
			if calls != 1 {
				t.Fatal("failed activation renewed cleanup", calls)
			}
		})
	}
}
func TestOperationSharedCleanupFinishCancelsActivation(t *testing.T) {
	entered := make(chan struct{})
	work, finish, err := WithOperationContextProvider(context.Background(), time.Second, time.Second, func(ctx context.Context) (time.Time, error) {
		close(entered)
		<-ctx.Done()
		return time.Time{}, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { _, err := OperationCleanupContext(work); joined <- err }()
	<-entered
	finish()
	select {
	case err := <-joined:
		if err == nil {
			t.Fatal("finished activation accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("provider did not join original cancellation")
	}
}

func TestOperationSharedControllerAdmissionUsesCapturedClock(t *testing.T) {
	c, _ := contextController(t)
	parent, stopParent := context.WithTimeout(context.Background(), time.Second)
	defer stopParent()
	admission, stopAdmission := context.WithCancel(parent)
	defer stopAdmission()
	calls := 0
	op, err := c.beginContextAdmissionProvider(admission, parent, "1234567890abcdef1234567890abcdef", true, func(ctx context.Context) (time.Time, error) {
		calls++
		deadline, _ := ctx.Deadline()
		return deadline, nil
	}, func(ctx context.Context) error { stopAdmission(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer op.finish()
	defer op.cancel()
	if op.ctx.Err() == nil || parent.Err() != nil || calls != 0 {
		t.Fatal("late admission changed original worker or eagerly activated cleanup")
	}
	cleanup, err := OperationCleanupContext(op.ctx)
	if err != nil || cleanup.Err() != nil || calls != 1 {
		t.Fatal("accepted generation lost shared cleanup provider", err, calls)
	}
	if _, err := OperationCleanupContext(op.ctx); err != nil || calls != 1 {
		t.Fatal("controller refreshed captured cleanup clock", err, calls)
	}
	if err := c.execute(op, true); !errors.Is(err, context.Canceled) {
		t.Fatal("late accepted generation failed to drain", err)
	}
	if cleanup.Err() == nil {
		t.Fatal("joined controller retained cleanup authority")
	}
}

func TestOperationSharedCapturedDeadlineAndCleanupMarker(t *testing.T) {
	parent, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	deadline := time.Now().Add(-time.Millisecond)
	calls := 0
	work, finish, err := WithCapturedOperationContextProvider(parent, deadline, 100*time.Millisecond, func(ctx context.Context) (time.Time, error) { calls++; bound, _ := ctx.Deadline(); return bound, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	if !errors.Is(work.Err(), context.DeadlineExceeded) {
		t.Fatal("captured expired work received renewed admission")
	}
	captured, err := OperationWorkDeadline(work)
	if err != nil || !captured.Equal(deadline) {
		t.Fatal("captured work deadline changed", err)
	}
	if only, err := OperationCleanupOnly(work); err != nil || only {
		t.Fatal("work inferred cleanup authority", err)
	}
	cleanup, err := OperationCleanupContext(work)
	if err != nil {
		t.Fatal(err)
	}
	if only, err := OperationCleanupOnly(cleanup); err != nil || !only || !SameOperationContext(work, cleanup) {
		t.Fatal("cleanup lost original token marker", err)
	}
	child, stop := context.WithTimeout(cleanup, time.Millisecond)
	defer stop()
	if only, err := OperationCleanupOnly(child); err != nil || !only {
		t.Fatal("cleanup child lost explicit marker", err)
	}
	if calls != 1 {
		t.Fatal("captured cleanup renewed", calls)
	}
	finish()
	if _, err := OperationWorkDeadline(work); err == nil {
		t.Fatal("closed work authority escaped")
	}
	if _, err := OperationCleanupOnly(cleanup); err == nil {
		t.Fatal("closed cleanup authority escaped")
	}
}
func TestOperationSharedAdmissionKeepsAcceptedDeadline(t *testing.T) {
	parent, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	work, finish, err := WithOperationContextProvider(parent, 500*time.Millisecond, 100*time.Millisecond, func(ctx context.Context) (time.Time, error) { d, _ := ctx.Deadline(); return d, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	admission, stop := context.WithTimeout(work, time.Millisecond)
	defer stop()
	original, _ := work.Deadline()
	got, err := OperationWorkDeadline(admission)
	if err != nil || !got.Equal(original) {
		t.Fatal("short admission replaced original work deadline", err)
	}
}

func TestOperationSharedFinalizationRetainsOriginalTokenUntilJoin(t *testing.T) {
	c, _ := contextController(t)
	parent, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	var original context.Context
	entered, release := make(chan struct{}), make(chan struct{})
	failure := errors.New("original observer closure failed")
	finalized := 0
	done := make(chan error, 1)
	go func() {
		done <- c.RunContextWithCleanupProvider(parent, parent, "1234567890abcdef1234567890abcdef", true, func(ctx context.Context) (time.Time, error) { d, _ := ctx.Deadline(); return d, nil }, func(ctx context.Context) error { original = ctx; return nil }, func(ctx context.Context) error {
			finalized++
			if !SameOperationContext(original, ctx) {
				t.Error("finalizer changed original operation token")
			}
			if err := LockContext(parent, &c.mu); err != nil {
				t.Error("finalizer held controller mutex", err)
			} else {
				if !c.status.Running || c.status.Complete {
					t.Error("run completed before original closure")
				}
				c.mu.Unlock()
			}
			cleanup, err := OperationCleanupContext(ctx)
			if err != nil || cleanup.Err() != nil {
				t.Error("finalizer lost original cleanup authority", err)
			}
			close(entered)
			<-release
			return failure
		})
	}()
	select {
	case <-entered:
	case <-parent.Done():
		t.Fatal("original finalizer not reached")
	}
	select {
	case <-done:
		t.Fatal("controller returned before finalizer joined")
	default:
	}
	close(release)
	if err := <-done; !errors.Is(err, failure) {
		t.Fatal("closure failure was discarded", err)
	}
	if finalized != 1 || SameOperationContext(original, original) {
		t.Fatal("joined finalizer retained authority", finalized)
	}
	status := readStatus(t, c)
	if status.Measured || status.Running || !status.Complete || status.EffectiveMTU != 0 {
		t.Fatal("closure failure advertised current measured success", status)
	}
}

func TestOperationSharedFinalizationPreservesJoinedCancellation(t *testing.T) {
	for _, phase := range []string{"restored", "late-measured", "late-parent", "closure-failure"} {
		t.Run(phase, func(t *testing.T) {
			c, owner, _ := externalFixtureController(t)
			c.owner = &contextTestOwner{externalTestOwner: owner}
			c.cache = nil // Closure regression; generic fixture cache lacks Context commit.
			beforeConfig := c.Config()
			request := strings.Repeat("b", 32)
			if phase == "restored" {
				c.external.measure = func(ctx context.Context, _ hopmeasure.Engine, _ hopmeasure.Hop, _ int) (hopmeasure.Result, error) {
					if err := c.CancelContext(ctx, request); err != nil {
						t.Error("precommit atomic cancellation failed", err)
					}
					return hopmeasure.Result{}, ctx.Err()
				}
			}
			parent, end := context.WithTimeout(context.Background(), 30*time.Second)
			defer end()
			ctx, cancelParent := context.WithCancel(parent)
			defer cancelParent()
			finalized := false
			closureFailure := errors.New("exact original child closure failed")
			err := c.RunContextWithCleanupProvider(ctx, ctx, request, true, func(ctx context.Context) (time.Time, error) { d, _ := ctx.Deadline(); return d, nil }, func(context.Context) error { return nil }, func(original context.Context) error {
				finalized = true
				before := readStatus(t, c)
				state, _ := owner.Capture()
				if phase == "restored" {
					if !before.Restored || before.Measured || state.MTU != 1380 || c.Config() != beforeConfig {
						t.Error("actual optimizer did not restore cancelled native reader/config", before, state)
					}
				} else {
					if !before.Measured || state.MTU != 1500 || c.Config() == beforeConfig {
						t.Error("fixture did not adopt actual measured native reader/config", before, state)
					}
					if e := c.CancelContext(parent, request); !errors.Is(e, ErrOperationCommitted) {
						t.Error("atomic Cancel did not preserve committed winner", e)
					}
					c.Cancel(request)
					if original.Err() != nil {
						t.Error("late explicit Cancel revoked already committed operation")
					}
					if phase == "late-parent" {
						cancelParent()
					}
					if phase == "closure-failure" {
						return closureFailure
					}
				}
				if original.Err() != nil {
					cleanup, e := OperationCleanupContext(original)
					if e != nil || cleanup.Err() != nil {
						t.Error("joined closure lost original cleanup authority", e)
					}
				}
				return nil
			})
			if !finalized {
				t.Fatal("original finalizer was omitted")
			}
			status := readStatus(t, c)
			state, _ := owner.Capture()
			if status.Running || !status.Complete {
				t.Fatal("original finalizer did not join", status)
			}
			switch phase {
			case "restored":
				if !errors.Is(err, context.Canceled) || !status.Restored || status.Measured || status.EffectiveMTU != 1380 || state.MTU != 1380 || c.Config() != beforeConfig || strings.Contains(status.Failure, "did not join") {
					t.Fatal("successful finalizer erased actual restored cancellation", status, state, err)
				}
			case "closure-failure":
				if !errors.Is(err, closureFailure) || status.Measured || status.Restored || status.EffectiveMTU != 0 || state.MTU != 1500 {
					t.Fatal("failed closure falsely published or restored native winner", status, state, err)
				}
			default:
				if err != nil || !status.Measured || status.Restored || status.EffectiveMTU != 1500 || state.MTU != 1500 || c.Config() == beforeConfig {
					t.Fatal("late cancellation changed already committed native winner/config", status, state, err)
				}
			}
		})
	}
}
