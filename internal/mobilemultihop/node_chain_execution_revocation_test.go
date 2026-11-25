package mobilemultihop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func TestOriginalServerTrialCleanupDuringRenewal(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "auto")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var puts atomic.Int32
	renewing := make(chan struct{})
	f.beforePUT = func(call context.Context, _ multihoprelay.NodeChainRequest) {
		if puts.Add(1) == 2 {
			close(renewing)
			<-call.Done()
		}
	}
	// Hold the real Server trial before its comparison Close. Reuse Run's
	// original observed identity and parent lifetime without starting a winner watchdog.
	f.runtime.identity = f.engine.identity
	f.runtime.lifetime = ctx
	session, err := f.runtime.open(ctx, f.runtime.candidate("server"), Targets[0])
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-renewing:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.engine.mu.Lock()
	before := f.engine.revokes
	f.engine.mu.Unlock()
	if err = session.Close(ctx); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	delta := f.engine.revokes - before
	f.engine.mu.Unlock()
	if delta != 1 {
		t.Fatalf("deliberate original trial Close issued %d simultaneous-or-sequential revoke barriers while joining in-flight lease renewal; want exactly one", delta)
	}
}

type heldTrialRevokeEngine struct {
	*nodeChainExecutionRuntimeEngine
	entered    chan struct{}
	release    chan struct{}
	calls      atomic.Int32
	firstError error
}

func (e *heldTrialRevokeEngine) RevokeApplicationContext(ctx context.Context) error {
	if e.calls.Add(1) == 1 {
		close(e.entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.release:
		}
		if e.firstError != nil {
			return e.firstError
		}
	}
	return e.nodeChainExecutionRuntimeEngine.RevokeApplicationContext(ctx)
}

// A second caller observes Done only when it is waiting on the pending native
// barrier. This makes the overlap independent of goroutine scheduling.
type waitingTrialRevokeContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waitingTrialRevokeContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestOriginalServerTrialTerminalRevokeBoundaries(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "one-positive-barrier"
		if fail {
			name = "failed-barrier-retried"
		}
		t.Run(name, func(t *testing.T) {
			ctx, finish := context.WithTimeout(t.Context(), 5*time.Second)
			defer finish()
			engine := &heldTrialRevokeEngine{nodeChainExecutionRuntimeEngine: &nodeChainExecutionRuntimeEngine{}, entered: make(chan struct{}), release: make(chan struct{})}
			if fail {
				engine.firstError = errors.New("native barrier failed")
			}
			runtime := &NodeChainExecutionRuntime{engine: engine}
			lifetime, cancel := context.WithCancel(ctx)
			defer cancel()
			trial := &nodeChainExecutionTrial{runtime: runtime, lifetime: lifetime}
			runtime.active = trial
			if _, err := trial.revokeTerminal(ctx); err == nil || engine.calls.Load() != 0 {
				t.Fatal("a live trial entered terminal revocation")
			}
			cancel()
			first := make(chan error, 1)
			go func() {
				_, err := trial.revokeTerminal(ctx)
				first <- err
			}()
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-engine.entered:
			}
			bounded, stop := context.WithTimeout(ctx, 20*time.Millisecond)
			if _, err := trial.revokeTerminal(bounded); !errors.Is(err, context.DeadlineExceeded) || engine.calls.Load() != 1 {
				stop()
				t.Fatal("held native callback was superseded or credited", err, engine.calls.Load())
			}
			stop()
			waiter := &waitingTrialRevokeContext{Context: ctx, waiting: make(chan struct{})}
			type barrierResult struct {
				barrier *nodeChainTrialRevocation
				err     error
			}
			second := make(chan barrierResult, 1)
			go func() {
				proof, err := trial.revokeTerminal(waiter)
				second <- barrierResult{proof, err}
			}()
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-waiter.waiting:
			}
			close(engine.release)
			if err := <-first; err != engine.firstError {
				t.Fatal("first caller lost its own result", err)
			}
			res := <-second
			if res.err != nil || res.barrier == nil {
				t.Fatal("independently waiting original owner could not prove native revocation", res.err)
			}
			calls := int32(1)
			if fail {
				calls++
			}
			reused, err := trial.revokeTerminal(ctx)
			if err != nil || reused != res.barrier || engine.calls.Load() != calls {
				t.Fatal("positive barrier was replaced", err, engine.calls.Load())
			}
			runtime.mu.Lock()
			runtime.active = &nodeChainExecutionTrial{runtime: runtime, lifetime: lifetime}
			runtime.mu.Unlock()
			if _, err := trial.revokeTerminal(ctx); err == nil || engine.calls.Load() != calls {
				t.Fatal("retired owner reused native terminal proof", err)
			}
		})
	}
}

func TestOriginalServerTrialRenewalFailureRevokesBeforeClose(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "auto")
	ctx, finish := context.WithTimeout(t.Context(), 15*time.Second)
	defer finish()
	var puts atomic.Int32
	f.mutateLease = func(lease *multihoprelay.NodeChainLease) {
		if puts.Add(1) == 2 {
			lease.OwnerID = strings.Repeat("e", 64)
		}
	}
	f.runtime.identity = f.engine.identity
	f.runtime.lifetime = ctx
	session, err := f.runtime.open(ctx, f.runtime.candidate("server"), Targets[0])
	if err != nil {
		t.Fatal(err)
	}
	trial := session.(*nodeChainExecutionTrial)
	f.engine.mu.Lock()
	before := f.engine.revokes
	f.engine.mu.Unlock()
	if err := trial.attempt.joinRenew(ctx); err != nil {
		t.Fatal("failed original renewal did not finish", err)
	}
	f.engine.mu.Lock()
	after := f.engine.revokes
	f.engine.mu.Unlock()
	if after != before+1 || trial.lifetime.Err() == nil {
		t.Fatal("changed renewal owner failed to revoke the original without an explicit Close", before, after)
	}
	if err := trial.Close(ctx); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	defer f.engine.mu.Unlock()
	if after != f.engine.revokes {
		t.Fatal("Close invalidated the previously joined native barrier")
	}
}
