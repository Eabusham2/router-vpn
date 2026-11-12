package mobilemultihop

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This is an explicit native transaction boundary double. Actual TUN/manager
// replacement, ingress transfer and readback are tested by the native adapter.
type nodeChainExecutionMTUEngine struct {
	*nodeChainExecutionRuntimeEngine
	mtuMu       sync.Mutex
	nonce       string
	generation  uint64
	admitted    atomic.Int32
	beforeAdmit func(context.Context)
	ignoreLate  bool
}

func (e *nodeChainExecutionMTUEngine) change(ctx context.Context, b NodeChainExecutionMTUResumeBinding) error {
	if err := b.ValidateTransitionContext(ctx); err != nil {
		return err
	}
	bound, err := b.MTUPlan()
	if err != nil || bound.Ceiling < 1280 || b.TUNTag() != bound.TUNTag {
		return nodeChainExecutionError
	}
	e.mu.Lock()
	current := e.alive && !e.open && e.identity == b.Identity() && e.selected == b.SelectedTag()
	e.mu.Unlock()
	if !current {
		return nodeChainExecutionError
	}
	e.mtuMu.Lock()
	e.nonce, e.generation = b.Nonce(), e.generation+1
	e.mtuMu.Unlock()
	return ctx.Err()
}

func (e *nodeChainExecutionMTUEngine) AdmitExecutionMTUResumeContext(ctx context.Context, b NodeChainExecutionMTUResumeBinding) error {
	e.admitted.Add(1)
	if e.beforeAdmit != nil {
		e.beforeAdmit(ctx)
	}
	if e.ignoreLate {
		return nil
	}
	if err := b.ValidateClosedContext(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	current := e.alive && !e.open && e.identity == b.Identity() && e.selected == b.SelectedTag()
	e.mu.Unlock()
	e.mtuMu.Lock()
	receipt := e.generation != 0 && e.nonce == b.Nonce()
	e.mtuMu.Unlock()
	if !current || !receipt {
		return errors.New("original native reader transaction/readback not admitted")
	}
	return ctx.Err()
}

func nodeChainExecutionMTUFixture(t *testing.T, execution string, configure func(*nodeChainExecutionRuntimeFixture, *nodeChainExecutionMTUEngine)) (*nodeChainExecutionRuntimeFixture, *nodeChainExecutionMTUEngine, context.Context) {
	t.Helper()
	f := newNodeChainExecutionRuntimeFixture(t, execution)
	e := &nodeChainExecutionMTUEngine{nodeChainExecutionRuntimeEngine: f.engine}
	f.runtime.engine = e
	if configure != nil {
		configure(f, e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	return f, e, ctx
}

func nodeChainExecutionMTUResume(t *testing.T, f *nodeChainExecutionRuntimeFixture, ctx context.Context, b NodeChainExecutionMTUResumeBinding) *NodeChainExecutionRuntime {
	t.Helper()
	r, err := NewNodeChainExecutionMTUResumeRuntime(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	r.testTLS = f.trust
	t.Cleanup(func() {
		f.runner.failStop.Store(false)
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := r.CloseContext(cleanup); err != nil {
			t.Error("original resumed runtime cleanup", err)
		}
	})
	return r
}

func TestNodeChainExecutionMTUResumeKeepsSelectedChoiceAndFreshAttempt(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, e, ctx := nodeChainExecutionMTUFixture(t, "auto", func(f *nodeChainExecutionRuntimeFixture, _ *nodeChainExecutionMTUEngine) {
				if winner == "local" {
					f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 30*time.Millisecond
				}
			})
			prior := f.runtime.Progress()
			if prior.Execution != winner {
				t.Fatal("fixture winner not proved", prior.Execution)
			}
			b, err := f.runtime.PauseMTUContext(ctx)
			if err != nil || b.Nonce() == "" || b.SelectionEpoch() == 0 || b.Identity() != e.identity || b.ValidateClosedContext(ctx) != nil {
				t.Fatal("original execution did not retain exact closed pause", err)
			}
			bound, err := b.MTUPlan()
			if err != nil || bound.Ceiling >= 9000 || bound.TUNTag != b.TUNTag() {
				t.Fatal("binding lost original packet bound", err)
			}
			if err := e.change(ctx, b); err != nil {
				t.Fatal(err)
			}
			e.mu.Lock()
			before := len(e.selections)
			e.localDelay, e.serverDelay = time.Millisecond, 30*time.Millisecond
			if winner == "local" {
				e.localDelay, e.serverDelay = 30*time.Millisecond, time.Millisecond
			}
			e.mu.Unlock()
			f.mu.Lock()
			requestsBefore := len(f.requests)
			oldRequests := append([]struct{ method, session string }(nil), f.requests...)
			f.mu.Unlock()
			r := nodeChainExecutionMTUResume(t, f, ctx, b)
			if err := r.Run(ctx); err != nil {
				t.Fatal(err)
			}
			next := r.Progress()
			if !next.Ready || next.Execution != winner || next.Comparison.Target != prior.Comparison.Target || !reflect.DeepEqual(next.Comparison.Measurements, prior.Comparison.Measurements) {
				t.Fatal("MTU resume reranked or replaced original proved execution", prior, next)
			}
			e.mu.Lock()
			selected := append([]string(nil), e.selections[before:]...)
			identity := e.identity
			e.mu.Unlock()
			if len(selected) != 1 || selected[0] != b.SelectedTag() || identity != b.Identity() {
				t.Fatal("same-Box MTU resume compared or replaced original owner", selected)
			}
			f.mu.Lock()
			newRequests := append([]struct{ method, session string }(nil), f.requests[requestsBefore:]...)
			f.mu.Unlock()
			seen := map[string]bool{}
			for _, q := range oldRequests {
				if q.method == "PUT" {
					seen[q.session] = true
				}
			}
			puts := 0
			for _, q := range newRequests {
				if q.method == "PUT" {
					puts++
					if seen[q.session] {
						t.Fatal("MTU resume replayed tombstoned server request")
					}
				}
			}
			if winner == "server" && puts != 1 || winner == "local" && puts != 0 {
				t.Fatal("wrong MTU resume remote acquisition", puts)
			}
			if err := b.ValidateTransitionContext(ctx); err == nil {
				t.Fatal("native mutation admitted while resumed runtime owns the Box")
			}
			if e.admitted.Load() != 2 {
				t.Fatal("constructor/Run did not independently admit same native generation", e.admitted.Load())
			}
		})
	}
}

func TestNodeChainExecutionMTUPauseRetainsFailedOriginalCleanup(t *testing.T) {
	f, e, ctx := nodeChainExecutionMTUFixture(t, "server", nil)
	f.runner.failStop.Store(true)
	b, err := f.runtime.PauseMTUContext(ctx)
	if err == nil || b.Nonce() == "" {
		t.Fatal("failed original cleanup lost retained pause binding", err)
	}
	if b.ValidateClosedContext(ctx) == nil || b.ValidateTransitionContext(ctx) == nil {
		t.Fatal("unjoined original owner granted native mutation")
	}
	if _, err := NewNodeChainExecutionMTUResumeRuntime(ctx, b); err == nil || e.admitted.Load() != 0 {
		t.Fatal("unjoined original owner entered native resume")
	}
	again, err := f.runtime.PauseMTUContext(ctx)
	if err == nil || again != b {
		t.Fatal("failed pause retry replaced the original nonce or owner", err)
	}
	f.runner.failStop.Store(false)
	again, err = f.runtime.PauseMTUContext(ctx)
	if err != nil || again != b || b.ValidateClosedContext(ctx) != nil {
		t.Fatal("original cleanup retry did not release exact binding", err)
	}
	if err := e.change(ctx, b); err != nil {
		t.Fatal(err)
	}
	r := nodeChainExecutionMTUResume(t, f, ctx, b)
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNodeChainExecutionMTUResumeRequiresActualNativeReceipt(t *testing.T) {
	f, e, ctx := nodeChainExecutionMTUFixture(t, "server", nil)
	b, err := f.runtime.PauseMTUContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNodeChainExecutionMTUResumeRuntime(ctx, b); err == nil {
		t.Fatal("shared closed state replaced actual native reader/readback receipt")
	}
	if e.admitted.Load() != 1 {
		t.Fatal("native admission was omitted")
	}
	if err := e.change(ctx, b); err != nil {
		t.Fatal(err)
	}
	r := nodeChainExecutionMTUResume(t, f, ctx, b)
	e.mtuMu.Lock()
	e.nonce = strings.Repeat("f", 64)
	e.mtuMu.Unlock()
	if err := r.Run(ctx); err == nil || r.Progress().Ready {
		t.Fatal("changed native receipt between constructor and Run was admitted")
	}
}

func TestNodeChainExecutionMTUResumeClaimsOneOwnerUntilJoinedRollback(t *testing.T) {
	f, e, ctx := nodeChainExecutionMTUFixture(t, "server", nil)
	b, err := f.runtime.PauseMTUContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.change(ctx, b); err != nil {
		t.Fatal(err)
	}
	r := nodeChainExecutionMTUResume(t, f, ctx, b)
	admitted := e.admitted.Load()
	if _, err := NewNodeChainExecutionMTUResumeRuntime(ctx, b); err == nil || e.admitted.Load() != admitted {
		t.Fatal("unstarted resumed owner was replaced before positive cleanup")
	}
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	f.runner.failStop.Store(true)
	if err := r.CloseContext(ctx); err == nil {
		t.Fatal("failed resumed server owner was acknowledged")
	}
	if err := b.ValidateTransitionContext(ctx); err == nil {
		t.Fatal("rollback overlapped original resumed remote owner")
	}
	if err := e.change(ctx, b); err == nil {
		t.Fatal("native rollback accepted unjoined resumed owner")
	}
	f.runner.failStop.Store(false)
	if err := r.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.ValidateTransitionContext(ctx); err != nil {
		t.Fatal("joined prior resume still blocked rollback", err)
	}
	if err := e.change(ctx, b); err != nil {
		t.Fatal(err)
	}
	next := nodeChainExecutionMTUResume(t, f, ctx, b)
	if err := next.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if next.Progress().Execution != "server" || next.identity != b.Identity() {
		t.Fatal("rollback changed proved execution or original Box")
	}
}

func TestNodeChainExecutionMTUResumeOwnsLateNativeAdmission(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f, e, ctx := nodeChainExecutionMTUFixture(t, "server", func(_ *nodeChainExecutionRuntimeFixture, e *nodeChainExecutionMTUEngine) {
		e.ignoreLate = true
		e.beforeAdmit = func(context.Context) { close(entered); <-release }
	})
	b, err := f.runtime.PauseMTUContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.change(ctx, b); err != nil {
		t.Fatal(err)
	}
	call, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { _, err := NewNodeChainExecutionMTUResumeRuntime(call, b); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native admission not entered")
	}
	cancel()
	if err := b.ValidateClosedContext(ctx); err != nil {
		t.Fatal("native constructor could not inspect original closed binding", err)
	}
	if err := b.ValidateTransitionContext(ctx); err == nil {
		t.Fatal("pending original native admission lost transition ownership")
	}
	if _, err := NewNodeChainExecutionMTUResumeRuntime(ctx, b); err == nil {
		t.Fatal("replacement overlapped late native admission")
	}
	unblock()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("late canceled native receipt published runtime")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late native admission did not join")
	}
	if err := b.ValidateTransitionContext(ctx); err != nil {
		t.Fatal("joined canceled admission retained phantom owner", err)
	}
}

func TestNodeChainExecutionMTUPauseWaitsForMeasurementActivity(t *testing.T) {
	var native *nodeChainExecutionMTUEngine
	f, owner, service := nodeChainExecutionMeasurementFixture(t, "server", func(f *nodeChainExecutionRuntimeFixture) {
		native = &nodeChainExecutionMTUEngine{nodeChainExecutionRuntimeEngine: f.engine}
		f.runtime.engine = native
	})
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	owner.releaseHook = func() { close(entered); <-release }
	if err := service.Start(strings.Repeat("a", 32), 65536); err != nil {
		t.Fatal(err)
	}
	service.Cancel(strings.Repeat("a", 32))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("measurement release did not enter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := f.runtime.PauseMTUContext(ctx)
	if err == nil || b.Nonce() == "" || b.ValidateClosedContext(ctx) == nil {
		t.Fatal("MTU pause discarded original measurement activity", err)
	}
	if _, err := NewNodeChainExecutionMTUResumeRuntime(ctx, b); err == nil || native.admitted.Load() != 0 {
		t.Fatal("held measurement admitted reader replacement")
	}
	unblock()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := f.runtime.PauseMTUContext(ctx)
	if err != nil || again != b || b.ValidateTransitionContext(ctx) != nil {
		t.Fatal("measurement join lost original MTU retry binding", err)
	}
}

func TestNodeChainExecutionMTUResumeRejectsReplacementAndInvalidAuthority(t *testing.T) {
	f, e, ctx := nodeChainExecutionMTUFixture(t, "server", nil)
	var empty NodeChainExecutionMTUResumeBinding
	if empty.Nonce() != "" || empty.SelectedTag() != "" || empty.TUNTag() != "" || empty.SelectionEpoch() != 0 || empty.Identity() != (NodeChainIdentity{}) {
		t.Fatal("zero binding carried authority")
	}
	if _, err := empty.MTUPlan(); err == nil {
		t.Fatal("zero binding carried a ceiling")
	}
	if empty.ValidateClosedContext(ctx) == nil || empty.ValidateTransitionContext(ctx) == nil {
		t.Fatal("zero binding accepted")
	}
	if _, err := NewNodeChainExecutionMTUResumeRuntime(nil, empty); err == nil {
		t.Fatal("nil caller accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.runtime.PauseMTUContext(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled pause acquired state", err)
	}
	if !f.runtime.Progress().Ready {
		t.Fatal("invalid caller retired valid original runtime")
	}
	b, err := f.runtime.PauseMTUContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.change(ctx, b); err != nil {
		t.Fatal(err)
	}
	r := nodeChainExecutionMTUResume(t, f, ctx, b)
	e.mu.Lock()
	e.identity.EngineID = "replacement-box"
	e.mu.Unlock()
	if err := r.Run(ctx); err == nil {
		t.Fatal("MTU receipt adopted a replacement Box")
	}
}
