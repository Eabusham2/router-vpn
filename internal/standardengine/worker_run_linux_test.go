//go:build linux && routervpn_controller_privileged

package standardengine

import (
	"context"
	"errors"
	"fmt"
	"router-vpn/internal/mobilemtu"
	"sync"
	"testing"
	"time"
)

// Real FD11 and production supervisor/provider; native reader/OS calls and the
// two observer acknowledgements are explicit models. Native composition tests
// separately exercise the actual Box adapter and privileged receipt observers.
type sharedClockBackend struct {
	*operationNativeBackend
	access  sync.Mutex
	ready   map[any]string
	mtu     map[any]int
	observe func(context.Context, any) (string, int, error)
}

func (b *sharedClockBackend) Observe(ctx context.Context, reader any) (string, int, error) {
	if b.observe != nil {
		return b.observe(ctx, reader)
	}
	actual, err := b.Current(ctx)
	if err != nil || actual != reader {
		return "", 0, errors.Join(err, errors.New("modeled native reader changed"))
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.ready[reader], b.mtu[reader], ctx.Err()
}
func sharedClockSubmit(t *testing.T, ctx context.Context, p *OperationFile, run OperationRun, seq uint64, binding ReaderBinding, mtu int, cleanup bool) OperationCommand {
	t.Helper()
	deadline := run.WorkDeadlineNS
	if cleanup {
		stamp, present, err := p.OperationRunCleanupDeadline(ctx, run)
		if err != nil || !present {
			t.Fatal("missing retained clock", err)
		}
		deadline = stamp.UnixNano()
	}
	r, err := p.Reserve(ctx, OperationKey{p.capture, fmt.Sprintf("%032x", seq), seq, deadline, binding})
	if err != nil {
		t.Fatal(err)
	}
	c := OperationCommand{r, mtu}
	if err := p.BindOperationRun(ctx, c, run, cleanup); err != nil {
		t.Fatal(err)
	}
	if err := p.SubmitCommand(ctx, c); err != nil {
		t.Fatal(err)
	}
	return c
}
func sharedClockSettle(t *testing.T, ctx context.Context, p *OperationFile, c OperationCommand, r OperationResult) {
	t.Helper()
	for _, role := range []ObserverRole{ServiceObserver, ControllerObserver} {
		if err := p.Acknowledge(ctx, c.Reservation, role, r.Digest); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Settle(ctx, c.Reservation, r.Digest); err != nil {
		t.Fatal(err)
	}
}
func TestCleanupSharedRunWorkerOneClockAndOriginalRestore(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	original := &operationNativeReader{1}
	b := &sharedClockBackend{operationNativeBackend: &operationNativeBackend{current: original}, ready: map[any]string{original: "original-ready"}, mtu: map[any]int{original: 1500}}
	var work context.Context
	var stamps []time.Time
	calls, factories := 0, 0
	b.change = func(current context.Context, old any, mtu int) (NativeMTUTransaction, error) {
		calls++
		if work == nil {
			work = current
		} else if !mobilemtu.SameOperationContext(work, current) {
			t.Error("native candidate received replacement cleanup token")
		}
		cleanupOnly, err := mobilemtu.OperationCleanupOnly(current)
		if err != nil {
			t.Error(err)
		}
		if cleanupOnly != (calls == 3) {
			t.Error("native cleanup-only marker changed", calls, cleanupOnly)
		}
		if calls >= 2 {
			cleanup, err := mobilemtu.OperationCleanupContext(current)
			if err != nil {
				t.Error(err)
				return nil, err
			}
			stamp, _ := cleanup.Deadline()
			stamps = append(stamps, stamp)
		}
		next := &operationNativeReader{calls + 1}
		ready := fmt.Sprintf("ready-%d", calls)
		b.access.Lock()
		before := b.ready[old]
		b.ready[next] = ready
		b.mtu[next] = mtu
		b.access.Unlock()
		return &operationNativeTransaction{next, [3]NativeMTUEvidence{{old, before, fmt.Sprintf("retired-%d", calls), true, false}, {next, ready, "", false, false}}}, nil
	}
	worker, err := NewNativeMTUWorkerWithRunCleanup(c, b, original, "original-ready", func(ctx context.Context) error { return ctx.Err() }, func(ctx context.Context, deadline time.Time, budget time.Duration, provider func(context.Context) (time.Time, error)) (context.Context, context.CancelFunc, error) {
		factories++
		return mobilemtu.WithCapturedOperationContextProvider(ctx, deadline, budget, provider)
	}, mobilemtu.OperationCleanupContext)
	if err != nil {
		t.Fatal(err)
	}
	life, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- worker.Run(life) }()
	defer func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Error("strict worker did not join")
		}
	}()
	binding := run.Original
	for i, mtu := range []int{1400, 1380, 1500} {
		command := sharedClockSubmit(t, ctx, p, run, uint64(i+1), binding, mtu, i == 2)
		result := operationWaitResult(t, ctx, p, command.Reservation)
		hash, _ := run.SHA256()
		if result.Failed || result.Pending || result.RunSHA256 != hash || result.CleanupOnly != (i == 2) {
			t.Fatal("strict result changed run authority", result)
		}
		sharedClockSettle(t, ctx, p, command, result)
		binding, err = p.ReadBinding(ctx, command.Reservation, result.CurrentRole)
		if err != nil {
			t.Fatal(err)
		}
	}
	if factories != 1 || calls != 3 || len(stamps) != 2 || !stamps[0].Equal(stamps[1]) {
		t.Fatal("native optimizer renewed shared run cleanup", factories, calls, stamps)
	}
	stamp, present, err := p.OperationRunCleanupDeadline(ctx, run)
	if err != nil || !present || !stamp.Equal(stamps[0]) {
		t.Fatal("parent and native clocks diverged", err)
	}
	if err := p.RequestOperationRunClosure(ctx, run); err != nil {
		t.Fatal(err)
	}
	for {
		_, state, err := p.ReadOperationRun(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state == OperationRunClosed {
			break
		}
		select {
		case <-time.After(time.Millisecond):
		case <-ctx.Done():
			t.Fatal("child did not acknowledge actual closure")
		}
	}
	next := run
	next.ID = fmt.Sprintf("%032x", 303)
	next.Original = binding
	if err := p.BeginOperationRun(ctx, next); err != nil {
		t.Fatal("settled actual current did not transfer", err)
	}
	if _, err := p.ActivateOperationRunCleanup(ctx, run); err == nil {
		t.Fatal("old run activated replacement clock")
	}
}
func TestCleanupSharedRunWorkerExpiredWorkRejectsConstructor(t *testing.T) {
	ctx, p, c := operationPair(t)
	if err := c.AcknowledgeLaunch(ctx, "original-ready"); err != nil {
		t.Fatal(err)
	}
	run := OperationRun{p.capture, fmt.Sprintf("%032x", 601), time.Now().Add(30 * time.Millisecond).UnixNano(), int64(time.Second), InitialReaderBinding(p.capture, "original-ready"), 1500}
	if err := p.BeginOperationRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	command := sharedClockSubmit(t, ctx, p, run, 1, run.Original, 1400, false)
	original := &operationNativeReader{1}
	b := &sharedClockBackend{operationNativeBackend: &operationNativeBackend{current: original}, ready: map[any]string{original: "original-ready"}, mtu: map[any]int{original: 1500}}
	b.change = func(context.Context, any, int) (NativeMTUTransaction, error) {
		t.Error("expired run admitted native constructor")
		return nil, errors.New("unexpected constructor")
	}
	expired, end := context.WithDeadline(ctx, time.Unix(0, run.WorkDeadlineNS))
	defer end()
	<-expired.Done()
	worker, err := NewNativeMTUWorkerWithRunCleanup(c, b, original, "original-ready", func(ctx context.Context) error { return ctx.Err() }, func(ctx context.Context, deadline time.Time, budget time.Duration, provider func(context.Context) (time.Time, error)) (context.Context, context.CancelFunc, error) {
		return mobilemtu.WithCapturedOperationContextProvider(ctx, deadline, budget, provider)
	}, mobilemtu.OperationCleanupContext)
	if err != nil {
		t.Fatal(err)
	}
	life, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- worker.Run(life) }()
	result := operationWaitResult(t, ctx, p, command.Reservation)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !result.Failed || !result.WorkerJoined || result.CurrentRole != OriginalReader || result.ReadyMask != 1 {
		t.Fatal("late original admission lost actual unchanged reader", result)
	}
	if _, present, err := p.OperationRunCleanupDeadline(ctx, run); err != nil || !present {
		t.Fatal("late original admission did not retain exact cleanup clock", err)
	}
}

func TestCleanupSharedRunWorkerClosesWithoutMutation(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	original := &operationNativeReader{1}
	b := &sharedClockBackend{operationNativeBackend: &operationNativeBackend{current: original}, ready: map[any]string{original: "original-ready"}, mtu: map[any]int{original: 1500}}
	b.change = func(context.Context, any, int) (NativeMTUTransaction, error) {
		t.Error("no-change run constructed native transaction")
		return nil, errors.New("unexpected mutation")
	}
	factory := func(context.Context, time.Time, time.Duration, func(context.Context) (time.Time, error)) (context.Context, context.CancelFunc, error) {
		t.Error("no-change run minted native work")
		return nil, nil, errors.New("unexpected native work")
	}
	worker, err := NewNativeMTUWorkerWithRunCleanup(c, b, original, "original-ready", func(ctx context.Context) error { return ctx.Err() }, factory, mobilemtu.OperationCleanupContext)
	if err != nil {
		t.Fatal(err)
	}
	life, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- worker.Run(life) }()
	defer func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < 2; i++ {
		if err := p.RequestOperationRunClosure(ctx, run); err != nil {
			t.Fatal(err)
		}
		for {
			_, state, err := p.ReadOperationRun(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if state == OperationRunClosed {
				break
			}
			select {
			case <-time.After(time.Millisecond):
			case <-ctx.Done():
				t.Fatal("original no-change run did not receive native closure acknowledgement")
			}
		}
		if i == 0 {
			run.ID = fmt.Sprintf("%032x", 1101)
			if err := p.BeginOperationRun(ctx, run); err != nil {
				t.Fatal("no-change run blocked original later Retest", err)
			}
		}
	}
	if len(worker.units) != 0 {
		t.Fatal("no-change closure fabricated transaction history")
	}
}

func TestCleanupSharedRunWorkerClosureKeepsOriginalDeadline(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	deadline, err := p.ActivateOperationRunCleanup(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	original := &operationNativeReader{1}
	b := &sharedClockBackend{operationNativeBackend: &operationNativeBackend{current: original}}
	observed := make(chan time.Time, 1)
	b.observe = func(call context.Context, reader any) (string, int, error) {
		d, _ := call.Deadline()
		observed <- d
		<-call.Done()
		return "", 0, call.Err()
	}
	worker, err := NewNativeMTUWorkerWithRunCleanup(c, b, original, "original-ready", func(ctx context.Context) error { return ctx.Err() }, func(context.Context, time.Time, time.Duration, func(context.Context) (time.Time, error)) (context.Context, context.CancelFunc, error) {
		return nil, nil, errors.New("no mutation admitted")
	}, mobilemtu.OperationCleanupContext)
	if err != nil {
		t.Fatal(err)
	}
	life, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- worker.Run(life) }()
	if err := p.RequestOperationRunClosure(ctx, run); err != nil {
		stop()
		<-done
		t.Fatal(err)
	}
	select {
	case actual := <-observed:
		if actual.After(deadline) {
			t.Error("native closure renewed captured cleanup deadline", actual, deadline)
		}
	case <-ctx.Done():
		t.Error("native closure did not observe original reader")
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal("pure closure observation cancellation retired healthy owner", err)
	}
	_, state, err := p.ReadOperationRun(ctx)
	if err != nil || state != OperationRunClosing {
		t.Fatal("unjoined original closure invented child acknowledgement", state, err)
	}
}
