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

type operationNativeReader struct{ id int }
type operationNativeTransaction struct {
	current  any
	evidence [OperationReaders]NativeMTUEvidence
}

func (t *operationNativeTransaction) Current() any { return t.current }
func (t *operationNativeTransaction) Evidence() [OperationReaders]NativeMTUEvidence {
	return t.evidence
}

type operationNativeBackend struct {
	mu      sync.Mutex
	current any
	change  func(context.Context, any, int) (NativeMTUTransaction, error)
	retry   func(context.Context, NativeMTUTransaction) error
}

func (b *operationNativeBackend) Current(ctx context.Context) (any, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current, ctx.Err()
}
func (b *operationNativeBackend) Change(ctx context.Context, old any, mtu int) (NativeMTUTransaction, error) {
	tx, err := b.change(ctx, old, mtu)
	if tx != nil {
		b.mu.Lock()
		b.current = tx.Current()
		b.mu.Unlock()
	}
	return tx, err
}
func (b *operationNativeBackend) Retry(ctx context.Context, tx NativeMTUTransaction) error {
	if b.retry != nil {
		return b.retry(ctx, tx)
	}
	return ctx.Err()
}

func operationCommand(t *testing.T, ctx context.Context, p *OperationFile, sequence uint64, binding ReaderBinding) OperationCommand {
	t.Helper()
	deadline, _ := ctx.Deadline()
	key := OperationKey{p.capture, fmt.Sprintf("%032x", sequence), sequence, deadline.UnixNano(), binding}
	r, err := p.Reserve(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	c := OperationCommand{r, 1400}
	if err = p.SubmitCommand(ctx, c); err != nil {
		t.Fatal(err)
	}
	return c
}
func operationWaitResult(t *testing.T, ctx context.Context, p *OperationFile, r OperationReservation) OperationResult {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		result, err := p.ReadResult(ctx, r)
		if err == nil {
			return result
		}
		if !errors.Is(err, ErrOperationPending) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
}
func operationReport(t *testing.T, ctx context.Context, p *OperationFile, c OperationCommand, result OperationResult) OperationReport {
	t.Helper()
	report := OperationReport{Command: c, Result: result}
	for role := OperationRole(0); role < OperationReaders; role++ {
		binding, err := p.ReadBinding(ctx, c.Reservation, role)
		if err != nil {
			if (result.ReadyMask|result.RetirementMask)&(1<<role) != 0 {
				t.Fatal(err)
			}
			continue
		}
		if binding.IdentitySHA256 == "" {
			continue
		}
		e := &OperationReaderEvidence{Binding: binding}
		report.Readers[role] = e
		if result.ReadyMask&(1<<role) != 0 {
			e.Ready, err = p.ReadEvidence(ctx, c.Reservation, role, ReadyEvidence)
			if err != nil {
				t.Fatal(err)
			}
		}
		if result.RetirementMask&(1<<role) != 0 {
			e.Retirement, err = p.ReadEvidence(ctx, c.Reservation, role, RetirementEvidence)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return report
}
func operationStartWorker(t *testing.T, ctx context.Context, child *OperationFile, b *operationNativeBackend, initial any) (*NativeMTUWorker, context.CancelFunc, <-chan error) {
	t.Helper()
	worker, err := NewNativeMTUWorker(child, b, initial, "original-ready", func(ctx context.Context) error { return ctx.Err() }, func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc, error) {
		return mobilemtu.WithOperationContext(ctx, budget, time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}
	lifetime, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- worker.Run(lifetime); close(done) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("native worker did not join")
		}
	})
	return worker, stop, done
}

func TestCleanupOperationCommandRequiresBothOriginalAcknowledgements(t *testing.T) {
	ctx, p, c := operationPair(t)
	original := &operationNativeReader{1}
	next := &operationNativeReader{2}
	unused := &operationNativeReader{3}
	b := &operationNativeBackend{current: original}
	b.change = func(ctx context.Context, old any, mtu int) (NativeMTUTransaction, error) {
		if old != original || mtu != 1400 {
			t.Error("changed command")
		}
		return &operationNativeTransaction{next, [3]NativeMTUEvidence{{original, "original-ready", "original-retired", true, false}, {next, "candidate-ready", "", false, false}, {unused, "", "unused-retired", true, false}}}, nil
	}
	_, stop, _ := operationStartWorker(t, ctx, c, b, original)
	command := operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	result := operationWaitResult(t, ctx, p, command.Reservation)
	if result.Failed || result.Pending || !result.WorkerJoined || result.CurrentRole != CandidateReader {
		t.Fatal(result)
	}
	report := operationReport(t, ctx, p, command, result)
	digest, err := OperationResultDigest(report)
	if err != nil || digest != result.Digest {
		t.Fatal("independent report differs", digest, err)
	}
	if err = p.Settle(ctx, command.Reservation, digest); err == nil {
		t.Fatal("no observers settled native work")
	}
	if err = p.Acknowledge(ctx, command.Reservation, ServiceObserver, digest); err != nil {
		t.Fatal(err)
	}
	if err = p.Settle(ctx, command.Reservation, digest); err == nil {
		t.Fatal("one observer settled native work")
	}
	if err = p.Acknowledge(ctx, command.Reservation, ControllerObserver, SHA256([]byte("foreign"))); err == nil {
		t.Fatal("foreign result acknowledged")
	}
	if err = p.Acknowledge(ctx, command.Reservation, ControllerObserver, digest); err != nil {
		t.Fatal(err)
	}
	if err = p.Settle(ctx, command.Reservation, digest); err != nil {
		t.Fatal(err)
	}
	if _, err = p.ReadEvidence(ctx, command.Reservation, OriginalReader, RetirementEvidence); err != nil {
		t.Fatal("settlement erased original history", err)
	}
	stop()
	// A second reservation can be admitted only after both acknowledgements;
	// it retains a distinct non-reusable slot and exact previous current binding.
	second := operationCommand(t, ctx, p, 2, report.Readers[CandidateReader].Binding)
	if second.Reservation.Slot == command.Reservation.Slot {
		t.Fatal("history slot reused")
	}
}

func TestCleanupOperationWorkerCancellationJoinsOriginalMutation(t *testing.T) {
	ctx, p, c := operationPair(t)
	original := &operationNativeReader{1}
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	b := &operationNativeBackend{current: original, change: func(work context.Context, _ any, _ int) (NativeMTUTransaction, error) {
		close(entered)
		<-work.Done()
		close(cancelled)
		<-release
		return nil, errors.New("independent native failure")
	}}
	_, _, _ = operationStartWorker(t, ctx, c, b, original)
	command := operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := p.Cancel(ctx, command.Reservation); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("cancel blocked on native worker", ctx.Err())
	}
	if _, err := p.ReadResult(ctx, command.Reservation); !errors.Is(err, ErrOperationPending) {
		t.Fatal("unjoined native worker published completion", err)
	}
	close(release)
	result := operationWaitResult(t, ctx, p, command.Reservation)
	if !result.Failed || result.Pending || result.CurrentRole != OriginalReader {
		t.Fatal(result)
	}
}

func TestCleanupOperationExpiredCommandConsumesWithoutNativeMutation(t *testing.T) {
	ctx, p, c := operationPair(t)
	original := &operationNativeReader{1}
	work, end := context.WithTimeout(ctx, time.Millisecond)
	command := operationCommand(t, work, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	<-work.Done()
	end()
	b := &operationNativeBackend{current: original, change: func(context.Context, any, int) (NativeMTUTransaction, error) {
		t.Error("expired command mutated native TUN")
		return nil, nil
	}}
	_, _, _ = operationStartWorker(t, ctx, c, b, original)
	result := operationWaitResult(t, ctx, p, command.Reservation)
	if !result.Failed || result.CurrentRole != OriginalReader || !result.WorkerJoined {
		t.Fatal(result)
	}
}

func TestCleanupOperationPendingNativeEvidenceRetainsStopRetry(t *testing.T) {
	ctx, p, c := operationPair(t)
	original, partial := &operationNativeReader{1}, &operationNativeReader{2}
	tx := &operationNativeTransaction{original, [3]NativeMTUEvidence{{original, "original-ready", "", false, false}, {partial, "", "", false, true}}}
	retried := false
	b := &operationNativeBackend{current: original, change: func(context.Context, any, int) (NativeMTUTransaction, error) {
		return tx, errors.New("partial native construction")
	}, retry: func(_ context.Context, got NativeMTUTransaction) error {
		if got != tx {
			t.Error("retry substituted transaction")
		}
		retried = true
		tx.evidence[1].Pending = false
		tx.evidence[1].Retired = true
		tx.evidence[1].Retirement = "partial-retired"
		return nil
	}}
	worker, stop, done := operationStartWorker(t, ctx, c, b, original)
	command := operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	result := operationWaitResult(t, ctx, p, command.Reservation)
	if !result.Pending || !result.Failed {
		t.Fatal(result)
	}
	if err := p.Acknowledge(ctx, command.Reservation, ServiceObserver, result.Digest); err == nil {
		t.Fatal("pending original resource acknowledged")
	}
	if err := worker.Retire(ctx); err == nil {
		t.Fatal("Stop retried while supervisor still running")
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := worker.Retire(ctx); err != nil || !retried {
		t.Fatal("original retained retry", err)
	}
}

func TestCleanupOperationReportRejectsChangedNativeEvidence(t *testing.T) {
	ctx, p, c := operationPair(t)
	command := operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	if _, err := c.ReadCommand(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishJoinedEvidence(ctx, command.Reservation, OriginalReader, ReadyEvidence, []byte("original-ready")); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishResult(ctx, command.Reservation, OperationResult{CurrentRole: OriginalReader, WorkerJoined: true, ReadyMask: 1}); err != nil {
		t.Fatal(err)
	}
	result := operationWaitResult(t, ctx, p, command.Reservation)
	report := operationReport(t, ctx, p, command, result)
	for _, scenario := range []string{"bytes", "current", "deadline", "mtu", "revision", "binding", "unjoined"} {
		t.Run(scenario, func(t *testing.T) {
			copy := report
			original := *report.Readers[0]
			copy.Readers[0] = &original
			switch scenario {
			case "bytes":
				original.Ready = []byte("foreign")
			case "current":
				copy.Result.CurrentRole = NoReader
			case "deadline":
				copy.Command.Reservation.Key.DeadlineNS++
			case "mtu":
				copy.Command.MTU++
			case "revision":
				copy.Result.Revision++
			case "binding":
				original.Binding.Generation++
			case "unjoined":
				copy.Result.WorkerJoined = false
			}
			digest, err := OperationResultDigest(copy)
			if err == nil && digest == result.Digest {
				t.Fatal("changed native report retained original digest")
			}
		})
	}
}

func TestCleanupOperationPartialReadyCompletesOnlyOriginalEmptyBinding(t *testing.T) {
	ctx, p, c := operationPair(t)
	command := operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	if _, err := c.ReadCommand(ctx, 0); err != nil {
		t.Fatal(err)
	}
	partial := ReaderBinding{IdentitySHA256: SHA256([]byte("actual partial reader")), Generation: 2}
	if err := c.BindReader(ctx, command.Reservation, CandidateReader, partial); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishJoinedEvidence(ctx, command.Reservation, OriginalReader, ReadyEvidence, []byte("original-ready")); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishJoinedEvidence(ctx, command.Reservation, CandidateReader, RetirementEvidence, []byte("actual partial retirement")); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishResult(ctx, command.Reservation, OperationResult{CurrentRole: OriginalReader, WorkerJoined: true, Failed: true, Pending: true, ReadyMask: 1, RetirementMask: 2}); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishJoinedEvidence(ctx, command.Reservation, CandidateReader, ReadyEvidence, []byte("actual cached Ready")); err != nil {
		t.Fatal(err)
	}
	bound, err := p.ReadBinding(ctx, command.Reservation, CandidateReader)
	if err != nil || bound.IdentitySHA256 != partial.IdentitySHA256 || bound.Generation != partial.Generation || bound.InitialReceiptSHA256 != SHA256([]byte("actual cached Ready")) {
		t.Fatal(bound, err)
	}
	if _, err := p.ReadEvidence(ctx, command.Reservation, CandidateReader, RetirementEvidence); err != nil {
		t.Fatal("completion altered immutable prior retirement", err)
	}
	if err := c.PublishJoinedEvidence(ctx, command.Reservation, CandidateReader, ReadyEvidence, []byte("replacement")); err == nil {
		t.Fatal("existing actual Ready replaced")
	}
	if err := c.BindReader(ctx, command.Reservation, CandidateReader, ReaderBinding{SHA256([]byte("replacement reader")), 3, SHA256([]byte("replacement"))}); err == nil {
		t.Fatal("partial reader identity replaced")
	}
	if err := c.PublishResult(ctx, command.Reservation, OperationResult{CurrentRole: OriginalReader, WorkerJoined: true, Failed: true, ReadyMask: 3, RetirementMask: 2}); err != nil {
		t.Fatal(err)
	}
	result := operationWaitResult(t, ctx, p, command.Reservation)
	if result.Pending || result.Revision != 2 {
		t.Fatal(result)
	}
	if digest, err := OperationResultDigest(operationReport(t, ctx, p, command, result)); err != nil || digest != result.Digest {
		t.Fatal("completed evidence is not independently bound", err)
	}
}

func TestCleanupOperationCancelledAdmissionCannotConstructNativeReader(t *testing.T) {
	ctx, p, c := operationPair(t)
	original := &operationNativeReader{1}
	command := operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	if err := p.Cancel(ctx, command.Reservation); err != nil {
		t.Fatal(err)
	}
	b := &operationNativeBackend{current: original, change: func(context.Context, any, int) (NativeMTUTransaction, error) {
		t.Error("cancelled original admission constructed native readers")
		return nil, nil
	}}
	_, _, _ = operationStartWorker(t, ctx, c, b, original)
	result := operationWaitResult(t, ctx, p, command.Reservation)
	if !result.Failed || result.Pending || result.CurrentRole != OriginalReader {
		t.Fatal(result)
	}
}

func TestCleanupOperationUnsubmittedAbortCannotHidePublishedWork(t *testing.T) {
	for _, scenario := range []string{"reserved", "command-record", "published", "torn"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, p, c := operationPair(t)
			deadline, _ := ctx.Deadline()
			r, err := p.Reserve(ctx, OperationKey{p.capture, fmt.Sprintf("%032x", 1), 1, deadline.UnixNano(), InitialReaderBinding(p.capture, "original-ready")})
			if err != nil {
				t.Fatal(err)
			}
			command := OperationCommand{r, 1400}
			switch scenario {
			case "command-record":
				body, err := p.record(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				body[360] = 1
				body[364] = 0x78
				body[365] = 0x05
				if err = p.write(ctx, 4, body, recordOffset(r.Slot), operationRecordSize); err != nil {
					t.Fatal(err)
				}
			case "published":
				if err = p.SubmitCommand(ctx, command); err != nil {
					t.Fatal(err)
				}
			case "torn":
				if _, err = p.file.WriteAt([]byte("torn"), operationSlotSize); err != nil {
					t.Fatal(err)
				}
			}
			aborted, err := p.AbortUnsubmitted(ctx, r)
			if scenario == "torn" {
				if err == nil || aborted {
					t.Fatal("torn slot proved no work")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "published" {
				if aborted {
					t.Fatal("published native work hidden")
				}
				if _, err = c.ReadCommand(ctx, 0); err != nil {
					t.Fatal("published work erased", err)
				}
				return
			}
			if !aborted {
				t.Fatal("definite unsubmitted reservation did not abort")
			}
			if err = p.SubmitCommand(ctx, command); err == nil {
				t.Fatal("late submit resurrected aborted reservation")
			}
			if _, err = c.ReadCommand(ctx, 0); !errors.Is(err, ErrNoOperation) {
				t.Fatal("unsubmitted tombstone created native work", err)
			}
			if _, err = p.ReadResult(ctx, r); !errors.Is(err, ErrOperationPending) {
				t.Fatal("abort fabricated joined native result", err)
			}
		})
	}
}

func TestCleanupOperationExplicitRetryPreservesWorkDeadlineAndReader(t *testing.T) {
	ctx, p, c := operationPair(t)
	original, partial := &operationNativeReader{1}, &operationNativeReader{2}
	tx := &operationNativeTransaction{original, [3]NativeMTUEvidence{{original, "original-ready", "", false, false}, {partial, "", "", false, true}}}
	work, end := context.WithTimeout(ctx, 100*time.Millisecond)
	defer end()
	var changes int
	cleanup, stopCleanup := context.WithTimeout(ctx, 2*time.Second)
	defer stopCleanup()
	cleanupDeadline, _ := cleanup.Deadline()
	b := &operationNativeBackend{current: original, change: func(context.Context, any, int) (NativeMTUTransaction, error) {
		changes++
		return tx, errors.New("original partial native failure")
	}, retry: func(actual context.Context, retained NativeMTUTransaction) error {
		deadline, ok := actual.Deadline()
		if !ok || !deadline.Equal(cleanupDeadline) || retained != tx {
			t.Error("cleanup renewed or replaced original native authority")
		}
		tx.evidence[1].Pending = false
		tx.evidence[1].Retired = true
		tx.evidence[1].Ready = "late cached actual Ready"
		tx.evidence[1].Retirement = "actual joined partial retirement"
		return nil
	}}
	worker, stop, done := operationStartWorker(t, ctx, c, b, original)
	command := operationCommand(t, work, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	first := operationWaitResult(t, ctx, p, command.Reservation)
	if !first.Pending {
		t.Fatal(first)
	}
	<-work.Done()
	if err := p.RequestCleanup(cleanup, command.Reservation); err != nil {
		t.Fatal(err)
	}
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	var result OperationResult
	for {
		var err error
		result, err = p.ReadResult(ctx, command.Reservation)
		if err == nil && result.Revision > first.Revision {
			break
		}
		if err != nil && !errors.Is(err, ErrOperationPending) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
	if result.Pending || !result.Failed || result.CurrentRole != OriginalReader || result.ReadyMask != 3 || result.RetirementMask != 2 {
		t.Fatal(result)
	}
	if err := p.RequestCleanup(cleanup, command.Reservation); err == nil {
		t.Fatal("settled resources accepted another cleanup retry")
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Fatal("cleanup repeated measurement/mutation", changes)
	}
	if current, err := worker.CurrentReader(); err != nil || current != original {
		t.Fatal("cleanup changed active original reader", err)
	}
}

func TestCleanupOperationNoReaderKeepsActualOriginalRetirement(t *testing.T) {
	ctx, p, c := operationPair(t)
	original, partial := &operationNativeReader{1}, &operationNativeReader{2}
	tx := &operationNativeTransaction{nil, [3]NativeMTUEvidence{{original, "original-ready", "actual original retirement", true, false}, {partial, "", "actual partial retirement", true, false}}}
	b := &operationNativeBackend{current: original, change: func(context.Context, any, int) (NativeMTUTransaction, error) {
		return tx, errors.New("failed native replacement")
	}}
	worker, stop, done := operationStartWorker(t, ctx, c, b, original)
	command := operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
	result := operationWaitResult(t, ctx, p, command.Reservation)
	if result.CurrentRole != NoReader || result.Pending || !result.Failed {
		t.Fatal(result)
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := worker.Retire(ctx); err != nil {
		t.Fatal(err)
	}
	if raw, err := worker.CurrentRetirement(); err != nil || raw != "actual original retirement" {
		t.Fatal("native cleanup manufactured empty retirement", raw, err)
	}
}

func TestCleanupOperationWorkerObservationExpiryRetainsOriginal(t *testing.T) {
	for _, phase := range []string{"command", "cleanup"} {
		t.Run(phase, func(t *testing.T) {
			ctx, p, c := operationPair(t)
			original, partial := &operationNativeReader{1}, &operationNativeReader{2}
			tx := &operationNativeTransaction{original, [3]NativeMTUEvidence{{original, "original-ready", "", false, false}}}
			if phase == "cleanup" {
				tx.evidence[1] = NativeMTUEvidence{partial, "", "", false, true}
			}
			changes, retries := 0, 0
			b := &operationNativeBackend{current: original,
				change: func(context.Context, any, int) (NativeMTUTransaction, error) { changes++; return tx, nil },
				retry: func(_ context.Context, retained NativeMTUTransaction) error {
					if retained != tx {
						t.Error("cleanup replaced retained transaction")
					}
					retries++
					tx.evidence[1].Pending = false
					tx.evidence[1].Retired = true
					tx.evidence[1].Retirement = "actual partial retirement"
					return nil
				},
			}
			var command OperationCommand
			var stop context.CancelFunc
			var done <-chan error
			if phase == "cleanup" {
				_, stop, done = operationStartWorker(t, ctx, c, b, original)
				command = operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
				if !operationWaitResult(t, ctx, p, command.Reservation).Pending {
					t.Fatal("partial reader was not retained")
				}
			}
			unlock, err := p.lock(ctx, false)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "command" {
				_, stop, done = operationStartWorker(t, ctx, c, b, original)
			}
			// Hold the actual shared work lock beyond the fixed one-second read
			// bound. No mutation or cleanup is allowed while this read expires.
			timer := time.NewTimer(1200 * time.Millisecond)
			select {
			case err := <-done:
				unlock()
				timer.Stop()
				t.Fatalf("observation expiry terminated original engine: %v", err)
			case <-timer.C:
			}
			unlock()
			if phase == "command" {
				command = operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
			} else if err := p.RequestCleanup(ctx, command.Reservation); err != nil {
				t.Fatal(err)
			}
			for {
				result := operationWaitResult(t, ctx, p, command.Reservation)
				if !result.Pending {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("original supervisor failed: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			stop()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if changes != 1 || (phase == "cleanup" && retries != 1) {
				t.Fatal("original work replayed or omitted", changes, retries)
			}
		})
	}
}

func TestCleanupOperationWorkerObservationKeepsMixedFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failure := errors.New("original operation identity lost")
	for _, tc := range []struct {
		name    string
		err     error
		pending bool
	}{
		{"expired", context.Canceled, true},
		{"wrapped", fmt.Errorf("observation: %w", context.Canceled), true},
		{"identity", failure, false},
		{"mixed", errors.Join(context.Canceled, failure), false},
		{"mixed-empty", errors.Join(ErrNoOperation, failure), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeMTUReadPending(ctx, tc.err); got != tc.pending {
				t.Fatalf("read pending=%v: %v", got, tc.err)
			}
		})
	}
	if nativeMTUReadPending(context.Background(), context.DeadlineExceeded) {
		t.Fatal("foreign timeout renewed original observation")
	}
}
