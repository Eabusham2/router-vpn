//go:build linux

package standardengine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"router-vpn/internal/common"
	"sync/atomic"
	"time"
)

// These interfaces retain native objects supplied by the shipping Box adapter.
// A reader is never acquired from an interface name or a serialized binding.
type NativeMTUEvidence struct {
	Reader            any
	Ready, Retirement string
	Retired, Pending  bool
}
type NativeMTUTransaction interface {
	Current() any
	Evidence() [OperationReaders]NativeMTUEvidence
}
type NativeMTUBackend interface {
	Current(context.Context) (any, error)
	Change(context.Context, any, int) (NativeMTUTransaction, error)
	Retry(context.Context, NativeMTUTransaction) error
}
type nativeMTUCompletion struct {
	transaction NativeMTUTransaction
	failure     error
}

type nativeMTUUnit struct {
	completion      <-chan nativeMTUCompletion
	command         OperationCommand
	transaction     NativeMTUTransaction
	before          any
	beforeReady     string
	work            context.Context
	cancel, finish  context.CancelFunc
	failure         error
	bindings        [OperationReaders]*ReaderBinding
	readers         [OperationReaders]any
	cleanupDeadline int64
}

// NativeMTUWorker has one synchronous supervisor and at most one mutation
// goroutine. Lifetime cancellation leaves an unfinished call retained for the
// original fixed command's bounded Retire caller. No operation lock spans mutation.
type NativeMTUWorker struct {
	file              *OperationFile
	backend           NativeMTUBackend
	guard             func(context.Context) error
	operation         func(context.Context, time.Duration) (context.Context, context.CancelFunc, error)
	runFactory        NativeMTURunFactory
	runCleanup        func(context.Context) (context.Context, error)
	run               *nativeMTURun
	current           any
	ready             string
	binding           ReaderBinding
	units             []*nativeMTUUnit
	lastSequence      uint64
	started, finished atomic.Bool
}

func NewNativeMTUWorker(file *OperationFile, backend NativeMTUBackend, initial any, ready string, guard func(context.Context) error,
	operation func(context.Context, time.Duration) (context.Context, context.CancelFunc, error)) (*NativeMTUWorker, error) {
	if file == nil || !file.child || backend == nil || initial == nil || !reflect.TypeOf(initial).Comparable() || ready == "" || guard == nil || operation == nil {
		return nil, errors.New("native MTU worker omitted original lifetime or reader")
	}
	return &NativeMTUWorker{file: file, backend: backend, current: initial, ready: ready, binding: InitialReaderBinding(file.capture, ready), guard: guard, operation: operation}, nil
}

func nativeMTUObservation(parent context.Context) (context.Context, context.CancelFunc) {
	// Same one-second peer observation bound used by the fixed command startup
	// receipt guard. This poll never changes an admitted operation's deadline.
	return context.WithTimeout(parent, time.Second)
}

// A read timeout is absence of a fresh observation, never evidence that the
// retained native engine failed. Mixed protocol/identity errors remain fatal.
func nativeMTUReadPending(ctx context.Context, err error) bool {
	return err == ErrNoOperation || common.ObservationContextExpired(ctx, err)
}

func (w *NativeMTUWorker) Run(lifetime context.Context) (failure error) {
	if w == nil || lifetime == nil || !w.started.CompareAndSwap(false, true) {
		return errors.New("native MTU supervisor has no original lifetime")
	}
	defer w.finished.Store(true)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-lifetime.Done():
			return nil
		case <-ticker.C:
		}
		if len(w.units) != 0 {
			if err := w.retryRequested(lifetime, w.units[len(w.units)-1]); err != nil {
				return err
			}
		}
		if err := w.closeRequestedRun(lifetime); err != nil {
			return err
		}
		poll, end := nativeMTUObservation(lifetime)
		command, err := w.file.ReadCommand(poll, w.lastSequence)
		pending := nativeMTUReadPending(poll, err)
		end()
		if pending {
			continue
		}
		if err != nil {
			return err
		}
		w.lastSequence = command.Reservation.Key.Sequence
		if len(w.units) != 0 {
			previous := w.units[len(w.units)-1]
			if previous.finish != nil {
				previous.finish()
				previous.finish = nil
			}
		}
		unit := &nativeMTUUnit{command: command, before: w.current, beforeReady: w.ready}
		w.units = append(w.units, unit) // Retain admission before context/native construction.
		if len(w.units) > OperationTransactions {
			return errors.New("native MTU history exceeded reserved capacity")
		}
		if err := w.runUnit(lifetime, unit, ticker.C); err != nil {
			return err
		}
	}
}

func (w *NativeMTUWorker) runUnit(lifetime context.Context, unit *nativeMTUUnit, ticks <-chan time.Time) error {
	r := unit.command.Reservation
	deadline := time.Unix(0, r.Key.DeadlineNS)
	parent, stop := context.WithDeadline(lifetime, deadline)
	defer stop()
	unit.cancel = stop
	if w.runFactory != nil {
		if err := w.admitRunUnit(lifetime, unit); err != nil {
			return err
		}
		parent, stop = unit.work, unit.cancel
		defer stop()
	}
	if r.Key.Original != w.binding || w.current == nil || len(w.units) > OperationTransactions {
		return errors.New("native command replaced its original retained reader")
	}
	if err := parent.Err(); err != nil {
		unit.failure = err
		// No native work was admitted; reporting the unchanged retained reader
		// uses the bounded supervisor observation, never a new work allowance.
		ctx, end := nativeMTUObservation(lifetime)
		defer end()
		return w.publish(ctx, unit)
	}
	var err error
	if w.runFactory == nil {
		unit.work, unit.finish, err = w.operation(parent, time.Until(deadline))
		if err != nil {
			return err
		}
	}
	if err = w.guard(unit.work); err != nil {
		unit.failure = err
	} else {
		current, observed := w.backend.Current(unit.work)
		if observed != nil || current != unit.before {
			unit.failure = errors.Join(observed, errors.New("native MTU manager replaced its original reader"))
		}
	}
	if unit.failure == nil {
		cancelled, err := w.file.Cancelled(unit.work, r)
		if err != nil || cancelled {
			stop()
			unit.failure = errors.Join(err, unit.work.Err())
		}
	}
	if unit.failure == nil {
		done := make(chan nativeMTUCompletion, 1)
		unit.completion = done // Retain before native construction can acquire resources.
		go func() {
			tx, err := w.backend.Change(unit.work, unit.before, unit.command.MTU)
			done <- nativeMTUCompletion{tx, err}
		}()
		var completed nativeMTUCompletion
		for {
			select {
			case completed = <-done:
				w.acceptCompletion(unit, completed)
				goto joined
			case <-parent.Done():
				// Cancellation retires admission immediately, but only actual
				// completion can supply a joined result or release native ownership.
				stop()
				select {
				case completed = <-done:
					w.acceptCompletion(unit, completed)
					goto joined
				case <-lifetime.Done():
					// FD10 owns the next bounded join attempt. The actual call,
					// original reader and eventual transaction remain in this unit.
					return nil
				}
			case <-ticks:
				poll, end := nativeMTUObservation(lifetime)
				cancelled, observeErr := w.file.Cancelled(poll, r)
				if observeErr == nil {
					observeErr = w.guard(poll)
				}
				end()
				if cancelled || observeErr != nil {
					unit.failure = errors.Join(unit.failure, observeErr)
					stop()
				}
			}
		}
	}
joined:
	// Publication can fail after actual native mutation. Cleanup still owns the
	// real transaction's current pointer, never the pre-mutation reader.
	if unit.transaction != nil {
		w.current = unit.transaction.Current()
	} else if unit.failure == nil {
		unit.failure = errors.New("native mutation returned no retained transaction")
	}
	// The joined transaction already owns these bytes. Publishing its retained
	// evidence is an observation, not native cleanup or late winner admission;
	// exhausting the work/cleanup allowance must still leave a queryable result.
	ctx, end := nativeMTUObservation(lifetime)
	defer end()
	return w.publish(ctx, unit)
}

// Only the supervisor, or Retire after supervisor completion, consumes this
// exact channel. A late native transaction is retained even when Change failed.
func (w *NativeMTUWorker) acceptCompletion(unit *nativeMTUUnit, completed nativeMTUCompletion) {
	unit.transaction = completed.transaction
	unit.failure = errors.Join(unit.failure, completed.failure, unit.work.Err())
	unit.completion = nil
	if unit.transaction != nil {
		w.current = unit.transaction.Current()
	}
}
func (w *NativeMTUWorker) joinUnit(ctx context.Context, unit *nativeMTUUnit) error {
	if unit.completion == nil {
		return ctx.Err()
	}
	select {
	case completed := <-unit.completion:
		w.acceptCompletion(unit, completed)
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *NativeMTUWorker) publish(ctx context.Context, unit *nativeMTUUnit) error {
	if unit.completion != nil {
		return errors.New("native MTU result still retains an unjoined actual call")
	}
	r := unit.command.Reservation
	evidence := [OperationReaders]NativeMTUEvidence{{Reader: unit.before, Ready: unit.beforeReady}}
	current := unit.before
	if unit.transaction != nil {
		evidence = unit.transaction.Evidence()
		current = unit.transaction.Current()
		if evidence[0].Reader != unit.before {
			return errors.New("native transaction substituted original reader")
		}
		if evidence[0].Ready == "" {
			evidence[0].Ready = unit.beforeReady
		}
	}
	result := OperationResult{CurrentRole: NoReader, WorkerJoined: true, Failed: unit.failure != nil}
	for role := OperationRole(0); role < OperationReaders; role++ {
		e := evidence[role]
		if e.Reader == nil {
			continue
		}
		if !reflect.TypeOf(e.Reader).Comparable() {
			return errors.New("native reader identity is not retained")
		}
		binding := unit.bindings[role]
		if binding == nil {
			for _, prior := range unit.readers {
				if prior != nil && prior == e.Reader {
					return errors.New("native transaction reused retained reader across roles")
				}
			}
			unit.readers[role] = e.Reader
			value := r.Key.Original
			if role != OriginalReader {
				value = ReaderBinding{IdentitySHA256: SHA256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%d", r.Key.CaptureSHA256, r.Key.ID, r.Key.Sequence, role))), Generation: r.Key.Original.Generation + uint64(role), InitialReceiptSHA256: ""}
				if e.Ready != "" {
					value.InitialReceiptSHA256 = SHA256([]byte(e.Ready))
				}
				if err := w.file.BindReader(ctx, r, role, value); err != nil {
					return err
				}
			}
			binding = &value
			unit.bindings[role] = binding
		} else if unit.readers[role] != e.Reader {
			return errors.New("native retry substituted an already retained reader")
		}
		if e.Ready != "" {
			if err := w.file.PublishJoinedEvidence(ctx, r, role, ReadyEvidence, []byte(e.Ready)); err != nil {
				return err
			}
			if binding.InitialReceiptSHA256 == "" {
				binding.InitialReceiptSHA256 = SHA256([]byte(e.Ready))
			}
			result.ReadyMask |= 1 << role
		}
		if e.Retirement != "" {
			if !e.Retired {
				return errors.New("native retirement bytes lack actual joined resource")
			}
			if err := w.file.PublishJoinedEvidence(ctx, r, role, RetirementEvidence, []byte(e.Retirement)); err != nil {
				return err
			}
			result.RetirementMask |= 1 << role
		}
		result.Pending = result.Pending || e.Pending || e.Reader != current && (!e.Retired || e.Retirement == "")
		if e.Reader == current {
			if result.CurrentRole != NoReader {
				return errors.New("native transaction reused current reader across roles")
			}
			result.CurrentRole = role
		}
	}
	if current != nil && result.CurrentRole == NoReader {
		return errors.New("native current reader omitted retained evidence")
	}
	if err := w.file.PublishResult(ctx, r, result); err != nil {
		return err
	}
	w.current = current
	if current != nil {
		w.binding = *unit.bindings[result.CurrentRole]
		w.ready = evidence[result.CurrentRole].Ready
	}
	return nil
}

// Retire is an original Stop retry after Run has joined. It never retries a
// measurement or admits another candidate. Partial native transactions remain
// retained until their real manager-owned cleanup has completed.
func (w *NativeMTUWorker) retryRequested(lifetime context.Context, unit *nativeMTUUnit) error {
	poll, end := nativeMTUObservation(lifetime)
	deadline, err := w.file.ReadCleanupRequest(poll, unit.command.Reservation, unit.cleanupDeadline)
	pending := nativeMTUReadPending(poll, err)
	end()
	if pending {
		return nil
	}
	if err != nil {
		return err
	}
	unit.cleanupDeadline = deadline
	ctx, cancel := context.WithDeadline(lifetime, time.Unix(0, deadline))
	defer cancel()
	if ctx.Err() != nil {
		return nil
	}
	if unit.transaction == nil {
		return errors.New("pending native cleanup has no retained actual transaction")
	}
	if err := w.guard(ctx); err != nil {
		unit.failure = errors.Join(unit.failure, err)
		return nil
	}
	// Only retry manager-retained failed resources. No new candidate, work
	// budget or measurement can be admitted by this explicit cleanup request.
	err = w.backend.Retry(ctx, unit.transaction)
	unit.failure = errors.Join(unit.failure, err, ctx.Err())
	observation, end := nativeMTUObservation(lifetime)
	defer end()
	return w.publish(observation, unit)
}

func (w *NativeMTUWorker) Retire(ctx context.Context) error {
	if w == nil || !w.finished.Load() || ctx == nil {
		return errors.New("native MTU cleanup has not joined its original supervisor")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, unit := range w.units {
		if err := w.joinUnit(ctx, unit); err != nil {
			return err
		}
		if unit.transaction != nil {
			if err := w.backend.Retry(ctx, unit.transaction); err != nil {
				return err
			}
		}
		result, err := w.file.ReadResult(ctx, unit.command.Reservation)
		if err != nil && !errors.Is(err, ErrOperationPending) {
			return err
		}
		if result.Pending || errors.Is(err, ErrOperationPending) {
			if err := w.publish(ctx, unit); err != nil {
				return err
			}
			completed, err := w.file.ReadResult(ctx, unit.command.Reservation)
			if err != nil || completed.Pending {
				return errors.Join(err, errors.New("native cleanup still retains pending original resources"))
			}
		}
		if unit.finish != nil {
			unit.finish()
			unit.finish = nil
		}
	}
	if w.run != nil {
		w.run.finish()
	}
	return ctx.Err()
}

// CurrentReader is available only after the original supervisor/worker join.
func (w *NativeMTUWorker) CurrentReader() (any, error) {
	if w == nil || !w.finished.Load() {
		return nil, errors.New("native MTU reader requested before join")
	}
	for _, unit := range w.units {
		if unit.completion != nil {
			return nil, errors.New("native MTU reader still retains an unjoined actual call")
		}
	}
	return w.current, nil
}

// CurrentRetirement is the actual last original reader's retirement when a
// failed transaction retained no current reader. Other acquired readers remain
// represented by their individual FD11 history; no empty ledger is fabricated.
func (w *NativeMTUWorker) CurrentRetirement() (string, error) {
	if w == nil || !w.finished.Load() || w.current != nil || len(w.units) == 0 {
		return "", errors.New("native retirement has no joined empty-current transaction")
	}
	unit := w.units[len(w.units)-1]
	if unit.completion != nil {
		return "", errors.New("native retirement still retains an unjoined actual call")
	}
	if unit.transaction == nil {
		return "", errors.New("native retirement omitted retained original transaction")
	}
	evidence := unit.transaction.Evidence()
	for _, e := range evidence {
		if e.Reader != nil && (!e.Retired || e.Pending || e.Retirement == "") {
			return "", errors.New("native retirement still retains an unjoined acquired reader")
		}
	}
	original := evidence[OriginalReader]
	if original.Reader != unit.before || original.Retirement == "" {
		return "", errors.New("native retirement lost actual original reader evidence")
	}
	return original.Retirement, nil
}
