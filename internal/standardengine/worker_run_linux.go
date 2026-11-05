//go:build linux

package standardengine

import (
	"context"
	"errors"
	"router-vpn/internal/common"
	"time"
)

// NativeMTURunBackend observes the exact retained native reader. Serialized
// bindings never supply a reader or replace this independent native readback.
type NativeMTURunBackend interface {
	NativeMTUBackend
	Observe(context.Context, any) (string, int, error)
}
type NativeMTURunFactory func(context.Context, time.Time, time.Duration, func(context.Context) (time.Time, error)) (context.Context, context.CancelFunc, error)
type nativeMTURun struct {
	capture OperationRun
	work    context.Context
	finish  context.CancelFunc
}

// NewNativeMTUWorkerWithRunCleanup is the fixed child's strict entrypoint.
// The compatibility constructor remains for callers without service run frames.
func NewNativeMTUWorkerWithRunCleanup(file *OperationFile, backend NativeMTURunBackend, initial any, ready string, guard func(context.Context) error, factory NativeMTURunFactory, cleanup func(context.Context) (context.Context, error)) (*NativeMTUWorker, error) {
	if factory == nil || cleanup == nil {
		return nil, errors.New("native run omitted captured shared cleanup authority")
	}
	worker, err := NewNativeMTUWorker(file, backend, initial, ready, guard, func(context.Context, time.Duration) (context.Context, context.CancelFunc, error) {
		return nil, nil, errors.New("strict native run cannot mint transaction cleanup")
	})
	if err != nil {
		return nil, err
	}
	worker.runFactory, worker.runCleanup = factory, cleanup
	return worker, nil
}

func (w *NativeMTUWorker) observeRunCurrent(ctx context.Context, expected ReaderBinding, mtu int) error {
	backend, ok := w.backend.(NativeMTURunBackend)
	if !ok || w.current == nil || w.binding != expected {
		return errors.New("native run lost captured original reader")
	}
	if err := w.guard(ctx); err != nil {
		return err
	}
	ready, actualMTU, err := backend.Observe(ctx, w.current)
	if err != nil {
		return err
	}
	if ready == "" || SHA256([]byte(ready)) != expected.InitialReceiptSHA256 || ready != w.ready || actualMTU != mtu {
		return errors.New("native run changed actual original Ready or MTU")
	}
	return ctx.Err()
}
func (w *NativeMTUWorker) admitRunUnit(lifetime context.Context, unit *nativeMTUUnit) error {
	poll, end := nativeMTUObservation(lifetime)
	run, cleanupOnly, bound, err := w.file.CommandOperationRun(poll, unit.command)
	end()
	if err != nil || !bound {
		return errors.Join(err, errors.New("native command omitted original optimizer run"))
	}
	if w.run == nil || w.run.capture != run {
		if w.run != nil {
			return errors.New("native command bypassed original run closure")
		}
		work, finish, err := w.runFactory(lifetime, time.Unix(0, run.WorkDeadlineNS), time.Duration(run.CleanupBudgetNS), func(ctx context.Context) (time.Time, error) { return w.file.ActivateOperationRunCleanup(ctx, run) })
		if err != nil {
			return err
		}
		w.run = &nativeMTURun{run, work, finish} // Retain before observation or constructor.
		observation := work
		if work.Err() != nil || cleanupOnly {
			observation, err = w.runCleanup(work)
			if err != nil {
				return err
			}
		}
		if err := w.observeRunCurrent(observation, run.Original, run.OriginalMTU); err != nil {
			return err
		}
	}
	parent := w.run.work
	if !cleanupOnly {
		poll, end := nativeMTUObservation(lifetime)
		_, active, err := w.file.OperationRunCleanupDeadline(poll, run)
		end()
		if err != nil {
			return err
		}
		if active {
			rejected, cancel := context.WithCancel(parent)
			cancel()
			parent = rejected
		}
	}
	if cleanupOnly {
		parent, err = w.runCleanup(parent)
		if err != nil {
			return err
		}
	}
	unit.work, unit.cancel = context.WithDeadline(parent, time.Unix(0, unit.command.Reservation.Key.DeadlineNS))
	return nil
}

// Closure is an observation after the only worker joined. The child checks the
// actual current reader, and the codec checks both original observer settlements.
func (w *NativeMTUWorker) closeRequestedRun(lifetime context.Context) (failure error) {
	if w.runFactory == nil {
		return nil
	}
	poll, end := nativeMTUObservation(lifetime)
	defer end()
	defer func() {
		if common.ObservationContextExpired(poll, failure) {
			failure = nil
		}
	}()
	run, state, err := w.file.ReadOperationRun(poll)
	if nativeMTUReadPending(poll, err) {
		return nil
	}
	if err != nil {
		return err
	}
	if state != OperationRunClosing {
		return nil
	}
	deadline, present, err := w.file.OperationRunCleanupDeadline(poll, run)
	if err != nil {
		return err
	}
	if !present {
		deadline = time.Unix(0, run.WorkDeadlineNS)
	}
	bounded, stop := context.WithDeadline(poll, deadline)
	defer stop()
	poll = bounded
	if err := poll.Err(); err != nil {
		return err
	}
	if w.run != nil && w.run.capture != run {
		return errors.New("native closure replaced retained run")
	}
	last, err := w.file.runRecords(poll, run, true)
	if err != nil {
		return err
	}
	binding, mtu := run.Original, run.OriginalMTU
	if last != nil {
		result, err := w.file.ReadResult(poll, *last)
		if err != nil || result.CurrentRole == NoReader {
			return errors.Join(err, errors.New("native closure has no actual current reader"))
		}
		binding, err = w.file.ReadBinding(poll, *last, result.CurrentRole)
		if err != nil {
			return err
		}
		backend := w.backend.(NativeMTURunBackend)
		ready, actual, err := backend.Observe(poll, w.current)
		if err != nil || ready != w.ready {
			return errors.Join(err, errors.New("native closure changed actual current Ready"))
		}
		mtu = actual
	}
	if err := w.observeRunCurrent(poll, binding, mtu); err != nil {
		return err
	}
	if w.run != nil {
		w.run.finish()
	}
	if err := w.file.AcknowledgeOperationRunClosure(poll, run); err != nil {
		return err
	}
	w.run = nil
	return nil
}
