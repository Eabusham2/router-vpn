//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"syscall"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// Signaling uses only the os.Process returned by this actual original Start.
// It requests graceful graph cancellation, never table removal or admission.
// A dead peer or successful signal is not source-join/engine-join evidence.
func requestDesktopLinuxNodeStop(ctx context.Context, p *desktopLinuxNodeProcess) error {
	if p == nil {
		return errors.New("Linux Node Stop lost its original created process")
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if !p.Started() || p.command == nil || p.command.Process == nil {
		return errors.New("Linux Node Stop has no actual original started engine")
	}
	select {
	case <-p.joined:
		return nil
	default:
	}
	if p.closed || p.released {
		return errors.New("Linux Node Stop lost its original process owner")
	}
	if p.finishing {
		return nil
	}
	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return ctx.Err()
}

func (t *desktopLinuxNodeTransaction) finishOriginalEngine(ctx context.Context) error {
	if t.engineJoined {
		return nil
	}
	code, waitErr := t.process.FinishAndWait(ctx)
	var exit *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exit) {
		return waitErr
	}
	p := t.process
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if !p.finishing || p.closed || p.released || p.bootstrap != nil || p.command == nil || p.command.ProcessState == nil ||
		!sameDesktopLinuxParentCapture(p.parent, t.parent) || p.root == nil || len(p.pins) == 0 {
		return errors.New("Linux Node settlement lost its joined original engine and retained package owners")
	}
	select {
	case <-p.joined:
	default:
		return errors.New("Linux Node settlement preceded its original Cmd.Wait")
	}
	if exit != nil && exit.ProcessState != p.command.ProcessState {
		return errors.New("Linux Node settlement substituted a different process exit")
	}
	for _, pin := range p.pins {
		if err := p.checkPin(pin); err != nil {
			return err
		}
	}
	if err := t.parent.retirementCurrent(ctx); err != nil {
		return err
	}
	t.engineJoined, t.exitCode, t.exitError = true, code, waitErr
	return nil
}

func (t *desktopLinuxNodeTransaction) verifyClosed(ctx context.Context, _ linuxprotection.NodeRetirementRecord) error {
	if err := t.parent.retirementCurrent(ctx); err != nil {
		return err
	}
	if t.baseline == nil {
		// This constructor never returned a creator. A table name cannot fill
		// that gap; a read-only absence proof only bounds this unused session.
		return mobiletor.ReadDesktopLinuxNodeAbsence(ctx, t.selection.SessionID)
	}
	return t.baseline.ObserveClosed(ctx)
}

// Retire preserves closed protection across temporary tests and restoration.
// Normal On-connect release is a separate captured operation below. Always
// requires its original successor or explicit saved-profile Off transaction.
func (t *desktopLinuxNodeTransaction) Retire(ctx context.Context) error {
	if t == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("Linux Node retirement has no live original operation")
	}
	t.stopRequested.Store(true)
	if err := requestDesktopLinuxNodeStop(ctx, t.process); err != nil {
		return err
	}
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if t.retired {
		return nil
	}
	if !t.complete || t.closed || t.control == nil {
		return errors.New("Linux Node retirement has no complete original transaction")
	}
	t.retiring = true
	if !t.served {
		t.served = true
		err := t.control.ServePreparation(ctx, t.createBaseline, t.admitSource)
		if err != nil && !errors.Is(err, linuxprotection.ErrNodeControlRefused) && !errors.Is(err, linuxprotection.ErrNodeControlRetired) {
			return err
		}
	}
	if t.retirement == nil {
		retired, err := t.control.ReceiveRetirement(ctx)
		if err != nil {
			return err
		}
		copy := retired.Clone()
		t.retirement = &copy
	}
	if !t.engineJoined {
		if err := t.control.AcknowledgeRetirement(ctx, t.verifyClosed); err != nil {
			return err
		}
		if err := t.finishOriginalEngine(ctx); err != nil {
			return err
		}
	}
	if err := t.resolveRetirementPending(ctx); err != nil {
		return err
	}
	if err := t.checkHead(ctx); err != nil {
		return err
	}
	if err := t.settleJoined(ctx); err != nil {
		return err
	}
	if err := t.retirePredecessorReservation(ctx); err != nil {
		return err
	}
	t.admitted, t.retired = false, true
	return nil
}

func (t *desktopLinuxNodeTransaction) settleJoined(ctx context.Context) error {
	if !t.engineJoined || t.retirement == nil || t.pending != nil {
		return errors.New("Linux Node durable settlement preceded actual source and engine joining")
	}
	if t.standardTransfer != nil {
		if err := t.standardTransfer.resolve(ctx); err != nil {
			return err
		}
		t.nativeCommitted = t.standardTransfer.committed.Load()
	}
	head := t.head.Record
	if head.Phase == "intent" && head.Intent.Action == "prepare" {
		if t.baseline != nil {
			if err := t.baseline.Release(ctx); err != nil {
				return err
			}
			t.baselineReleased = true
		} else if err := mobiletor.ReadDesktopLinuxNodeAbsence(ctx, t.selection.SessionID); err != nil {
			return err
		}
		if t.predecessor != nil {
			if err := t.predecessor.baseline.ObserveClosed(ctx); err != nil {
				return err
			}
		}
		next := t.nextRecord()
		next.Phase, next.Intent, next.Committed = "settled", nil, linuxprotection.CloneState(t.previous)
		return t.appendRecord(ctx, next)
	}
	if head.Phase == "intent" && head.Intent.Action == "successor" {
		if t.prepared == nil || t.baseline == nil {
			return errors.New("Linux Node successor settlement lost its original prepared native creator")
		}
		committed := t.nativeCommitted
		if t.predecessor != nil {
			var err error
			committed, err = t.predecessor.baseline.ObserveRetiredSuccession(ctx, t.baseline)
			if err != nil {
				return err
			}
		} else if err := t.baseline.ObserveClosed(ctx); err != nil {
			return err
		}
		state := linuxprotection.CloneState(t.previous)
		if committed {
			state = linuxprotection.CloneState(head.Intent.Candidate)
			state.Engine = nil
		} else {
			if err := t.baseline.Release(ctx); err != nil {
				return err
			}
			t.baselineReleased = true
		}
		t.nativeCommitted = committed
		next := t.nextRecord()
		next.Phase, next.Intent, next.Committed = "settled", nil, state
		return t.appendRecord(ctx, next)
	}
	if head.Phase != "settled" {
		return errors.New("Linux Node settlement cannot resolve another captured native intent")
	}
	if !t.nativeCommitted {
		if !reflect.DeepEqual(head.Committed, t.previous) {
			return errors.New("Linux Node rollback changed its original predecessor")
		}
		return nil
	}
	if t.prepared == nil || t.baseline == nil {
		return errors.New("Linux Node committed settlement lost its exact prepared source")
	}
	expected, err := t.candidate(*t.prepared)
	if err != nil {
		return err
	}
	if head.Committed.Engine == nil {
		expected.Engine = nil
	}
	if !reflect.DeepEqual(head.Committed, expected) {
		return errors.New("Linux Node settlement substituted its committed profile or native source")
	}
	if err := t.baseline.ObserveClosed(ctx); err != nil {
		return err
	}
	if head.Committed.Engine == nil {
		return nil
	}
	next := t.nextRecord()
	next.Committed.Engine = nil
	return t.appendRecord(ctx, next)
}

func (t *desktopLinuxNodeTransaction) retirePredecessorReservation(ctx context.Context) error {
	p := t.predecessor
	if p == nil {
		return nil
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if p.successor != t || p.closed || p.superseded || p.journal != t.journal {
		return errors.New("Linux Node settlement lost its reserved original predecessor")
	}
	if !t.nativeCommitted && !reflect.DeepEqual(t.head.Record.Committed, t.previous) {
		return errors.New("Linux Node failed successor changed its original retained checkpoint")
	}
	p.head, p.superseded, p.successor = t.head, t.nativeCommitted, nil
	return nil
}

// ReleaseOnDisconnect is separate from Retire so a temporary operation can
// restore its captured connection while the original closed baseline remains
// installed. It cannot release Always or the predecessor of a failed attempt.
func (t *desktopLinuxNodeTransaction) ReleaseOnDisconnect(ctx context.Context) error {
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if !t.complete || !t.retired || !t.engineJoined || t.closed || t.successor != nil || t.superseded || t.off != nil {
		return errors.New("Linux Node disconnect lost its exact joined original transaction")
	}
	if !t.nativeCommitted || t.selection.Policy == "always" {
		return nil
	}
	if err := t.flushPending(ctx); err != nil {
		return err
	}
	if err := t.checkHead(ctx); err != nil {
		return err
	}
	if t.head.Record.Phase == "settled" && t.head.Record.Committed.Target == nil {
		return nil
	}
	if t.prepared == nil || t.baseline == nil {
		return errors.New("Linux Node disconnect lost its original committed native target")
	}
	expected, err := t.candidate(*t.prepared)
	if err != nil {
		return err
	}
	expected.Engine = nil
	if !reflect.DeepEqual(t.head.Record.Committed, expected) {
		return errors.New("Linux Node disconnect cannot mutate a replacement's durable target")
	}
	if t.head.Record.Phase == "settled" {
		next := t.nextRecord()
		next.Phase = "intent"
		next.Intent = &linuxprotection.JournalIntent{Action: "release", RequestID: t.selection.SessionID,
			ProfileID: t.profileID, ProfileRevision: t.revision, ResultProfileRevision: t.revision}
		if err := t.appendRecord(ctx, next); err != nil {
			return err
		}
	}
	intent := t.head.Record.Intent
	if t.head.Record.Phase != "intent" || intent == nil || intent.Action != "release" || intent.RequestID != t.selection.SessionID ||
		intent.ProfileID != t.profileID || intent.ProfileRevision != t.revision {
		return errors.New("Linux Node disconnect has another unresolved durable intent")
	}
	if err := t.baseline.Release(ctx); err != nil {
		return err
	}
	t.baselineReleased = true
	next := t.nextRecord()
	next.Phase, next.Intent, next.Committed = "settled", nil, linuxprotection.JournalState{}
	return t.appendRecord(ctx, next)
}

func (t *desktopLinuxNodeTransaction) Close(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if t.closed && t.released {
		return nil
	}
	if t.off != nil && !t.off.settled {
		return errors.New("Linux Node Close retains its accepted unfinished saved-policy Off change")
	}
	if t.complete && (!t.retired || t.pending != nil || t.successor != nil ||
		!t.superseded && t.nativeCommitted && t.head.Record.Committed.Target != nil) {
		return errors.New("Linux Node Close retains unresolved or selected closed native protection")
	}
	if !t.complete && t.baseline != nil {
		return errors.New("incomplete Linux Node transaction retains an original native creator")
	}
	if err := t.process.Close(ctx); err != nil {
		return err
	}
	if t.baseline != nil {
		if err := t.baseline.Close(ctx); err != nil {
			return err
		}
	}
	t.closed = true
	if !t.released {
		if err := t.parent.parent.releaseDependent(ctx, t); err != nil {
			return err
		}
		t.released = true
	}
	return nil
}
