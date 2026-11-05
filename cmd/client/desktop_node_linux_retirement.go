//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// Retirement may outlive a Connect request and the app's admission latch. It
// still belongs to the same actual controller, private roots, native process,
// namespace, credentials and descriptor owners. None of those may be rebuilt
// from journal values or a replacement application.
func (c *desktopLinuxNodeParentCapture) retirementCurrent(ctx context.Context) error {
	if err := c.currentAppModeContext(ctx, true); err != nil {
		return err
	}
	if err := c.parent.observeCurrent(ctx, true); err != nil {
		return err
	}
	return c.currentAppModeContext(ctx, true)
}

func (j *desktopLinuxNodeJournal) checkOperation(ctx context.Context, retiring *desktopLinuxNodeTransaction) error {
	if retiring == nil {
		return j.checkParent(ctx)
	}
	if j == nil || ctx == nil || ctx.Err() != nil || j.ctx == nil || j.ctx.Err() != nil || j.closed ||
		retiring.journal != j || !sameDesktopLinuxParentCapture(j.parent, retiring.parent) ||
		!retiring.complete || !retiring.stopRequested.Load() || !retiring.retiring || !retiring.engineJoined ||
		retiring.retirement == nil || retiring.closed && (retiring.off == nil || !retiring.off.settled) || retiring.superseded || retiring.successor != nil {
		return errors.New("Linux retirement journal requires its exact joined original transaction")
	}
	return j.parent.retirementCurrent(ctx)
}

func (t *desktopLinuxNodeTransaction) snapshotJournal(ctx context.Context) (linuxprotection.JournalSelection, error) {
	if t.retiring && t.engineJoined {
		return t.journal.snapshot(ctx, t)
	}
	return t.journal.Snapshot(ctx)
}

func (t *desktopLinuxNodeTransaction) appendJournal(ctx context.Context, next linuxprotection.JournalRecord) (linuxprotection.JournalSelection, error) {
	if t.retiring && t.engineJoined {
		return t.journal.append(ctx, next.PreviousSHA256, next, t)
	}
	return t.journal.Append(ctx, next.PreviousSHA256, next)
}

// If the initial append was refused before the journal entered its native
// write, the still-owned old snapshot proves there are no pending bytes to
// finish. Already-entered writes can only replay their exact immutable bytes.
// Native settlement below independently resolves the original creator; this
// never interprets an unwritten intent as a create/delete acknowledgement.
func (t *desktopLinuxNodeTransaction) resolveRetirementPending(ctx context.Context) error {
	if t.pending == nil {
		return nil
	}
	selected, err := t.snapshotJournal(ctx)
	if err == nil && sameDesktopLinuxJournalSelection(selected, t.head.Record) {
		t.pending = nil
		return nil
	}
	return t.flushPending(ctx)
}

func (t *desktopLinuxNodeTransaction) observeReleasedCandidate(ctx context.Context) error {
	if t.baseline != nil && !t.baselineReleased {
		return errors.New("Linux retirement journal has no original acknowledged native release")
	}
	return mobiletor.ReadDesktopLinuxNodeAbsence(ctx, t.selection.SessionID)
}

func (t *desktopLinuxNodeTransaction) observePreviousClosed(ctx context.Context) error {
	if t.previous.Target == nil {
		return nil
	}
	if t.predecessor == nil || t.predecessor.baseline == nil || !reflect.DeepEqual(t.previous, t.predecessor.head.Record.Committed) {
		return errors.New("Linux retirement journal substituted its original predecessor checkpoint")
	}
	return t.predecessor.baseline.ObserveClosed(ctx)
}

func (t *desktopLinuxNodeTransaction) joinedCandidate() (linuxprotection.JournalState, error) {
	if t.prepared == nil || !t.nativeCommitted || t.baseline == nil {
		return linuxprotection.JournalState{}, errors.New("Linux retirement journal has no original committed native candidate")
	}
	state, err := t.candidate(*t.prepared)
	state.Engine = nil
	return state, err
}

// Called under the original journal gate and transaction gate. This authority
// cannot prepare a new source, admit a live engine, or install a different
// target. A prior native write may require exact replay before the subsequent
// joined checkpoint; its pending bytes are never replaced by a new record.
func (j *desktopLinuxNodeJournal) checkRetirementAppend(ctx context.Context, t *desktopLinuxNodeTransaction, next linuxprotection.JournalRecord, body []byte) error {
	if j.pending != nil {
		if bytes.Equal(j.pending.body, body) {
			return nil
		}
		return errors.New("Linux retirement cannot replace its already-entered durable append")
	}
	if next.Committed.Engine != nil {
		return errors.New("Linux retirement cannot record a newly admitted live engine")
	}
	current := j.current.Record
	if next.Phase == "intent" {
		if next.Intent != nil && next.Intent.Action == "off" {
			return t.checkProtectionOffIntent(ctx, next)
		}
		if !t.retired || t.selection.Policy != "on-connect" || next.Intent == nil || next.Intent.Action != "release" ||
			current.Phase != "settled" || !reflect.DeepEqual(current.Committed, next.Committed) {
			return errors.New("Linux retirement cannot create a prepare, successor or foreign release intent")
		}
		expected, err := t.joinedCandidate()
		if err != nil || !reflect.DeepEqual(expected, current.Committed) {
			return errors.Join(err, errors.New("Linux retirement release changed its original committed target"))
		}
		return t.baseline.ObserveClosed(ctx)
	}
	if next.Phase != "settled" {
		return errors.New("Linux retirement cannot change another durable phase")
	}
	if current.Phase == "intent" {
		switch current.Intent.Action {
		case "off":
			return t.checkProtectionOffSettlement(ctx, next)
		case "prepare":
			if !reflect.DeepEqual(next.Committed, t.previous) {
				return errors.New("Linux retired preparation cannot commit a new target")
			}
			return errors.Join(t.observeReleasedCandidate(ctx), t.observePreviousClosed(ctx))
		case "successor":
			if !t.nativeCommitted {
				if !reflect.DeepEqual(next.Committed, t.previous) {
					return errors.New("Linux failed succession cannot replace its original predecessor")
				}
				return errors.Join(t.observeReleasedCandidate(ctx), t.observePreviousClosed(ctx))
			}
			expected, err := t.joinedCandidate()
			candidate := linuxprotection.CloneState(current.Intent.Candidate)
			candidate.Engine = nil
			if err != nil || !reflect.DeepEqual(next.Committed, expected) || !reflect.DeepEqual(next.Committed, candidate) {
				return errors.Join(err, errors.New("Linux retired succession changed its already-captured native candidate"))
			}
			if t.predecessor != nil {
				committed, err := t.predecessor.baseline.ObserveRetiredSuccession(ctx, t.baseline)
				if err != nil || !committed {
					return errors.Join(err, errors.New("Linux retired journal has no original acknowledged succession"))
				}
			}
			return t.baseline.ObserveClosed(ctx)
		case "release":
			if next.Committed.Target != nil || next.Committed.ProfileID != "" || next.Committed.ProfileRevision != "" {
				return errors.New("Linux retired release cannot install a replacement target")
			}
			return t.observeReleasedCandidate(ctx)
		}
		return errors.New("Linux retirement cannot settle another captured intent")
	}
	expected, err := t.joinedCandidate()
	before := linuxprotection.CloneState(current.Committed)
	before.Engine = nil
	if current.Phase != "settled" || current.Committed.Engine == nil || err != nil ||
		!reflect.DeepEqual(expected, next.Committed) || !reflect.DeepEqual(before, next.Committed) {
		return errors.Join(err, errors.New("Linux retirement cannot rewrite a settled target or profile"))
	}
	return t.baseline.ObserveClosed(ctx)
}

// Stop admission before selecting dependents, while retaining the original
// parent's native witnesses for their source/engine/journal retirement. Only
// after every transaction has settled may the parent join remaining dependents,
// clean its original empty checkpoint and cancel the retained parent lifetime.
func (p *desktopLinuxNodeParent) prepareTransactionShutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	if !p.stopping {
		p.stopping = true
		for dependent := range p.dependents {
			if transaction, ok := dependent.(*desktopLinuxNodeTransaction); ok {
				p.shutdownTransactions = append(p.shutdownTransactions, transaction)
			}
		}
	}
	var bootstraps []*linuxStandardBootBootstrapClient
	for dependent := range p.dependents {
		if bootstrap, ok := dependent.(*linuxStandardBootBootstrapClient); ok {
			bootstraps = append(bootstraps, bootstrap)
		}
	}
	transactions := append([]*desktopLinuxNodeTransaction(nil), p.shutdownTransactions...)
	p.gate <- struct{}{}
	// Cleanup may observe this parent and release its dependency; never hold
	// the parent gate while joining the retained service conversation.
	for _, bootstrap := range bootstraps {
		if err := bootstrap.Close(ctx); err != nil {
			return err
		}
	}
	for _, transaction := range transactions {
		if err := transaction.prepareParentShutdown(ctx, make(map[*desktopLinuxNodeTransaction]bool), len(transactions)); err != nil {
			return err
		}
	}
	return nil
}

func (t *desktopLinuxNodeTransaction) prepareParentShutdown(ctx context.Context, path map[*desktopLinuxNodeTransaction]bool, remaining int) error {
	if remaining < 1 || path[t] {
		return errors.New("Linux shutdown lost its bounded original successor chain")
	}
	if err := t.enter(ctx); err != nil {
		return err
	}
	if t.closed && t.released {
		t.gate <- struct{}{}
		return nil
	}
	t.stopRequested.Store(true)
	successor, complete := t.successor, t.complete
	t.gate <- struct{}{}
	path[t] = true
	defer delete(path, t)
	if successor != nil {
		if err := successor.prepareParentShutdown(ctx, path, remaining-1); err != nil {
			return err
		}
	}
	if !complete {
		return t.Close(ctx)
	}
	if err := t.Retire(ctx); err != nil {
		return err
	}
	if err := t.enter(ctx); err != nil {
		return err
	}
	superseded := t.superseded
	t.gate <- struct{}{}
	if superseded {
		return t.Close(ctx)
	}
	if err := t.ReleaseOnDisconnect(ctx); err != nil {
		return err
	}
	if t.selection.Policy != "always" || !t.nativeCommitted {
		return t.Close(ctx)
	}
	return t.closeRetainedAlways(ctx)
}

// The explicit terminal path may release descriptors while preserving an
// exact, settled, closed Always table. Ordinary Close cannot do so, because
// temporary restoration still needs its original successor capability.
// Future restart must establish its own recovery; this checkpoint grants no
// new process authority and never adopts the table by decoded values.
func (t *desktopLinuxNodeTransaction) closeRetainedAlways(ctx context.Context) error {
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if t.closed && t.released {
		return nil
	}
	if !t.retired || !t.engineJoined || !t.nativeCommitted || t.selection.Policy != "always" ||
		t.pending != nil || t.successor != nil || t.superseded || t.baseline == nil || t.baselineReleased {
		return errors.New("Linux shutdown lost its original settled Always owner")
	}
	p := t.parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	stopping := p.stopping
	p.gate <- struct{}{}
	if !stopping {
		return errors.New("Linux retained Always close requires the permanent parent stop latch")
	}
	if err := t.checkHead(ctx); err != nil {
		return err
	}
	expected, err := t.joinedCandidate()
	if err != nil || t.head.Record.Phase != "settled" || !reflect.DeepEqual(t.head.Record.Committed, expected) {
		return errors.Join(err, errors.New("Linux shutdown changed its exact settled Always checkpoint"))
	}
	if err := t.baseline.ObserveClosed(ctx); err != nil {
		return err
	}
	if err := t.process.Close(ctx); err != nil {
		return err
	}
	if err := t.baseline.Close(ctx); err != nil {
		return err
	}
	t.closed = true
	if !t.released {
		if err := p.releaseDependent(ctx, t); err != nil {
			return err
		}
		t.released = true
	}
	return nil
}
