//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"reflect"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// One actual installed parent retains its journal and its latest closed
// predecessor across separate app requests. Neither a saved journal nor a
// table name can create this owner. Callers retain operationMu around changes;
// gate also joins terminal parent cleanup with any entered change.
type desktopLinuxNodeSession struct {
	gate          chan struct{}
	parent        *desktopLinuxNodeParentCapture
	journal       *desktopLinuxNodeJournal
	journalErr    error
	emptyRecovery *desktopLinuxEmptyJournalRecovery
	active        *desktopLinuxNodeHost
	predecessor   *desktopLinuxNodeTransaction
	off           *desktopLinuxNodeProtectionOff
	closed        bool
	released      bool
}

func captureDesktopLinuxNodeSession(ctx context.Context, a *app) (*desktopLinuxNodeSession, error) {
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.Join(err, errors.New("Linux Node session requires its original bounded installed parent"))
	}
	p := parent.parent
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	if err := p.currentLocked(true); err != nil {
		return nil, err
	}
	if p.session != nil {
		if !sameDesktopLinuxParentCapture(p.session.parent, parent) {
			return nil, errors.New("Linux Node session belongs to another original application")
		}
		return p.session, nil
	}
	s := &desktopLinuxNodeSession{gate: make(chan struct{}, 1), parent: parent}
	if p.dependents == nil {
		p.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	p.session, p.dependents[s] = s, struct{}{}
	s.gate <- struct{}{}
	return s, nil
}

func (s *desktopLinuxNodeSession) enter(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.gate == nil || s.parent == nil {
		return errors.New("Linux Node session has no original bounded caller")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
		if ctx.Err() != nil {
			s.gate <- struct{}{}
			return ctx.Err()
		}
		return nil
	}
}

func (s *desktopLinuxNodeSession) currentLocked(ctx context.Context) error {
	if s.closed || s.released || s.parent.Current(ctx) != nil {
		return errors.New("Linux Node session lost its original live controller")
	}
	p := s.parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	if p.session != s {
		return errors.New("Linux Node session was replaced under its original parent")
	}
	if _, retained := p.dependents[s]; !retained {
		return errors.New("Linux Node session lost its parent retirement registration")
	}
	return nil
}

// Start creates the first journal only after the caller joined the old app
// connection. Subsequent starts retain that same open journal and exact closed
// transaction. A failed constructor remains retained; it is never retried by
// reopening a pathname or adopting an unrelated native table.
func (s *desktopLinuxNodeSession) Start(ctx context.Context, host *desktopLinuxNodeHost) error {
	return s.startWithVerifier(ctx, host, os.Environ(), verifyBundledNativeContext)
}

func (s *desktopLinuxNodeSession) startWithVerifier(ctx context.Context, host *desktopLinuxNodeHost,
	environment []string, verify func(context.Context, string) (string, error)) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.active != nil || s.off != nil || host == nil || verify == nil || !sameDesktopLinuxParentCapture(s.parent, host.parent) {
		return errors.New("Linux Node session cannot replace an unjoined or foreign host")
	}
	if err := host.enter(ctx); err != nil {
		return err
	}
	err := host.unoccupied(ctx)
	if err == nil && (!host.staged || host.startEntered || host.process != nil || host.transaction != nil) {
		err = errors.New("Linux Node session requires its unused staged original host")
	}
	host.gate <- struct{}{}
	if err != nil {
		return err
	}
	if s.journalErr != nil {
		return s.journalErr
	}
	// Retain the prepared host before entering journal creation or child start.
	// Even cancellation after a partial result leaves a specific Stop owner.
	s.active = host
	if s.journal == nil {
		s.journal, s.journalErr = createDesktopLinuxNodeJournal(ctx, s.parent)
		if s.journalErr != nil {
			return s.journalErr
		}
	}
	if s.journal == nil || !sameDesktopLinuxParentCapture(s.parent, s.journal.parent) {
		return errors.New("Linux Node session lost its original open journal")
	}
	if _, err := s.selectedPredecessorLocked(ctx, s.predecessor); err != nil {
		return err
	}
	return host.startWithVerifier(ctx, s.journal, s.predecessor, environment, verify)
}

// A journal read only compares the original candidate. The original creator
// must independently observe its closed native source. An empty checkpoint
// requires an independent kernel absence proof, never merely Target == nil.
func (s *desktopLinuxNodeSession) selectedPredecessorLocked(ctx context.Context,
	candidate *desktopLinuxNodeTransaction) (*desktopLinuxNodeTransaction, error) {
	if s.journal == nil || !sameDesktopLinuxParentCapture(s.parent, s.journal.parent) {
		return nil, errors.New("Linux Node session has no original journal")
	}
	selected, err := s.journal.Snapshot(ctx)
	if err != nil || selected.Incomplete || selected.Record.Phase != "settled" || selected.Record.Intent != nil ||
		selected.Record.Controller != s.parent.record || selected.Record.Committed.Engine != nil {
		return nil, errors.Join(err, errors.New("Linux Node session requires its exact settled joined checkpoint"))
	}
	if selected.Record.Committed.Target == nil {
		if !reflect.DeepEqual(selected.Record.Committed, linuxprotection.JournalState{}) {
			return nil, errors.New("Linux Node empty session retained another private identity")
		}
		return nil, mobiletor.ReadDesktopLinuxProtectionAbsence(ctx)
	}
	if candidate == nil || !sameDesktopLinuxParentCapture(candidate.parent, s.parent) || candidate.journal != s.journal {
		return nil, errors.New("Linux Node checkpoint has no retained original predecessor")
	}
	if err := candidate.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { candidate.gate <- struct{}{} }()
	if !candidate.complete || !candidate.retired || !candidate.engineJoined || !candidate.nativeCommitted ||
		candidate.closed || candidate.released || candidate.superseded || candidate.successor != nil || candidate.pending != nil ||
		candidate.baseline == nil || candidate.baselineReleased || !sameDesktopLinuxJournalSelection(selected, candidate.head.Record) {
		return nil, errors.New("Linux Node session lost its exact joined predecessor capability")
	}
	if err := candidate.baseline.ObserveClosed(ctx); err != nil {
		return nil, err
	}
	return candidate, nil
}

// Retire accepts the captured host, not whichever host is active when an old
// callback finishes. A nil host is valid only after that exact active host has
// already joined, for an explicit Disconnect releasing retained On-connect.
// Always remains closed until its original successor or saved-policy change.
func (s *desktopLinuxNodeSession) Retire(ctx context.Context, host *desktopLinuxNodeHost, disconnect bool) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if s.off != nil {
		if host != nil || !disconnect {
			return errors.New("finish the original pending Linux Kill Switch Off change before another retirement")
		}
		_, err := s.resumeProtectionOffLocked(ctx, s.off, true)
		return err
	}
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.active != host {
		return errors.New("Linux Node stop belongs to a replaced original host")
	}
	candidate := s.predecessor
	if host != nil {
		if !sameDesktopLinuxParentCapture(s.parent, host.parent) {
			return errors.New("Linux Node stop cannot retire another parent")
		}
		if err := host.Retire(ctx, disconnect); err != nil {
			return err
		}
		if transaction := host.transaction; transaction != nil {
			if err := transaction.enter(ctx); err != nil {
				return err
			}
			if transaction.nativeCommitted {
				candidate = transaction
			}
			transaction.gate <- struct{}{}
		}
	}
	// No complete journal exists after a failed initial constructor. Keep that
	// exact error and descriptor owner for terminal cleanup; workspace cleanup
	// cannot authorize a subsequent attempt to overwrite its private records.
	if s.journalErr != nil || s.journal == nil {
		if host != nil {
			if err := host.Close(ctx); err != nil {
				return err
			}
		}
		s.active = nil
		return s.journalErr
	}
	selected, err := s.selectedPredecessorLocked(ctx, candidate)
	if err != nil {
		return err
	}
	if disconnect && selected != nil {
		if err := selected.ReleaseOnDisconnect(ctx); err != nil {
			return err
		}
		selected, err = s.selectedPredecessorLocked(ctx, selected)
		if err != nil {
			return err
		}
	}
	if host != nil {
		if err := host.Close(ctx); err != nil {
			return err
		}
	}
	// A superseded ancestor is no longer an admission capability. Close its
	// retained original descriptors only after the new source's joined result
	// is durable; a failed successor still retains this same old predecessor.
	if previous := s.predecessor; previous != nil && previous != selected {
		if err := previous.Close(ctx); err != nil {
			return err
		}
	}
	if candidate != nil && candidate != selected {
		if err := candidate.Close(ctx); err != nil {
			return err
		}
	}
	s.active, s.predecessor = nil, selected
	return nil
}

func (s *desktopLinuxNodeSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if !s.closed {
		p := s.parent.parent
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.gate:
		}
		stopping := p.stopping
		p.gate <- struct{}{}
		if !stopping {
			return errors.New("Linux Node session close requires its original terminal parent stop")
		}
		if recovery := s.emptyRecovery; recovery != nil && !recovery.ready && recovery.journal != nil {
			if recovery.journal.removal != nil {
				// Finish only the already accepted exact unlink. A shutdown
				// cannot upgrade rejected/nonempty storage into recovery.
				if err := s.finishEmptyRecoveryLocked(ctx, true); err != nil {
					return err
				}
			} else if err := recovery.journal.Close(ctx); err != nil {
				return err
			}
		}
		if s.active != nil {
			if err := s.active.Close(ctx); err != nil {
				return err
			}
		}
		s.closed = true
	}
	if !s.released {
		if err := s.parent.parent.releaseDependent(ctx, s); err != nil {
			return err
		}
		s.released = true
	}
	return nil
}

var _ ownedDesktopNodeParent = (*desktopLinuxNodeSession)(nil)
