//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"reflect"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// This capture observes an existing session only. Stop cannot construct a
// parent, reopen a journal or select a source from a saved table name. The
// caller retains operationMu from capture through MTU drain and retirement.
type desktopNodeStopCapture struct {
	app         *app
	session     *desktopLinuxNodeSession
	host        *desktopLinuxNodeHost
	predecessor *desktopLinuxNodeTransaction
	journal     *desktopLinuxNodeJournal
	operation   context.Context
	command     *exec.Cmd
	completion  *desktopLinuxStopCompletion
}

func (a *app) captureDesktopNodeStop() (*desktopNodeStopCapture, error) {
	return a.captureDesktopNodeStopContext(context.Background())
}

func (a *app) captureDesktopNodeStopContext(caller context.Context) (*desktopNodeStopCapture, error) {
	if a == nil || caller == nil {
		return nil, errors.New("Linux Node Stop has no application")
	}
	ctx, cancel := context.WithTimeout(caller, 2*time.Second)
	defer cancel()
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	controller, operation, command := a.localController, a.connectionContext, a.cmd
	a.mu.Unlock()
	if controller == nil || controller.nodeParent == nil {
		return nil, nil
	}
	parent, ok := controller.nodeParent.(*desktopLinuxNodeParent)
	if !ok || parent == nil {
		return nil, errors.New("Linux Node Stop has another original parent")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-parent.gate:
	}
	session := parent.session
	parent.gate <- struct{}{}
	if session == nil {
		return nil, nil
	}
	if err := session.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { session.gate <- struct{}{} }()
	if session.parent == nil || session.parent.app != a || session.parent.controller != controller || session.parent.parent != parent {
		return nil, errors.New("Linux Node Stop cannot borrow another application's session")
	}
	// A completed native retirement may still owe its original app publication.
	// Recover that exact retained capability before considering empty dispatch.
	if pending := session.stopCompletion; pending != nil {
		if err := pending.currentAppContext(ctx, command, pending.completion.commandRetired.Load()); err != nil {
			return nil, err
		}
		if pending.completion.hostReleased && pending.completion.failedConstructor != nil {
			if session.active != nil || session.journalErr != pending.completion.failedConstructor || session.journal != pending.journal {
				return nil, errors.New("Linux Stop lost its original failed constructor cleanup")
			}
			return nil, pending.completion.failedConstructor
		}
		return pending, nil
	}
	// An unused or completely released session has no claim on a later legacy
	// connection, including its terminal Stop. This read-only comparison uses
	// the original retirement parent; it cannot reopen Node admission.
	if session.active == nil && session.predecessor == nil && session.off == nil && session.journalErr == nil {
		if err := session.unclaimedStopLocked(ctx); err != nil {
			return nil, err
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return nil, err
		}
		current := session.parent.currentAppLocked(true) == nil && a.localController == controller &&
			a.connectionContext == operation && a.cmd == command
		a.mu.Unlock()
		if !current {
			return nil, errors.New("Linux empty Stop dispatch changed its original application or command")
		}
		return nil, nil
	}
	if err := session.currentLocked(ctx); err != nil {
		return nil, err
	}
	captured := &desktopNodeStopCapture{app: a, session: session, host: session.active, predecessor: session.predecessor,
		journal: session.journal, operation: operation, command: command}
	captured.completion = &desktopLinuxStopCompletion{owner: captured}
	if err := captured.currentAppContext(ctx, command, false); err != nil {
		return nil, err
	}
	return captured, nil
}

// A released session can defer Stop to a later legacy connection only while
// its exact empty checkpoint and native Node-family absence remain current.
// The fixed Tor/global guard belongs to that legacy Stop path. This helper
// grants no creation, admission, restoration, release or global absence proof.
// The caller retains the original session gate and application operation lock.
func (s *desktopLinuxNodeSession) unclaimedStopLocked(ctx context.Context) error {
	current := func() error {
		if s.closed || s.released || s.stopCompletion != nil || s.active != nil || s.predecessor != nil || s.off != nil || s.journalErr != nil ||
			s.parent == nil || s.parent.parent == nil {
			return errors.New("Linux empty Stop dispatch lost its original unclaimed session")
		}
		if err := s.parent.retirementCurrent(ctx); err != nil {
			return err
		}
		p := s.parent.parent
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.gate:
		}
		defer func() { p.gate <- struct{}{} }()
		_, sessionOwned := p.dependents[s]
		_, journalOwned := p.dependents[s.journal]
		if p.session != s || !sessionOwned || s.journal != nil && !journalOwned {
			return errors.New("Linux empty Stop dispatch lost its original parent registration")
		}
		return nil
	}
	if err := current(); err != nil {
		return err
	}
	if j := s.journal; j != nil {
		if err := j.enter(ctx); err != nil {
			return err
		}
		defer func() { j.gate <- struct{}{} }()
		if j.ctx == nil || j.ctx.Err() != nil || j.closed || j.released || j.pending != nil || j.removal != nil || j.closeErr != nil ||
			!sameDesktopLinuxParentCapture(s.parent, j.parent) {
			return errors.New("Linux empty Stop dispatch cannot borrow incomplete or retired storage")
		}
		if err := j.verifyObjects(); err != nil {
			return err
		}
		selection, body, err := j.readSelection()
		if err != nil || !bytes.Equal(body, j.currentBytes) || selection.SHA256 != j.current.SHA256 || selection.Slot != j.current.Slot ||
			selection.Incomplete || selection.Incomplete != j.current.Incomplete || selection.Record.Controller != s.parent.record ||
			selection.Record.Phase != "settled" || selection.Record.Intent != nil ||
			!reflect.DeepEqual(selection.Record.Committed, linuxprotection.JournalState{}) {
			return errors.Join(err, errors.New("Linux empty Stop dispatch lost its exact settled empty checkpoint"))
		}
	}
	if err := mobiletor.ReadDesktopLinuxNodeStopAbsence(ctx); err != nil {
		return err
	}
	return current()
}

// Cancellation of the initiating request does not prevent its exact Stop.
// Replacing the request, controller, command or session does. No call to the
// command's Wait/Signal/Kill methods occurs outside its original process owner.
func (captured *desktopNodeStopCapture) currentApp(command *exec.Cmd, retired bool) error {
	return captured.currentAppContext(context.Background(), command, retired)
}

func (captured *desktopNodeStopCapture) currentAppContext(ctx context.Context, command *exec.Cmd, retired bool) error {
	return captured.currentAppModeContext(ctx, command, retired, false)
}

func (captured *desktopNodeStopCapture) currentAppModeContext(ctx context.Context, command *exec.Cmd, retired, shutdown bool) error {
	if captured == nil || captured.app == nil || captured.session == nil || captured.session.parent == nil {
		return errors.New("Linux Node Stop lost its captured session")
	}
	if captured.completion == nil || captured.completion.owner != captured {
		return errors.New("Linux Node Stop lost its original completion identity")
	}
	retired = retired || captured.completion.commandRetired.Load()
	a := captured.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if captured.session.parent.currentAppLocked(shutdown) != nil || a.connectionContext != captured.operation || command != captured.command && !(retired && command == nil) {
		return errors.New("Linux Node Stop belongs to a replaced application or operation")
	}
	if !retired && a.cmd != captured.command || retired && a.cmd != nil {
		return errors.New("Linux Node Stop cannot change a replacement command")
	}
	if captured.host == nil {
		if captured.command != nil || a.state.Connected {
			return errors.New("Linux retained protection cannot stop another running connection")
		}
	} else if captured.host.parent == nil || !sameDesktopLinuxParentCapture(captured.host.parent, captured.session.parent) ||
		captured.host.launch == nil || captured.command != nil && captured.host.launch.command != captured.command ||
		captured.command != nil && (a.state.RouterID != desktopExternalPathProfileID(captured.host.launch) || !retired && a.state.RuntimeMode != captured.host.launch.mode) ||
		retired && a.state.Connected {
		return errors.New("Linux Node Stop changed its original host or presentation")
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		return errors.New("Linux Node Stop cannot share its original process with the legacy native registry")
	}
	return ctx.Err()
}

func (captured *desktopNodeStopCapture) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Linux Node Stop requires a live bounded retirement caller")
	}
	if err := captured.retainCompletion(ctx, command, disconnect); err != nil {
		return err
	}
	if captured.completion.published.Load() {
		return nil
	}
	if err := captured.session.retireCaptured(ctx, captured.host, disconnect, captured); err != nil {
		// The original session retains both partial cleanup and any positive
		// command-retirement receipt. A cancelled failure tail cannot block.
		locked := desktopnetwork.LockContext(ctx, &captured.app.mu) == nil
		if !locked {
			locked = captured.app.mu.TryLock()
		} // one nonblocking owned-failure publication attempt
		if locked {
			a := captured.app
			if a.connectionContext == captured.operation && captured.session.parent.currentAppLocked(false) == nil &&
				(a.cmd == captured.command || captured.completion.commandRetired.Load() && a.cmd == nil) {
				a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", err.Error()
			}
			a.mu.Unlock()
		}
		return err
	}
	return captured.publishCompletion(ctx, command)
}
