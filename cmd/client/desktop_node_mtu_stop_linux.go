//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
)

// Only the explicit Stop and terminal-controller paths call this after their
// ordinary MTU hold failed. A measurement hold never retires an engine. The
// caller captures the original outer lease, command and operation before the
// hold; this function cannot select whichever lease appeared during draining.
func prepareDesktopPlatformMTUStop(ctx context.Context, a *app, command *exec.Cmd, operation context.Context,
	outer *mtuLiveOwner, terminal bool, failedHold error) (bool, error) {
	if outer == nil {
		return false, nil
	}
	native, ok := outer.kernel.(*desktopLinuxNodeMTUOwner)
	if !ok {
		return false, nil
	}
	if ctx == nil || ctx.Err() != nil || a == nil || command == nil || native == nil || failedHold == nil ||
		errors.Is(failedHold, context.Canceled) || errors.Is(failedHold, context.DeadlineExceeded) {
		return true, errors.New("Linux MTU retirement lost its bounded original teardown capture")
	}
	if raw, found := mtuLiveOwners.Load(a); !found || raw != outer || outer.a != a || outer.command != command {
		return true, errors.New("Linux MTU retirement cannot discharge a replacement lease or command")
	}
	// A failure while the Retest itself still owns this lock remains a refusal.
	// Only a drained operation with unresolved native cleanup can take the
	// explicit engine-retirement fallback. This lock also prevents a new test.
	lock := mtuRetestLockFor(a)
	if !lock.TryLock() {
		return true, errors.New("Linux MTU retirement is still waiting for its captured Retest operation")
	}
	defer lock.Unlock()
	outer.mu.Lock()
	defer outer.mu.Unlock()
	if !outer.stopped || outer.closed || outer.kernel != native || outer.command != command || outer.a != a {
		return true, errors.New("Linux MTU retirement preceded original request drain or changed its lease")
	}
	s, h := native.session, native.host
	if s == nil || h == nil || s.parent == nil || s.parent.app != a || h.parent == nil {
		return true, errors.New("Linux MTU retirement has no original retained session")
	}
	if err := s.enter(ctx); err != nil {
		return true, err
	}
	defer func() { s.gate <- struct{}{} }()
	current := func() error {
		if err := native.cleanupCurrentLocked(ctx); err != nil {
			return err
		}
		if ctx.Err() != nil || s.closed || s.released || s.active != h || s.journalErr != nil ||
			s.journal == nil || s.journal != native.transaction.journal ||
			!sameDesktopLinuxParentCapture(s.parent, h.parent) {
			return errors.New("Linux MTU teardown changed its retained original session")
		}
		p := s.parent.parent
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.gate:
		}
		_, sessionOwned := p.dependents[s]
		_, hostOwned := p.dependents[h]
		selected := p.session == s && p.complete && !p.closed && sessionOwned && hostOwned && (!p.stopping || terminal)
		p.gate <- struct{}{}
		if !selected {
			return errors.New("Linux MTU teardown lost the original parent's retained owners")
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		raw, found := mtuLiveOwners.Load(a)
		_, duplicate := desktopNodeOwners.Load(a)
		if ctx.Err() != nil || s.parent.currentAppLocked(terminal) != nil || a.closing != terminal ||
			a.localController != s.parent.controller || a.cmd != command || a.connectionContext != operation ||
			a.state.RouterID != h.launch.profileID || a.state.RuntimeMode != h.launch.mode ||
			!found || raw != outer || duplicate {
			return errors.New("Linux MTU teardown belongs to a replaced original application operation")
		}
		return nil
	}
	if err := h.enter(ctx); err != nil {
		return true, err
	}
	err := current()
	h.gate <- struct{}{}
	if err != nil {
		return true, err
	}
	// Cancel and join only this original monitor before entering the host gate
	// for retirement; do not invert its observation/retirement lock order.
	if err := h.stopMonitorBeforeRetirement(ctx); err != nil {
		return true, err
	}
	if err := h.enter(ctx); err != nil {
		return true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := current(); err != nil {
		return true, err
	}
	h.revokeActivationLocked()
	if err := native.transaction.Retire(ctx); err != nil {
		return true, err
	}
	if err := native.finishRetirementLocked(ctx); err != nil {
		return true, err
	}
	// Leave the original command/session selected for the Stop capture made
	// before the hold. Its ordinary Retire owns On-connect release, descriptor
	// closure, presentation clearing and the original session's succession.
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, found := mtuLiveOwners.Load(a)
	_, duplicate := desktopNodeOwners.Load(a)
	if ctx.Err() != nil || s.parent.currentAppLocked(terminal) != nil || a.closing != terminal ||
		a.cmd != command || a.connectionContext != operation || !found || raw != outer || duplicate {
		return true, errors.New("Linux MTU retirement cannot publish over a replacement command")
	}
	a.state.Connected, a.state.Phase = false, "stopping"
	return true, nil
}
