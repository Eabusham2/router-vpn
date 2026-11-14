package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
)

type desktopOrderedExecutionRestore struct {
	owner   *desktopOrderedExecutionOwner
	capture *desktopNodeChainExecutionRestore
}

// Split retirement from successor construction: temporary Speed Lab owns the
// intervening connection, so the successor must capture the later restore
// operation only after that temporary native owner has joined.
func (saved *desktopOrderedExecutionRestore) retire(ctx context.Context) error {
	if ctx == nil || saved == nil || saved.owner == nil || saved.owner.session == nil || saved.capture == nil {
		return errors.New("ordered temporary restore lost its original session")
	}
	s, capture := saved.owner.session, saved.capture
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if capture.app != s.app || capture.launch != s.launch || capture.execution != s.execution || s.restoreNext != nil {
		return errors.New("ordered temporary restore changed its captured owner")
	}
	if s.closed {
		if err := desktopnetwork.LockContext(ctx, &capture.mu); err != nil {
			return err
		}
		retired := capture.retired
		capture.mu.Unlock()
		if !retired {
			return errors.New("ordinary Close cannot grant retained-intent restoration")
		}
		return ctx.Err()
	}
	s.captureDNSPublication()
	if err := capture.retireContext(ctx); err != nil {
		return err
	}
	return s.finishRetirementLocked(ctx)
}

func (a *app) speedLabOrderedExecutionRestore(ctx context.Context, original *desktopOrderedExecutionOwner) (*desktopOrderedExecutionRestore, error) {
	if ctx == nil {
		return nil, errors.New("ordered restore lookup requires its original Stop caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, exists := speedLabTemporaryOwners.Load(a)
	if !exists {
		return nil, nil
	}
	owner, ok := raw.(*speedLabTemporaryOwner)
	if !ok || owner == nil {
		return nil, nil
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	saved := owner.orderedExecution
	if !a.speedLabOwnerCurrentLocked(owner) || owner.intent.Err() != nil || saved == nil || saved.owner != original {
		return nil, nil
	}
	return saved, nil
}

func (a *app) captureSpeedLabOrderedExecutionRestore(ctx context.Context, snapshot speedLabTemporarySnapshot) (*desktopOrderedExecutionRestore, error) {
	owner, err := a.desktopOrderedExecutionOwner()
	if err != nil || owner == nil {
		return nil, err
	}
	if owner.session.launch.command != snapshot.Runtime || !snapshot.State.Connected || snapshot.State.Mode != "multihop" {
		return nil, errors.New("temporary ordered restore changed its complete runtime snapshot")
	}
	capture, err := owner.session.CaptureRestore(ctx)
	if err != nil {
		return nil, err
	}
	return &desktopOrderedExecutionRestore{owner: owner, capture: capture}, nil
}

func (a *app) restartSpeedLabOrderedExecution(ctx context.Context, saved *desktopOrderedExecutionRestore) error {
	if ctx == nil || saved == nil || saved.owner == nil || saved.capture == nil || saved.owner.session == nil || saved.owner.session.app != a {
		return errors.New("ordered restart lost its original complete restore capsule")
	}
	if err := a.checkCapturedConnectionOperation(ctx); err != nil {
		return err
	}
	a.mu.Lock()
	busy := a.cmd != nil
	a.mu.Unlock()
	if busy {
		return errors.New("ordered restart cannot replace an unjoined temporary child")
	}
	if current, err := a.desktopOrderedExecutionOwner(); err != nil || current != nil {
		return errors.Join(err, errors.New("ordered restart still has a retained cleanup owner"))
	}
	s, err := saved.owner.session.Restore(ctx, saved.capture)
	if s != nil {
		_, retained := a.retainDesktopOrderedExecution(s)
		err = errors.Join(err, retained)
	}
	if s != nil && s.launch.command != nil && a.ownsConnectionRuntime(s.launch.command) {
		err = errors.Join(err, a.speedLabOwnRuntime(s.launch.command))
	}
	if err == nil {
		err = s.Verify(ctx)
	}
	if err == nil {
		err = a.publishDesktopOrderedExecution(ctx, s, false)
	}
	if err != nil {
		// Leave the exact partial successor in the ordinary Stop registry. The
		// caller's restore failure cleanup drains that owner under its DNS fence.
		return err
	}
	if !desktopMultihopPlatformLaunch(s.launch) {
		a.monitorDesktopOwnedNodeRuntime(s.launch)
	}
	return nil
}
