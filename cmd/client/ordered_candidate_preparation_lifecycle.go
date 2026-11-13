package main

import (
	"context"
	"errors"
	"sync"

	"router-vpn/internal/desktopnetwork"
)

// Binding is one-shot and happens before the first native stage. The pointer
// remains on the launch through retirement; a newer preparation cannot adopt
// an old process by changing an application-level testing flag.
func (p *orderedCandidatePreparation) bindLaunch(ctx context.Context, launch *desktopNodeLaunch) error {
	if ctx == nil || p == nil || launch == nil || launch.chain == nil || launch.chain.selection.Native != p.selection.Native ||
		launch.chain.preparation != nil || launch.command != nil || launch.directory != "" || launch.chain.ready != nil {
		return errors.New("candidate purpose requires its unused original full-graph launch")
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return err
	}
	if err := validateDesktopNodeChainLaunch(ctx, launch); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
		return err
	}
	defer p.mu.Unlock()
	if p.launch != nil || p.down {
		return errors.New("candidate purpose was already bound or retired")
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	defer p.app.mu.Unlock()
	if err := p.currentLocked(); err != nil {
		return err
	}
	if p.app.cmd != nil || p.app.state != p.state {
		return errors.New("candidate purpose lost its original idle Home state")
	}
	p.launch, launch.chain.preparation = launch, p
	return ctx.Err()
}

// Caller holds app.mu. This is the narrow purpose predicate for subsequent
// native hooks. A nil purpose means an ordinary launch; a non-nil but invalid
// purpose is an error and must never fall through to ordinary adoption.
func orderedCandidateLaunchPurposeLocked(a *app, launch *desktopNodeLaunch) (*orderedCandidatePreparation, error) {
	if launch == nil || launch.chain == nil {
		return nil, errors.New("candidate purpose observation lost its ordered launch")
	}
	p := launch.chain.preparation
	if p == nil {
		if a != nil && a.candidatePreparation != nil {
			return nil, errors.New("temporary candidate operation has an unbound native launch")
		}
		return nil, nil
	}
	if a == nil || p.app != a || p.launch != launch || p.selection.Native != launch.chain.selection.Native {
		return nil, errors.New("candidate launch purpose belongs to another original owner")
	}
	return p, p.currentLocked()
}

func (p *orderedCandidatePreparation) holdLease(ctx context.Context) error {
	if err := p.sourceCurrent(ctx); err != nil {
		return err
	}
	release, err := p.app.holdCapturedMTU(ctx)
	if err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
		release()
		return err
	}
	if p.down || p.releaseLease != nil || p.operation.Err() != nil {
		p.mu.Unlock()
		release()
		return errors.New("candidate outer measurement lease was cancelled or already captured")
	}
	p.releaseLease = release
	p.mu.Unlock()
	return nil
}

// The worker reports its actual child drain result before closing this channel.
// HTTP cancellation alone cannot stand in for that native join.
func (p *orderedCandidatePreparation) beginWorker(ctx context.Context) (func(error), error) {
	if err := p.sourceCurrent(ctx); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
		return nil, err
	}
	defer p.mu.Unlock()
	if p.down || p.launch == nil || p.releaseLease == nil || p.workerDone != nil || p.operation.Err() != nil {
		return nil, errors.New("candidate worker requires its one original launch and outer lease")
	}
	done := make(chan struct{})
	p.workerDone = done
	var once sync.Once
	return func(pending error) {
		once.Do(func() {
			p.mu.Lock()
			p.pending = pending
			p.mu.Unlock()
			close(done)
		})
	}, nil
}

// viaEntryOwner.closeMu serializes calls, including explicit Cancel retries.
// Failed worker/native cleanup retains the launch, lease, purpose and operation
// slot. Cleanup observes neither current profiles nor the replacement's graph.
func (p *orderedCandidatePreparation) retire(ctx context.Context) error {
	if ctx == nil || p == nil || p.app == nil {
		return errors.New("candidate retirement lost its original owner")
	}
	p.cancel()
	if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
		return err
	}
	if p.down {
		p.mu.Unlock()
		return ctx.Err()
	}
	done := p.workerDone
	p.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return errors.Join(ctx.Err(), errors.New("original candidate worker has not joined"))
		}
	}
	if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
		return err
	}
	launch, pending := p.launch, p.pending
	p.mu.Unlock()
	if pending != nil {
		if launch == nil {
			return errors.New("pending candidate child lost its retained launch")
		}
		if err := retryDesktopNodeChainCandidateDrain(ctx, launch, pending); err != nil {
			return err
		}
		if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
			return err
		}
		p.pending = nil
		p.mu.Unlock()
	}
	if launch != nil {
		if launch.chain == nil || launch.chain.preparation != p {
			return errors.New("candidate retirement lost its bound original purpose")
		}
		if launch.ownedNode == nil && launch.chain.platform == nil && launch.command == nil && launch.directory == "" {
			// Socket-free preparation can be cancelled before a native host is staged.
			clear(launch.config)
			clear(launch.metadata)
		} else if err := closeDesktopNodeChainLaunch(ctx, p.app, launch); err != nil {
			return err
		}
		// The successful native retirement above owns only this launch. Its
		// coupled graph can now retire; a replacement registry never matches.
		retireNativeMultihopGraph(p.app, launch)
	}
	if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		p.mu.Unlock()
		return err
	}
	if p.app.candidatePreparation == p {
		// A replacement connection context is never cleared or restored. Such a
		// replacement also makes the eventual detached result unadoptable.
		if p.app.connectionContext == p.operation {
			if !orderedCandidatePreparationDownLocked(p.app) {
				p.app.mu.Unlock()
				p.mu.Unlock()
				return errors.New("candidate graph retirement did not confirm Home DOWN")
			}
			p.app.connectionContext, p.app.connectionCancel = nil, nil
			if p.app.connectionCancelIntent == p.operation {
				p.app.connectionCancelIntent = nil
			}
		}
		p.app.candidatePreparation = nil
	}
	release := p.releaseLease
	p.releaseLease, p.down = nil, true
	p.app.mu.Unlock()
	p.mu.Unlock()
	if release != nil {
		release()
	}
	return ctx.Err()
}

// Caller holds app.mu. No ordinary/native identity can remain while this
// original preparation publishes its successful DOWN boundary.
func orderedCandidatePreparationDownLocked(a *app) bool {
	if a == nil || a.cmd != nil || profileSettingsBusy(a.state.Connected, a.state.Phase) {
		return false
	}
	if _, ok := desktopNodeOwners.Load(a); ok {
		return false
	}
	if _, ok := nativeMultihopOwners.Load(a); ok {
		return false
	}
	if _, ok := activeMultihopGraphs.Load(a); ok {
		return false
	}
	if _, ok := desktopRelays.Load(a); ok {
		return false
	}
	return true
}

// The operation lock covers all preparation/measurement work. A failed cleanup
// releases that request's lock only after recording its retained exact owner;
// the existing admission guard then blocks every replacement until Cancel joins.
func (p *orderedCandidatePreparation) finish() error {
	p.finishOnce.Do(func() {
		p.finishError = cleanupViaEntryOwner(p.control, p.owner)
		p.control.mu.Lock()
		p.owner.running = false
		close(p.owner.done)
		p.control.mu.Unlock()
		p.app.operationMu.Unlock()
	})
	return p.finishError
}
