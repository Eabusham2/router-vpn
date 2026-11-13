package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobiletor"
)

func closeOrderedCandidateNativeLaunch(ctx context.Context, p *orderedCandidatePreparation, launch *desktopNodeLaunch) error {
	if ctx == nil || p == nil || launch == nil || p.launch != launch || launch.chain == nil || launch.chain.preparation != p {
		return errors.New("candidate disconnect lost its original immutable launch")
	}
	if launch.chain.platform != nil {
		return launch.chain.platform.closePreparation(ctx, p)
	}
	return closeDesktopNodeChainLaunch(ctx, p.app, launch)
}

type orderedCandidateWindowsRelease struct {
	slot       *desktopNodeProtectionSlot
	attempt    *desktopNodeProtectionAttempt
	target     *mobiletor.DesktopWindowsProtectionTarget
	generation uint64
	retirement desktopNodeProtectionRelease
	done       bool
}

// Full temporary disconnect may release its own joined on-connect successor.
// A failed attempt's unchanged predecessor is never adopted as that successor.
// The original release transaction and generation survive cancellation/retry.
func (p *orderedCandidatePreparation) releaseWindowsProtection(ctx context.Context, launch *desktopNodeLaunch) error {
	if p == nil || launch == nil || launch != p.launch || launch.chain == nil || launch.chain.preparation != p ||
		launch.ownedNode == nil || launch.ownedNode.chain != launch.chain {
		return errors.New("candidate disconnect lost its original retired launch")
	}
	owned := launch.ownedNode
	if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	retired := owned.retired
	launch.workspaceMu.Unlock()
	if !retired {
		return errors.New("candidate protection release preceded native child retirement")
	}
	if owned.attempt == nil && desktopOwnedNodeProcess(launch) == nil {
		return nil // No protection transfer was ever entered.
	}
	slot, attempt := owned.slot, owned.attempt
	if slot == nil || attempt == nil || attempt.launch != launch || attempt.chain != launch.chain.policy {
		return errors.New("candidate disconnect lost its original protection transfer")
	}
	if err := desktopnetwork.LockContext(ctx, &slot.mu); err != nil {
		return err
	}
	defer slot.mu.Unlock()
	if p.windowsRelease != nil {
		if p.windowsRelease.slot != slot || p.windowsRelease.attempt != attempt {
			return errors.New("candidate disconnect substituted its captured protection owner")
		}
		if p.windowsRelease.done {
			return nil
		}
	}
	if !slot.known || slot.active != nil || slot.off != nil {
		return errors.New("candidate disconnect cannot release an active or replaced protection target")
	}
	if p.windowsRelease == nil {
		if slot.retirement != nil {
			return errors.New("candidate disconnect cannot adopt another pending protection release")
		}
		meta := launch.chain.policy.Metadata()
		if slot.target != nil {
			if previous := attempt.transfer.Predecessor; previous != nil && *slot.target == *previous {
				// The exact joined child returned the existing baseline. It
				// remains owned by its predecessor, even for on-connect.
				p.windowsRelease = &orderedCandidateWindowsRelease{slot: slot, attempt: attempt, done: true}
				return nil
			}
			if slot.target.Capture.SessionID != meta.SessionID || slot.target.Capture.SourceSHA256 != meta.SourceSHA256 ||
				slot.target.Policy != meta.KillSwitchPolicy || attempt.prepared != nil && *slot.target != *attempt.prepared {
				return errors.New("candidate disconnect cannot release a different native successor")
			}
		}
		p.windowsRelease = &orderedCandidateWindowsRelease{slot: slot, attempt: attempt,
			target: copyDesktopNodeProtectionTarget(slot.target), generation: slot.generation}
	}
	r := p.windowsRelease
	if r.slot != slot || r.attempt != attempt || r.generation != slot.generation || r.retirement != slot.retirement ||
		(r.target == nil) != (slot.target == nil) || r.target != nil && *r.target != *slot.target {
		return errors.New("candidate disconnect changed its captured protection release generation")
	}
	err := slot.releaseLocked(ctx)
	r.retirement = slot.retirement
	if err != nil {
		return err
	}
	r.done = true
	return nil
}

// Called only after the original native child/protection retirement succeeded.
// The ordinary Windows Stop helper discovers a current global owner; temporary
// retirement instead completes this exact captured launch and preserves any
// replacement command, registry, graph or Home state.
func (p *orderedCandidatePreparation) finishWindowsNativeDown(ctx context.Context, launch *desktopNodeLaunch) error {
	if p == nil || p.app == nil || launch == nil || launch != p.launch || launch.ownedNode == nil ||
		launch.chain == nil || launch.chain.preparation != p || launch.ownedNode.chain != launch.chain {
		return errors.New("candidate native DOWN lost its original Windows launch")
	}
	if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	retired := launch.ownedNode.retired
	launch.workspaceMu.Unlock()
	if !retired {
		return errors.New("candidate native DOWN has no joined child and protection retirement")
	}
	if err := p.releaseWindowsProtection(ctx, launch); err != nil {
		return err
	}
	if !p.workspaceDown {
		if err := cleanupDesktopNodeLaunch(launch); err != nil {
			return err
		}
		// This retained completion is essential if a later publication lock
		// times out: a missing directory alone never authorizes a retry.
		p.workspaceDown = true
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	defer p.app.mu.Unlock()
	desktopNodeOwners.CompareAndDelete(p.app, launch)
	if p.app.candidatePreparation == p && p.app.connectionContext == p.operation &&
		(p.app.cmd == launch.command || p.app.cmd == nil && launch.command == nil) {
		p.app.cmd = nil
		p.app.state = p.state
		clearActiveDNSRuntimeConfig(p.app)
	}
	return ctx.Err()
}

func (r *orderedCandidatePreparedRuntime) beforeNativeDown(ctx context.Context) {
	if r == nil || r.cohort == nil || r.transition {
		return
	}
	if err := r.cohort.Begin(ctx, r.receipt); err != nil {
		r.preparation.invalidate()
		return
	}
	r.transition = true
}

func (r *orderedCandidatePreparedRuntime) afterNativeDown(ctx context.Context) {
	if r == nil || r.cohort == nil || !r.transition {
		return
	}
	if err := r.cohort.End(ctx, nil); err != nil {
		r.preparation.invalidate()
		return
	}
	r.transition, r.receipt = false, nil
}

func (r *orderedCandidatePreparedRuntime) closeCohort() error {
	if r == nil {
		return nil
	}
	if r.cohort != nil {
		if err := r.cohort.Close(); err != nil {
			return err
		}
	}
	if r.stopCohort != nil {
		r.stopCohort()
	}
	return nil
}
