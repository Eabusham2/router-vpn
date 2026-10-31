package main

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/multihoprelay"
)

// Native PQ/MAX startup completes its initial-key phase before the child can
// publish its first captured TUN readback. Wait for that exact owner, then run
// the ordinary private-node proof with its unchanged per-probe deadline. A
// readback alone never reports Connected or supplies a path measurement.
func (a *app) testStartedModeHealth(parent context.Context, profile common.RouterProfile, launch *desktopNodeLaunch) (time.Duration, error) {
	if launch != nil && launch.ownedNode != nil {
		return a.testDesktopOwnedNodeHealth(parent, profile, launch)
	}
	if launch == nil || multihoprelay.NativeStartupAllowance(launch.mode) == 0 {
		return a.testHealthContext(parent, profile)
	}
	current := func() error {
		if parent == nil || parent.Err() != nil || a.checkConnectionOperation() != nil || a.connectionOperationContextOrBackground() != parent {
			return errConnectionOperationCancelled
		}
		if launch.external != nil || launch.tor != nil || launch.profileID != profile.ID ||
			launch.command == nil || !a.ownsConnectionRuntime(launch.command) {
			return errors.New("native node startup lost its captured connection")
		}
		if owned, ok := desktopNodeOwners.Load(a); !ok || owned != launch {
			return errors.New("native node startup lost its captured TUN owner")
		}
		return nil
	}
	if err := current(); err != nil {
		return 0, err
	}
	// Preserve the ordinary startup/proof window and add only this captured
	// peer's existing initial-key phase. Both readiness and proof spend the
	// same deadline; a late readback cannot restart a full proof window.
	budget := time.Duration(a.cfg.AutoTestSeconds)*time.Second + multihoprelay.NativeStartupAllowance(launch.mode)
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := current(); err != nil {
			return 0, err
		}
		if stopped, err := readDesktopNodeStopped(launch); err != nil || stopped {
			return 0, errors.Join(errors.New("native node stopped before initial-key readiness"), err)
		}
		if desktopNodeProcessExited(launch) {
			return 0, errors.New("native node exited before initial-key readiness")
		}
		if record, err := readDesktopNodeMTU(launch); err == nil {
			if record.Failure != "" || record.Active || record.Restored || record.Expired ||
				record.Generation != 0 || record.Request != "" || record.Lease != "" || record.Reader != 1 {
				return 0, errors.New("native node startup readback is not its initial owned TUN")
			}
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			if err := current(); err != nil {
				return 0, err
			}
			break
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
	// The initial-key allowance must not become a larger steady-state health
	// timeout. This request keeps the operation captured before startup began.
	latency, err := a.testHealthContext(ctx, profile)
	if deadlineErr := ctx.Err(); deadlineErr != nil {
		return 0, deadlineErr
	}
	if ownershipErr := current(); ownershipErr != nil {
		return 0, ownershipErr
	}
	return latency, err
}
