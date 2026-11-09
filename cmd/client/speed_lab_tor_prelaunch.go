package main

import (
	"context"
	"errors"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

// Preparation can perform filesystem work while Disconnect cancels its
// transaction. Check the originally captured context and runtime, not whatever
// operation/profile happens to be current when exec.Start is reached.
func (a *app) speedLabTorPrelaunchCheck(profile common.RouterProfile) func() error {
	operation := a.connectionOperationContextOrBackground()
	check, err := a.speedLabTorPrelaunchCheckContext(operation, operation, profile)
	if err != nil {
		return func() error { return err }
	}
	return check
}

func (a *app) speedLabTorPrelaunchCheckContext(ctx, operation context.Context, profile common.RouterProfile) (func() error, error) {
	if ctx == nil || operation == nil {
		return nil, errors.New("Tor Speed Lab admission has no original caller")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	command, selected := a.cmd, a.profiles.SelectedID
	rawOwner, owned := speedLabTemporaryOwners.Load(a)
	owner, validOwner := rawOwner.(*speedLabTemporaryOwner)
	token := liveMeasurementProfileToken(profile)
	a.mu.Unlock()
	return func() error {
		if ctx.Err() != nil || operation.Err() != nil {
			return errConnectionOperationCancelled
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return err
		}
		defer a.mu.Unlock()
		if desktopTorOperationCurrentLocked(a, operation, selected) != nil || a.cmd != command {
			return errors.New("Tor preparation belongs to a retired Speed Lab operation")
		}
		rawCurrent, currentlyOwned := speedLabTemporaryOwners.Load(a)
		currentOwner, validCurrent := rawCurrent.(*speedLabTemporaryOwner)
		if currentlyOwned != owned || currentlyOwned && (!validOwner || !validCurrent || currentOwner != owner) {
			return errors.New("Tor preparation lost its captured temporary owner")
		}
		if owned {
			if !validOwner || !a.speedLabOwnerCurrentLocked(owner) || owner.runtime != command {
				return errors.New("Tor preparation lost its captured runtime owner")
			}
		}
		current, exists := a.profileByIDLocked(profile.ID)
		if !exists || liveMeasurementProfileToken(current) != token {
			return errors.New("Tor private profile changed during Speed Lab preparation")
		}
		return ctx.Err()
	}, nil
}
