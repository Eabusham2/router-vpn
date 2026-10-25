package main

import (
	"errors"

	"router-vpn/internal/common"
)

// Preparation can perform filesystem work while Disconnect cancels its
// transaction. Check the originally captured context and runtime, not whatever
// operation/profile happens to be current when exec.Start is reached.
func (a *app) speedLabTorPrelaunchCheck(profile common.RouterProfile) func() error {
	a.mu.Lock()
	operation, command, selected := a.connectionContext, a.cmd, a.profiles.SelectedID
	rawOwner, owned := speedLabTemporaryOwners.Load(a)
	owner, validOwner := rawOwner.(*speedLabTemporaryOwner)
	token := liveMeasurementProfileToken(profile)
	a.mu.Unlock()
	return func() error {
		if operation != nil && operation.Err() != nil {
			return errConnectionOperationCancelled
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.closing || a.connectionContext != operation || a.cmd != command || a.profiles.SelectedID != selected {
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
		return nil
	}
}
