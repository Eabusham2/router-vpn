package main

import (
	"context"
	"errors"
)

// A temporary Speed Lab test owns both its trial and the subsequent restore.
// Candidate/strategy failure must leave protection with that exact owner;
// its outer transaction joins the trial and chooses restore or explicit Stop.
// The cancelled test context is deliberately distinct from the restore intent.
// Callers hold operationMu and pass their captured operation, never a later one.
func (a *app) speedLabDefersFallbackRelease(operation context.Context) (bool, error) {
	raw, exists := speedLabTemporaryOwners.Load(a)
	if !exists {
		return false, nil
	}
	owner, ok := raw.(*speedLabTemporaryOwner)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !ok || owner == nil || operation == nil || !a.speedLabOwnerCurrentLocked(owner) ||
		owner.test != operation || owner.current != operation || owner.intent == nil ||
		!owner.mutated || owner.restored || a.cmd != nil && a.cmd != owner.runtime {
		return true, errors.New("fallback cleanup no longer owns the captured temporary test")
	}
	return true, nil
}

func (a *app) releaseFallbackKillSwitch(operation context.Context) error {
	if !a.sameConnectionOperation(operation) {
		return errors.Join(errConnectionOperationCancelled, errDesktopNodeOperationReplaced)
	}
	if temporary, err := a.speedLabDefersFallbackRelease(operation); temporary {
		return err
	}
	return a.releaseTransitionKillSwitch()
}
