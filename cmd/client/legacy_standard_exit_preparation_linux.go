//go:build linux

package main

import (
	"context"
	"errors"
	"sync"
)

// Each key is the original unstarted private capture. A later preparation
// cannot overwrite another capture, or borrow a live runtime's cleanup owner.
var legacyStandardExitPreparations sync.Map // map[*linuxLegacyStandardExitOwner]*app

func retireLegacyStandardPreparations(a *app, ctx context.Context) error {
	var failure error
	legacyStandardExitPreparations.Range(func(key, value any) bool {
		if value != a {
			return true
		}
		owner, ok := key.(*linuxLegacyStandardExitOwner)
		if !ok || owner == nil || owner.app != a {
			failure = errors.New("standard preparation retry lost its original owner")
			return false
		}
		owner.mu.Lock()
		if owner.registered || owner.started || owner.protection != nil || owner.offInherited != nil || owner.command != nil && owner.command.Process != nil {
			failure = errors.New("standard preparation retry cannot retire an adopted runtime")
		} else {
			failure = owner.discardLocked(ctx)
			if failure == nil && !legacyStandardExitPreparations.CompareAndDelete(owner, a) {
				failure = errors.New("standard preparation retry entry changed during cleanup")
			}
		}
		owner.mu.Unlock()
		return failure == nil
	})
	return failure
}
