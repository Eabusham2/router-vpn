package main

import (
	"context"
	"errors"
	"fmt"
)

func (a *app) finalizeCancelledFallback(scope string) error {
	return a.finalizeCancelledFallbackFor(scope, a.connectionOperationContextOrBackground())
}

func (a *app) finalizeCancelledFallbackFor(scope string, operation context.Context) error {
	message := errConnectionOperationCancelled.Error()
	if scope != "" {
		message = scope + ": " + message
	}
	if !a.sameConnectionOperation(operation) {
		return errors.Join(errConnectionOperationCancelled, errors.New("cancelled fallback no longer owns the current operation"))
	}
	a.mu.Lock()
	slot := a.nodeProtection
	command := a.cmd
	a.mu.Unlock()
	owned, releaseErr := a.stopDesktopNodeForOperation(operation)
	if errors.Is(releaseErr, errDesktopNodeOperationReplaced) {
		return errors.Join(errConnectionOperationCancelled, releaseErr)
	}
	if !a.sameConnectionOperation(operation) {
		return errors.Join(errConnectionOperationCancelled, releaseErr, errors.New("cancelled fallback cannot release replacement protection"))
	}
	a.mu.Lock()
	sameSlot := a.nodeProtection == slot
	sameRuntime := !owned || a.cmd == nil || a.cmd == command
	a.mu.Unlock()
	if !sameSlot || !sameRuntime {
		return errors.Join(errConnectionOperationCancelled, releaseErr, errDesktopNodeOperationReplaced)
	}
	if releaseErr == nil {
		if slot != nil {
			releaseErr = a.releaseCapturedDesktopNodeProtection(slot)
		} else {
			releaseErr = a.releaseTransitionKillSwitch()
		}
	}
	if !a.sameConnectionOperation(operation) {
		return errors.Join(errConnectionOperationCancelled, releaseErr, errors.New("cancelled fallback cannot change replacement state"))
	}
	emptySlot := slot != nil && slot.provedEmpty()

	a.mu.Lock()
	if a.connectionContext != operation && !(a.connectionContext == nil && operation == context.Background()) {
		a.mu.Unlock()
		return errors.Join(errConnectionOperationCancelled, releaseErr, errors.New("cancelled fallback was replaced before finalization"))
	}
	if owned && a.cmd != nil && a.cmd != command || a.nodeProtection != slot && !(a.nodeProtection == nil && emptySlot) {
		a.mu.Unlock()
		return errors.Join(errConnectionOperationCancelled, releaseErr, errDesktopNodeOperationReplaced)
	}
	a.state.Connected = false
	if releaseErr != nil {
		a.state.Phase = "failed"
		a.state.LastError = message + "; " + releaseErr.Error()
	} else {
		a.state.Phase = "off"
		a.state.LastError = message
	}
	a.mu.Unlock()

	tracker := sessionTrackerFor(a)
	tracker.strategyEvent("connection-cancelled", message)
	if releaseErr != nil {
		cleanupErr := fmt.Errorf("%s; cancellation cleanup failed: %w", message, releaseErr)
		tracker.markRequestFailure(cleanupErr.Error())
		return errors.Join(errConnectionOperationCancelled, cleanupErr)
	}
	tracker.markRequestFailure(message)
	return errConnectionOperationCancelled
}
