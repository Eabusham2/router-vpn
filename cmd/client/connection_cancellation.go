package main

import "fmt"

func (a *app) finalizeCancelledFallback(scope string) error {
	message := errConnectionOperationCancelled.Error()
	if scope != "" {
		message = scope + ": " + message
	}
	releaseErr := a.releaseTransitionKillSwitch()

	a.mu.Lock()
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
		return cleanupErr
	}
	tracker.markRequestFailure(message)
	return errConnectionOperationCancelled
}
