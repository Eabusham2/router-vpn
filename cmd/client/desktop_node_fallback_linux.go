//go:build linux

package main

import (
	"context"
	"errors"
	"time"
)

// Fallback release consumes only an already joined original session target.
// It cannot stop an active host or adopt the fixed legacy guard. Empty Node
// sessions defer to their actual legacy owner; unresolved Node state remains
// handled even when its original release fails. The caller holds operationMu.
func (a *app) releaseDesktopLinuxNodeFallbackProtection() (bool, error) {
	captured, err := a.captureDesktopNodeStop()
	if err != nil {
		return true, err
	}
	if captured == nil {
		return false, nil
	}
	if captured.host != nil || captured.command != nil {
		return true, errors.New("Linux fallback protection release requires its original host to retire first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return true, captured.Retire(ctx, nil, true)
}

// Cancellation may join only the native candidate created by this exact
// request. A previously proved connection can survive a failed preflight of a
// later request; its original operation is not adopted by that later cleanup.
// Joined held protection has no live engine and remains with the same session.
func (a *app) stopDesktopLinuxNodeForOperation(operation context.Context, hold bool) (bool, error) {
	if !a.sameConnectionOperation(operation) {
		return true, errors.Join(errConnectionOperationCancelled, errDesktopNodeOperationReplaced)
	}
	captured, err := a.captureDesktopNodeStop()
	if err != nil {
		return true, err
	}
	if captured == nil {
		return false, nil
	}
	if captured.host != nil && captured.host.operation != operation {
		return true, errors.Join(errConnectionOperationCancelled, errDesktopNodeOperationReplaced)
	}
	if err := captured.currentApp(captured.command, false); err != nil || !a.sameConnectionOperation(operation) {
		return true, errors.Join(err, errConnectionOperationCancelled, errDesktopNodeOperationReplaced)
	}
	// Ordinary Stop captures and drains the real MTU owner before joined
	// retirement. No other command observer, signal or Wait is introduced here.
	return true, a.stopModeWithIntent(hold)
}
