package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// The watcher owns no shutdown authority until it holds operationMu for this
// exact command. Its watch loop is joined before native retirement; a watcher
// initiating Stop ends that loop first and completes Stop under operationMu,
// so controller shutdown cannot outlive its remaining cleanup work.
func (a *app) monitorDesktopOwnedNodeRuntime(launch *desktopNodeLaunch) {
	if launch == nil || launch.ownedNode == nil {
		return
	}
	launch.workspaceMu.Lock()
	owned := launch.ownedNode
	if owned.monitorDone != nil || owned.retired {
		launch.workspaceMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	owned.monitorCancel, owned.monitorDone = cancel, done
	launch.workspaceMu.Unlock()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		var finish sync.Once
		endWatch := func() { finish.Do(func() { ticker.Stop(); cancel(); close(done) }) }
		defer endWatch()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !a.ownsConnectionRuntime(launch.command) {
				return
			}
			if _, err := a.readDesktopOwnedNodeReady(launch, false); err == nil {
				continue
			}
			release, current := a.claimRuntimeMonitorOperation(launch.command)
			if !current {
				return
			}
			if release == nil {
				continue
			}
			if !a.ownsConnectionRuntime(launch.command) {
				release()
				return
			}
			if _, err := a.readDesktopOwnedNodeReady(launch, false); err == nil {
				release()
				continue
			}
			endWatch()
			invalidateDesktopDNSResults(a)
			err := a.stopModeWithIntent(true)
			message := "captured native Router source or network retired; exact protection is held"
			if err != nil {
				message += "; " + err.Error()
			}
			a.mu.Lock()
			a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
			a.mu.Unlock()
			sessionTrackerFor(a).markRequestFailure(message)
			release()
			return
		}
	}()
}

func stopDesktopOwnedNodeMonitor(ctx context.Context, launch *desktopNodeLaunch) error {
	if ctx == nil || launch == nil || launch.ownedNode == nil {
		return errors.New("native Router monitor retirement has no captured owner")
	}
	launch.workspaceMu.Lock()
	cancel, done := launch.ownedNode.monitorCancel, launch.ownedNode.monitorDone
	launch.workspaceMu.Unlock()
	if done == nil {
		return nil
	}
	if cancel == nil {
		return errors.New("native Router monitor lost its captured cancellation")
	}
	cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}
