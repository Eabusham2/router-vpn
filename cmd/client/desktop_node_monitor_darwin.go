//go:build darwin

package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

func (h *desktopMacOSPairedNodeHost) Monitor(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.current(ctx, true); err != nil {
		return err
	}
	if !h.activated || h.monitorDone != nil {
		return errors.New("macOS paired Node monitor has no unused original activation")
	}
	watch, cancel := context.WithCancel(h.parent.parent.ctx)
	done := make(chan struct{})
	h.monitorCancel, h.monitorDone = cancel, done
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		var once sync.Once
		end := func() { once.Do(func() { ticker.Stop(); cancel(); close(done) }) }
		defer end()
		a, launch := h.parent.app, h.launch
		observe := func() (error, bool) {
			before := h.mtuObservation.value.Load()
			call, stop := context.WithTimeout(watch, 2*time.Second)
			defer stop()
			err := h.Current(call)
			return err, err != nil && h.mtuObservation.deferFailure(h, launch, before)
		}
		for {
			select {
			case <-watch.Done():
				return
			case <-ticker.C:
			}
			if !a.ownsConnectionRuntime(launch.command) {
				return
			}
			if err, cleanup := observe(); err == nil || cleanup {
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
			if err, cleanup := observe(); err == nil || cleanup {
				release()
				continue
			}
			end()
			invalidateDesktopMacOSPairedNodeMeasurements(a, launch)
			err := a.stopModeWithIntent(true)
			message := "captured macOS paired Node path retired; original protection is held"
			if err != nil {
				message += "; " + err.Error()
			}
			a.mu.Lock()
			if a.cmd == launch.command || a.cmd == nil && a.state.RouterID == launch.policyProfileID {
				a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
			}
			a.mu.Unlock()
			sessionTrackerFor(a).markRequestFailure(message)
			release()
			return
		}
	}()
	return nil
}

func invalidateDesktopMacOSPairedNodeMeasurements(a *app, launch *desktopNodeLaunch) {
	a.mu.Lock()
	dns, latency := a.dnsMeasurements, a.latencyMeasurements
	a.mu.Unlock()
	if dns != nil {
		dns.mu.Lock()
		operation := dns.current
		if operation != nil && operation.snapshot.launch != launch {
			operation = nil
		}
		dns.mu.Unlock()
		if operation != nil {
			operation.invalidate()
		}
	}
	if latency != nil {
		latency.mu.Lock()
		operation := latency.current
		if operation != nil && operation.snapshot.launch != launch {
			operation = nil
		}
		latency.mu.Unlock()
		if operation != nil {
			operation.invalidate()
		}
	}
}
