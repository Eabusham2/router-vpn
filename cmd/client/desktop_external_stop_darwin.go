//go:build darwin

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
)

func (h *desktopMacOSExternalHost) stopMonitor(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	cancel, done := h.monitorCancel, h.monitorDone
	h.gate <- struct{}{}
	if done == nil {
		return nil
	}
	if cancel == nil {
		return errors.New("macOS external monitor lost its original cancellation")
	}
	cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// The actual stop exchange is the only native cleanup evidence. A forced
// process Close may join an exited child but cannot settle this PF owner.
func (h *desktopMacOSExternalHost) retireNative(ctx context.Context) error {
	if h.nativeRetired {
		return nil
	}
	h.retiring = true
	if h.process != nil && h.process.started.Load() {
		if h.process.NativeCleanup(ctx) != nil {
			if err := h.process.StopAndJoin(ctx); err != nil {
				return err
			}
		}
		if err := h.process.NativeCleanup(ctx); err != nil {
			return err
		}
	}
	h.nativeRetired = true
	return nil
}

func (h *desktopMacOSExternalHost) closeWithIntent(ctx context.Context, hold bool) error {
	if h == nil {
		return nil
	}
	if err := h.stopMonitor(ctx); err != nil {
		return err
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.closed {
		return nil
	}
	if h.parent == nil || h.parent.session == nil || h.launch == nil || h.launch.external == nil || h.launch.external.retained != h || h.policy == nil || h.launch.external.physical != h.policy || h.baselineRun == nil {
		return errors.New("macOS external retirement lost its original typed host")
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return err
	}
	if err := h.retireNative(ctx); err != nil {
		return err
	}
	if h.baselineEntered && (!h.baselineRetired || !hold && h.baseline != nil && h.baseline.Phase == "held") {
		action := "release"
		if hold {
			action = "retire"
		}
		value, err := h.baselineRun(ctx, h.parent, h.selection, action, h.baseline, nil)
		if err != nil {
			return err
		}
		h.baseline = value
		h.baselineRetired = true
	}
	if h.process != nil {
		if err := h.process.Close(ctx); err != nil {
			return err
		}
	}
	if !h.workspaceRetired {
		if h.stageDirectory != "" && h.launch.directory == "" {
			return errors.New("macOS external private staging retains its uncaptured directory")
		}
		if err := cleanupDesktopNodeLaunch(h.launch); err != nil {
			return err
		}
		h.workspaceRetired = true
	}
	a, p := h.parent.app, h.parent.parent
	a.mu.Lock()
	if h.published {
		value, ok := desktopExternalRetainedLaunches.Load(a)
		if !ok || value != h.launch || a.cmd != nil && a.cmd != h.launch.command {
			a.mu.Unlock()
			return errors.New("macOS external retirement cannot clear another application command")
		}
	}
	if err := p.enter(ctx); err != nil {
		a.mu.Unlock()
		return err
	}
	if p.originalSession != h.parent.session || h.published && h.parent.session.external != h {
		p.gate <- struct{}{}
		a.mu.Unlock()
		return errors.New("macOS external retirement belongs to a replaced session")
	}
	if h.published {
		if !desktopExternalRetainedLaunches.CompareAndDelete(a, h.launch) {
			p.gate <- struct{}{}
			a.mu.Unlock()
			return errors.New("macOS external registry changed during joined retirement")
		}
		h.parent.session.external = nil
		a.cmd = nil
		a.state.Connected = false
		a.state.Mode = "off"
		a.state.LogicalMode = ""
		a.state.RuntimeMode = ""
		a.state.Base = ""
		a.state.Phase = "off"
		a.state.LastError = ""
	}
	// Removing only successfully joined original dependents is safe even if
	// parent shutdown already copied its retirement list; Close is idempotent.
	delete(h.parent.session.dependents, h)
	if h.process != nil {
		delete(h.parent.session.dependents, h.process)
	}
	p.gate <- struct{}{}
	cover := a.daitaCancel
	if h.published {
		a.daitaCancel = nil
	}
	a.mu.Unlock()
	if h.published {
		if cover != nil {
			cover()
		}
		// Only this session's private config is ours. A replacement can publish
		// its own DNS/graph after the app lock is released; never erase it.
		activeDNSRuntimeIdentities.CompareAndDelete(a, activeDNSRuntimeIdentity{ProfileID: h.launch.profileID,
			RuntimeID: h.launch.mode, Config: filepath.Join(h.launch.directory, "sing-box.json")})
	}
	h.closed = true
	return nil
}

// A failed native path invalidates only measurements captured from this
// launch. Explicit Disconnect keeps completed drafts under their existing
// source/network validation, matching the ordinary measurement contract.
func invalidateDesktopMacOSExternalMeasurements(a *app, launch *desktopNodeLaunch) {
	a.mu.Lock()
	dns, latency := a.dnsMeasurements, a.latencyMeasurements
	a.mu.Unlock()
	if dns != nil {
		dns.mu.Lock()
		operation := dns.current
		if operation != nil && operation.snapshot.launch != launch {
			operation = nil
		}
		if dns.session == launch.external.session {
			dns.used = map[string]bool{}
			dns.cancelled = map[string]desktopDNSView{}
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
		if latency.session == launch.external.session {
			latency.used = map[string]bool{}
			latency.cancelled = map[string]desktopLatencyView{}
		}
		latency.mu.Unlock()
		if operation != nil {
			operation.invalidate()
		}
	}
}

func (h *desktopMacOSExternalHost) Close(ctx context.Context) error {
	return h.closeWithIntent(ctx, false)
}

type desktopMacOSExternalStopCapture struct {
	host      *desktopMacOSExternalHost
	command   *exec.Cmd
	operation context.Context
}

func (h *desktopMacOSExternalHost) CaptureStop() (desktopRetainedStopCapture, error) {
	if h == nil || h.parent == nil || h.parent.app == nil {
		return nil, errors.New("macOS Stop lacks its original retained host")
	}
	a := h.parent.app
	a.mu.Lock()
	c := &desktopMacOSExternalStopCapture{host: h, command: a.cmd, operation: a.connectionContext}
	a.mu.Unlock()
	return c, c.current()
}

func (c *desktopMacOSExternalStopCapture) current() error {
	if c == nil || c.host == nil || c.host.parent == nil || c.host.parent.app == nil || c.host.launch == nil {
		return errors.New("macOS Stop lost its original capture")
	}
	h, a := c.host, c.host.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	value, found := desktopExternalRetainedLaunches.Load(a)
	if !found || value != h.launch || a.connectionContext != c.operation || a.cmd != c.command || c.command != h.launch.command ||
		a.state.RouterID != h.launch.profileID || a.state.RuntimeMode != h.launch.mode {
		return errors.New("macOS Stop belongs to another captured operation or child")
	}
	return nil
}
func (c *desktopMacOSExternalStopCapture) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if command != c.command {
		return errors.New("macOS Stop changed its original MTU-held command")
	}
	if err := c.current(); err != nil {
		return err
	}
	return c.host.closeWithIntent(ctx, !disconnect)
}

// MTU cancellation may require closing the original TUN before its lease can
// discharge. Keep the selected command, workspace and baseline for the Stop
// capture made before the hold. Only actual native cleanup can satisfy it.
func prepareDesktopPlatformMTUStop(ctx context.Context, a *app, command *exec.Cmd, operation context.Context, outer *mtuLiveOwner, terminal bool, _ error) (bool, error) {
	value, found := desktopExternalRetainedLaunches.Load(a)
	if !found {
		return false, nil
	}
	launch, ok := value.(*desktopNodeLaunch)
	if !ok || launch == nil || launch.external == nil {
		return true, errors.New("macOS MTU stop lost its retained launch")
	}
	h, ok := launch.external.retained.(*desktopMacOSExternalHost)
	if !ok || h == nil || h.parent == nil || h.parent.app != a || command == nil || command != launch.command || outer == nil {
		return true, errors.New("macOS MTU stop lost its original host and owner")
	}
	current := func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		actual, present := mtuLiveOwners.Load(a)
		selected, exists := desktopExternalRetainedLaunches.Load(a)
		if ctx.Err() != nil || !present || actual != outer || !exists || selected != launch || a.cmd != command || a.connectionContext != operation ||
			a.closing != terminal || a.localController != h.parent.controller || a.state.RouterID != launch.profileID || a.state.RuntimeMode != launch.mode {
			return errors.New("macOS MTU stop belongs to a replaced captured operation")
		}
		return nil
	}
	if err := current(); err != nil {
		return true, err
	}
	if err := h.stopMonitor(ctx); err != nil {
		return true, err
	}
	if err := h.enter(ctx); err != nil {
		return true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := current(); err != nil {
		return true, err
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return true, err
	}
	if err := h.retireNative(ctx); err != nil {
		return true, err
	}
	return true, current()
}
