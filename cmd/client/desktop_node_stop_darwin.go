//go:build darwin

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
)

func (h *desktopMacOSPairedNodeHost) stopMonitor(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	cancel, done := h.monitorCancel, h.monitorDone
	h.gate <- struct{}{}
	if done == nil {
		return nil
	}
	if cancel == nil {
		return errors.New("macOS paired Node monitor lost its original cancellation")
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
func (h *desktopMacOSPairedNodeHost) retireNative(ctx context.Context) error {
	if h.nativeRetired {
		return nil
	}
	h.retiring = true
	h.measurementRetired.Store(true)
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

func (h *desktopMacOSPairedNodeHost) closeWithIntent(ctx context.Context, hold bool) error {
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
	if h.parent == nil || h.parent.session == nil || h.launch == nil || h.launch.pairedNode != h || h.policy == nil || h.baselineRun == nil {
		return errors.New("macOS paired Node retirement lost its original typed host")
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return err
	}
	if err := h.retireNative(ctx); err != nil {
		return err
	}
	if h.mtu != nil {
		if err := h.mtu.closeRetiredLocked(ctx); err != nil {
			return err
		}
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
			return errors.New("macOS paired Node private staging retains its uncaptured directory")
		}
		if err := cleanupDesktopNodeLaunch(h.launch); err != nil {
			return err
		}
		h.workspaceRetired = true
	}
	a, p := h.parent.app, h.parent.parent
	a.mu.Lock()
	if h.published {
		value, ok := desktopNodeOwners.Load(a)
		if !ok || value != h.launch || a.cmd != nil && a.cmd != h.launch.command {
			a.mu.Unlock()
			return errors.New("macOS paired Node retirement cannot clear another application command")
		}
	}
	if err := p.enter(ctx); err != nil {
		a.mu.Unlock()
		return err
	}
	if p.originalSession != h.parent.session || h.published && (h.parent.session.pairedNode != h || h.parent.session.external != nil || h.parent.session.nodeChain != nil || h.parent.session.candidatePrefix != nil) {
		p.gate <- struct{}{}
		a.mu.Unlock()
		return errors.New("macOS paired Node retirement belongs to a replaced session")
	}
	if h.published {
		if !desktopNodeOwners.CompareAndDelete(a, h.launch) {
			p.gate <- struct{}{}
			a.mu.Unlock()
			return errors.New("macOS paired Node registry changed during joined retirement")
		}
		h.parent.session.pairedNode = nil
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
		activeDNSRuntimeIdentities.CompareAndDelete(a, activeDNSRuntimeIdentity{ProfileID: h.launch.policyProfileID,
			RuntimeID: h.launch.mode, Config: filepath.Join(h.launch.directory, "sing-box.json")})
	}
	h.closed = true
	return nil
}

func (h *desktopMacOSPairedNodeHost) Close(ctx context.Context) error {
	return h.closeWithIntent(ctx, false)
}

type desktopMacOSPairedNodeStopCapture struct {
	host      *desktopMacOSPairedNodeHost
	command   *exec.Cmd
	operation context.Context
}

func (h *desktopMacOSPairedNodeHost) CaptureStop() (desktopRetainedStopCapture, error) {
	if h == nil || h.parent == nil || h.parent.app == nil {
		return nil, errors.New("macOS Stop lacks its original retained host")
	}
	a := h.parent.app
	a.mu.Lock()
	c := &desktopMacOSPairedNodeStopCapture{host: h, command: a.cmd, operation: a.connectionContext}
	a.mu.Unlock()
	return c, c.current()
}

func (c *desktopMacOSPairedNodeStopCapture) current() error {
	if c == nil || c.host == nil || c.host.parent == nil || c.host.parent.app == nil || c.host.launch == nil {
		return errors.New("macOS Stop lost its original capture")
	}
	h, a := c.host, c.host.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	value, found := desktopNodeOwners.Load(a)
	if !found || value != h.launch || a.connectionContext != c.operation || a.cmd != c.command || c.command != h.launch.command ||
		a.state.RouterID != h.launch.policyProfileID || a.state.RuntimeMode != h.launch.mode {
		return errors.New("macOS Stop belongs to another captured operation or child")
	}
	return nil
}
func (c *desktopMacOSPairedNodeStopCapture) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if command != c.command {
		return errors.New("macOS Stop changed its original MTU-held command")
	}
	if err := c.current(); err != nil {
		return err
	}
	return c.host.closeWithIntent(ctx, !disconnect)
}

func (h *desktopMacOSPairedNodeHost) captureStop(ctx context.Context, a *app, p *desktopMacOSParent, s *desktopMacOSSession) (desktopRetainedStopCapture, error) {
	if h == nil || h.parent == nil || h.parent.app != a || h.parent.parent != p || h.parent.session != s {
		return nil, errors.New("macOS paired Node Stop changed its original parent")
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return nil, err
	}
	return h.CaptureStop()
}

func prepareDesktopMacOSPairedNodeMTUStop(ctx context.Context, a *app, command *exec.Cmd, operation context.Context, outer *mtuLiveOwner, terminal bool, failedHold error) (bool, error) {
	if outer == nil {
		return false, nil
	}
	owner, ok := outer.kernel.(*desktopMacOSPairedNodeMTUOwner)
	if !ok {
		return false, nil
	}
	if owner == nil || owner.host == nil || ctx == nil || ctx.Err() != nil || failedHold == nil || errors.Is(failedHold, context.Canceled) || errors.Is(failedHold, context.DeadlineExceeded) {
		return true, errors.New("macOS paired Node MTU teardown has no bounded original failed hold")
	}
	h := owner.host
	if h.parent == nil || h.parent.app != a || command == nil || h.launch.command != command || h.process == nil || !h.process.started.Load() {
		return true, errors.New("macOS paired Node MTU teardown changed its original command")
	}
	lock := mtuRetestLockFor(a)
	if !lock.TryLock() {
		return true, errors.New("macOS paired Node MTU teardown waits for original Retest")
	}
	defer lock.Unlock()
	outer.mu.Lock()
	defer outer.mu.Unlock()
	current := func() error {
		if !outer.stopped || outer.closed || outer.a != a || outer.command != command || outer.kernel != owner || h.mtu != owner || owner.originalLocked() != nil {
			return errors.New("macOS paired Node MTU teardown replaced its drained original lease")
		}
		if err := h.parent.cleanupCurrent(ctx); err != nil {
			return err
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		value, found := mtuLiveOwners.Load(a)
		selected, exists := desktopNodeOwners.Load(a)
		if !found || value != outer || !exists || selected != h.launch || a.cmd != command || a.connectionContext != operation || a.closing != terminal || a.localController != h.parent.controller {
			return errors.New("macOS paired Node MTU teardown changed original application")
		}
		return ctx.Err()
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
	if err := h.retireNative(ctx); err != nil {
		return true, err
	}
	if stopped, err := readDesktopNodeStoppedContext(ctx, h.launch); err != nil || !stopped {
		return true, errors.Join(err, errors.New("macOS paired MTU teardown has no original stop receipt"))
	}
	if err := current(); err != nil {
		return true, err
	}
	a.mu.Lock()
	if a.cmd == command && a.connectionContext == operation {
		a.state.Connected = false
		a.state.Phase = "stopping"
	}
	a.mu.Unlock()
	return true, nil
}
