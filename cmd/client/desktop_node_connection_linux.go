//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This is a narrow platform dispatcher, not a new graph capability predicate.
// Other modes keep their existing host. Selected protected Shadowsocks, WG, AWG2, Hysteria2 and ss-v2ray
// must use its actual installed Linux owner even when its package is missing;
// verification failure never falls back to a differently owned legacy helper.
func (a *app) desktopLinuxNodeConnectionSelected(profile common.RouterProfile, mode string) bool {
	return a.desktopNodeConnectionHost() == nil && (mode == "shadowsocks" || mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" || mode == "hysteria2" || mode == "ss-v2ray") && desktopOwnedNodeProtectionPolicy(profile) != "off"
}

func validateDesktopLinuxNodeConnection(profile common.RouterProfile, mode string, options [3]bool) error {
	policy := desktopOwnedNodeProtectionPolicy(profile)
	if !mobilemultihop.DesktopLinuxNodePhysicalGraphSupported(mode, profile.StartLayer) || profile.External != nil ||
		profile.NodeKind != "" && profile.NodeKind != "router-vpn" || policy != "on-connect" && policy != "always" {
		return errors.New("Linux retained connection requires a supported protected graph and exact Start Layer")
	}
	return nil
}

// Captured before preparation, so neither a DNS/package callback nor a later
// native preflight may adopt whichever connection happens to be selected then.
type desktopLinuxNodeConnectPreflight struct {
	app        *app
	controller *ownedDesktopController
	operation  context.Context
	command    *exec.Cmd
	state      state
	prior      *desktopNodeStopCapture
	session    *desktopLinuxNodeSession
	host       *desktopLinuxNodeHost
	selected   string // External Connect retains its explicit initial UI selection.
}

func (capture *desktopLinuxNodeConnectPreflight) current(ctx context.Context) error {
	if capture == nil || capture.app == nil || capture.session == nil || capture.host == nil ||
		capture.operation == nil || capture.operation.Err() != nil {
		return errors.New("Linux Connect preflight lost its original request and prepared host")
	}
	s, h, a := capture.session, capture.host, capture.app
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.journalErr != nil || !sameDesktopLinuxParentCapture(s.parent, h.parent) || s.active == h {
		return errors.New("Linux Connect preflight cannot reuse an incomplete or foreign retained session")
	}
	if prior := capture.prior; prior != nil {
		if prior.session != s || prior.host != s.active || prior.predecessor != s.predecessor || prior.journal != s.journal ||
			prior.command != capture.command || prior.currentApp(capture.command, false) != nil {
			return errors.New("Linux Connect preflight replaced its captured previous source")
		}
	} else {
		if capture.command != nil || capture.state.Connected || capture.state.Mode != "" && capture.state.Mode != "off" {
			return errors.New("Linux Connect cannot inherit an unrelated running or unfinished legacy connection")
		}
		if err := s.unclaimedStopLocked(ctx); err != nil {
			return err
		}
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.current(ctx); err != nil {
		return err
	}
	if h.startEntered || h.process != nil || h.transaction != nil || h.activation != nil {
		return errors.New("Linux Connect preflight already entered its original launch")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return capture.currentAppLocked()
}

// The caller holds app.mu after its native/session/host observations. This
// comparison is also exercised independently; it grants no native admission.
func (capture *desktopLinuxNodeConnectPreflight) currentAppLocked() error {
	a, h := capture.app, capture.host
	selected := capture.selected
	if selected == "" {
		selected = h.launch.profileID
	}
	profile, exists := a.profileByIDLocked(h.launch.profileID)
	_, duplicate := desktopNodeOwners.Load(a)
	if duplicate || a.localController != capture.controller || a.checkCapturedConnectionOperationLocked(capture.operation) != nil ||
		a.connectionCancelIntent == capture.operation || h.parent.currentAppLocked(false) != nil ||
		a.cmd != capture.command || a.state != capture.state || !exists || a.profiles.SelectedID != selected ||
		desktopOwnedNodeProfileToken(profile) != h.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != h.savedOptions {
		return errors.New("Linux Connect preflight belongs to a replaced command, selection or private profile")
	}
	return nil
}

// startModeAttempt retains operationMu. Preparation, fixed-guard observation
// and private staging all finish before StopBegun. Only the existing native
// activation can publish Connected; this bridge never writes that bit true.
func (a *app) startDesktopLinuxNodeConnection(operation context.Context, profile common.RouterProfile, mode common.Mode,
	options [3]bool, holdOnFailure bool, transition ...*modeAttemptTransition) (handled bool, failure error) {
	if !a.desktopLinuxNodeConnectionSelected(profile, mode.ID) {
		return false, nil
	}
	if len(transition) > 1 {
		return true, errors.New("Linux connection has more than one transition owner")
	}
	if err := validateDesktopLinuxNodeConnection(profile, mode.ID, options); err != nil {
		return true, err
	}
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return true, err
	}
	if err := a.resumeDesktopLinuxEmptyRecovery(operation); err != nil {
		return true, err
	}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, a.checkCapturedConnectionOperation(operation))
		}
	}()
	if a.retainedDesktopNodeProtection() {
		return true, errors.New("Linux Connect cannot inherit another native platform's retained protection")
	}
	a.mu.Lock()
	capture := &desktopLinuxNodeConnectPreflight{app: a, operation: operation, controller: a.localController, command: a.cmd, state: a.state}
	a.mu.Unlock()
	prior, err := a.captureDesktopNodeStop()
	if err != nil {
		return true, err
	}
	capture.prior = prior
	profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled = options[0], options[1], options[2]
	ctx, cancel := context.WithTimeout(operation, 7*time.Minute)
	defer cancel()
	host, err := prepareDesktopLinuxNodeHost(operation, a, profile, mode.ID, 0)
	capture.host = host
	stopped := false
	if host != nil {
		defer func() {
			if failure == nil {
				return
			}
			cleanup, finish := context.WithTimeout(context.Background(), 20*time.Second)
			defer finish()
			failure = errors.Join(failure, capture.cleanup(cleanup, stopped, holdOnFailure), a.speedLabCheckLaunchedRuntime())
			if stopped {
				capture.publishFailure(failure)
			}
		}()
	}
	if err != nil {
		return true, err
	}
	capture.session, err = captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return true, err
	}
	if err := capture.current(ctx); err != nil {
		return true, err
	}
	if err := host.CheckLegacyTransition(ctx); err != nil {
		return true, err
	}
	if err := host.Stage(ctx); err != nil {
		return true, err
	}
	if err := capture.current(ctx); err != nil {
		return true, err
	}
	if len(transition) == 1 && transition[0] != nil {
		transition[0].StopBegun = true
	}
	if err := a.stopModeWithIntent(true); err != nil {
		return true, err
	}
	stopped = true
	session := capture.session
	err = session.Start(ctx, host)
	if host.launch.command != nil && a.ownsConnectionRuntime(host.launch.command) {
		err = errors.Join(err, a.speedLabOwnRuntime(host.launch.command))
	}
	if err != nil {
		return true, err
	}
	if _, err := host.WaitReady(ctx); err != nil {
		return true, err
	}
	elapsed, err := host.Prove(ctx)
	if err != nil {
		return true, fmt.Errorf("%s started but selected-router path proof failed: %w", mode.Name, err)
	}
	if err := host.Activate(ctx); err != nil {
		return true, err
	}
	if err := session.Monitor(ctx, host); err != nil {
		return true, err
	}
	path, owned, err := captureDesktopLinuxNodePath(ctx, a, host.launch.command)
	if err != nil || !owned || path == nil || path.host != host || path.session != session {
		return true, errors.Join(err, errors.New("Linux Connect lost its freshly activated retained path"))
	}
	a.mu.Lock()
	if a.checkCapturedConnectionOperationLocked(operation) != nil || a.connectionCancelIntent == operation ||
		host.parent.currentAppLocked(false) != nil || a.cmd != host.launch.command || !a.state.Connected ||
		a.state.Phase != "connected" || a.state.RouterID != profile.ID || a.state.RuntimeMode != mode.ID || a.profiles.SelectedID != profile.ID {
		a.mu.Unlock()
		return true, errors.New("Linux Connect completion belongs to a replaced request or native command")
	}
	if usageErr := a.recordProfileUsageLocked(profile.ID, time.Now().UTC()); usageErr != nil {
		log.Printf("profile usage metadata was not persisted: %v", usageErr)
	}
	a.mu.Unlock()
	log.Printf("mode %s selected-router path proof OK in %.2f ms", mode.ID, float64(elapsed.Microseconds())/1000)
	a.startRouterNodeAutomaticMTU()
	return true, nil
}

func (capture *desktopLinuxNodeConnectPreflight) cleanup(ctx context.Context, stopped, hold bool) error {
	h, s, a := capture.host, capture.session, capture.app
	if h == nil {
		return nil
	}
	if s == nil {
		return h.Close(ctx)
	}
	if err := s.enter(ctx); err != nil {
		return err
	}
	active := s.active
	s.gate <- struct{}{}
	if active == h {
		return s.Retire(ctx, h, !hold)
	}
	if err := h.Close(ctx); err != nil {
		return err
	}
	// A staged failure after the old Stop still owns its joined predecessor.
	// Only that same idle request may release On-connect; Always stays closed.
	if !stopped || hold || active != nil {
		return nil
	}
	a.mu.Lock()
	current := a.sameConnectionOperationLocked(capture.operation) && h.parent.currentAppLocked(false) == nil && a.cmd == nil && !a.state.Connected
	a.mu.Unlock()
	if !current {
		return errors.New("Linux failed startup cannot release a replaced request's retained protection")
	}
	return s.Retire(ctx, nil, true)
}

func (capture *desktopLinuxNodeConnectPreflight) publishFailure(failure error) {
	a, h := capture.app, capture.host
	a.mu.Lock()
	defer a.mu.Unlock()
	if failure != nil && a.sameConnectionOperationLocked(capture.operation) && h.parent.currentAppLocked(false) == nil &&
		(a.cmd == nil || a.cmd == h.launch.command && a.state.RouterID == h.launch.profileID && a.state.RuntimeMode == h.launch.mode) {
		a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", failure.Error()
	}
}

// Existing callers use this before Stop for legacy Router, external and
// multihop paths. An empty/released session may defer only through its actual
// original checkpoint/native absence proof; this never creates a session.
func (a *app) guardDesktopLinuxNodeLegacyTransition() error {
	captured, err := a.captureDesktopNodeStop()
	if err != nil {
		return err
	}
	if captured != nil {
		return errors.New("the selected path cannot inherit the retained Linux protection; disconnect the current on-connect path first")
	}
	return nil
}
