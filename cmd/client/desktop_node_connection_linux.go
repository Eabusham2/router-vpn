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
	"router-vpn/internal/mobiletor"
)

// This is a narrow platform dispatcher, not a new graph capability predicate.
// Other modes keep their existing host. Selected Shadowsocks, WG, AWG2,
// Hysteria2, ss-v2ray and Naive H2
// must use its actual installed Linux owner even when its package is missing;
// verification failure never falls back to a differently owned legacy helper.
func (a *app) desktopLinuxNodeConnectionSelected(profile common.RouterProfile, mode string) bool {
	if a.desktopNodeConnectionHost() != nil {
		return false
	}
	if mode == "wg-pq" || mode == "naive-h3" {
		a.mu.Lock()
		installed := a.localController != nil
		a.mu.Unlock()
		// A verified native package is selected from its receipt. A missing
		// or altered file observed after selection still fails native preflight.
		_, retained := desktopNodeOwners.Load(a)
		return installed && (retained || desktopNodeNativeSelected(mode)) && mobilemultihop.DesktopLinuxRetainedNodeGraphSupported(mode, profile.StartLayer, desktopOwnedNodeProtectionPolicy(profile))
	}
	return (mode == "shadowsocks" || mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" || mode == "hysteria2" || mode == "ss-v2ray" || mode == "naive-h2" || mode == "reality-vision" || mode == "reality-pq-vision" || mode == "reality-xhttp")
}

func validateDesktopLinuxNodeConnection(profile common.RouterProfile, mode string, options [3]bool) error {
	policy := desktopOwnedNodeProtectionPolicy(profile)
	if !mobilemultihop.DesktopLinuxRetainedNodeGraphSupported(mode, profile.StartLayer, policy) || profile.External != nil ||
		profile.NodeKind != "" && profile.NodeKind != "router-vpn" || policy != "off" && policy != "on-connect" && policy != "always" {
		return errors.New("Linux retained connection requires a supported captured graph and exact Start Layer")
	}
	return nil
}

// Captured before preparation, so neither a DNS/package callback nor a later
// native preflight may adopt whichever connection happens to be selected then.
type desktopLinuxNodeConnectPreflight struct {
	app              *app
	controller       *ownedDesktopController
	operation        context.Context
	command          *exec.Cmd
	state            state
	smartPredecessor *desktopSmartLegacyCapture
	prior            *desktopNodeStopCapture
	session          *desktopLinuxNodeSession
	host             *desktopLinuxNodeHost
	selected         string // External Connect retains its explicit initial UI selection.
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
	if capture.smartPredecessor != nil {
		if capture.prior != nil || h.standardTransfer != nil || h.selection.Policy != "off" ||
			capture.smartPredecessor.wrapper.root != linuxOwnedControllerRoot {
			return errors.New("SMART cannot transfer a protected wrapper or another native owner")
		}
		if err := s.unclaimedStopLocked(ctx); err != nil {
			return err
		}
	} else if prior := capture.prior; prior != nil {
		if prior.session != s || prior.host != s.active || prior.predecessor != s.predecessor || prior.journal != s.journal ||
			prior.command != capture.command || prior.currentApp(capture.command, false) != nil {
			return errors.New("Linux Connect preflight replaced its captured previous source")
		}
	} else if h.standardTransfer != nil {
		if err := h.standardTransfer.current(ctx, true); err != nil {
			return err
		}
		if s.active != nil || s.predecessor != nil {
			return errors.New("service transfer cannot replace a Node predecessor")
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
		selected = desktopExternalPathProfileID(h.launch)
	}
	profile, exists := a.profileByIDLocked(desktopExternalPathProfileID(h.launch))
	if h.external != nil {
		if err := h.externalSourcesLocked(a); err != nil {
			return err
		}
	}
	registered, duplicate := desktopNodeOwners.Load(a)
	if capture.smartPredecessor != nil {
		if !duplicate || capture.smartPredecessor.wrapper == nil || registered != capture.smartPredecessor.wrapper || capture.smartPredecessor.wrapper.command != capture.command {
			return errors.New("SMART native preflight lost its captured predecessor wrapper")
		}
		if err := capture.smartPredecessor.currentLocked(capture.state.Phase); err != nil {
			return err
		}
	}
	if duplicate && capture.smartPredecessor == nil || a.localController != capture.controller || a.checkCapturedConnectionOperationLocked(capture.operation) != nil ||
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
	var outcome *modeAttemptTransition
	if len(transition) == 1 {
		outcome = transition[0]
	}
	if outcome != nil && outcome.legacy != nil && outcome.legacy.wrapper != nil {
		capture.smartPredecessor = outcome.legacy
	}
	profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled = options[0], options[1], options[2]
	ctx, cancel := context.WithTimeout(operation, 7*time.Minute)
	defer cancel()
	host, err := prepareDesktopLinuxNodeHost(operation, a, profile, mode.ID, 0)
	capture.host = host
	stopped, cleaned := false, false
	if host != nil {
		defer func() {
			if failure == nil {
				return
			}
			cleanup, finish := context.WithTimeout(context.Background(), 20*time.Second)
			defer finish()
			cleanupErr := errors.Join(capture.cleanup(cleanup, stopped, holdOnFailure), a.speedLabCheckLaunchedRuntime())
			cleaned = cleanupErr == nil
			failure = errors.Join(failure, cleanupErr)
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
	if _, err = captureLinuxStandardServiceNodeTransfer(ctx, host); err != nil {
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
	if capture.smartPredecessor != nil {
		plan := &speedLabRestorePlan{profile: cloneRouterProfile(profile),
			request: speedLabRequest{Topology: "router", NodeID: profile.ID, Mode: capture.state.RuntimeMode, Base: capture.state.Base, Execution: "local"}}
		if err := plan.captureWrapper(ctx, capture.smartPredecessor.wrapper); err != nil {
			return true, err
		}
		outcome.wrapperPlan = plan
		outcome.restoreWrapper = func() error {
			if !stopped || !cleaned {
				return errors.New("SMART wrapper restoration requires its original Stop and completed candidate cleanup")
			}
			return capture.restoreWrapper(plan)
		}
		// The restore copy includes live MTU. Recheck both owners after reading
		// it and before entering the predecessor's ordinary checked Stop.
		if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
			return true, err
		}
		if err := capture.current(ctx); err != nil {
			return true, err
		}
	}
	if outcome != nil {
		outcome.StopBegun = true
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
	if !stopped && h.standardTransfer != nil {
		if err := h.standardTransfer.resolve(ctx); err != nil {
			return err
		}
	}
	if err := s.enter(ctx); err != nil {
		return err
	}
	active := s.active
	s.gate <- struct{}{}
	if active == h {
		// A transfer failure is not an explicit Disconnect. Once native source
		// removal committed, retain the destination guard for this original
		// retry; before commit, settlement retains the original service guard.
		// An Off wrapper needs an empty checkpoint for restoration. Only
		// retire this candidate's own Off target through its original session.
		release := !hold || capture.smartPredecessor != nil && h.selection.Policy == "off"
		return s.Retire(ctx, h, release && h.standardTransfer == nil)
	}
	if h.standardTransfer != nil {
		if err := h.standardTransfer.resolve(ctx); err != nil {
			return err
		}
	}
	if err := h.Close(ctx); err != nil {
		return err
	}
	if h.standardTransfer != nil {
		return nil
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

// A failed trial may restart only the captured wrapper, after its exact
// candidate has fully retired and both firewall families are proved absent.
func (capture *desktopLinuxNodeConnectPreflight) restoreWrapper(plan *speedLabRestorePlan) error {
	a, h, s := capture.app, capture.host, capture.session
	ctx, cancel := context.WithTimeout(capture.operation, 10*time.Second)
	defer cancel()
	if err := s.enter(ctx); err != nil {
		return err
	}
	err := s.currentLocked(ctx)
	if err == nil {
		err = s.unclaimedStopLocked(ctx)
	}
	s.gate <- struct{}{}
	if err != nil {
		return err
	}
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return err
	}
	network, err := physicalNetworkIdentityContext(ctx)
	if err != nil || network != h.network {
		return errors.Join(err, errors.New("SMART wrapper restoration lost its original physical network"))
	}
	a.mu.Lock()
	profile, exists := a.profileByIDLocked(plan.profile.ID)
	_, registered := lookupDesktopNativeLaunch(a)
	_, standard := linuxStandardServiceOwners.Load(a)
	current := !registered && !standard && a.cmd == nil && !a.state.Connected && a.state.Mode == "off" && a.state.RuntimeMode == "" &&
		h.parent.currentAppLocked(false) == nil &&
		a.checkCapturedConnectionOperationLocked(capture.operation) == nil && a.profiles.SelectedID == plan.profile.ID && exists &&
		desktopOwnedNodeProfileToken(profile) == h.revision && desktopOwnedNodeProtectionPolicy(profile) == "off" &&
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == h.options
	a.mu.Unlock()
	if !current {
		return errors.New("SMART wrapper restoration lost its original request, policy or connection slot")
	}
	err = a.restartCapturedDesktopNode(capture.operation, *plan, "smart:restore")
	if err != nil && a.sameConnectionOperation(capture.operation) && a.ownsConnectionRuntime(plan.native.command) {
		if raw, found := desktopNodeOwners.Load(a); found && raw == plan.native {
			err = errors.Join(err, a.stopModeWithIntent(true))
		}
	}
	return err
}

func (capture *desktopLinuxNodeConnectPreflight) publishFailure(failure error) {
	a, h := capture.app, capture.host
	a.mu.Lock()
	defer a.mu.Unlock()
	if failure != nil && a.sameConnectionOperationLocked(capture.operation) && h.parent.currentAppLocked(false) == nil &&
		(a.cmd == nil || a.cmd == h.launch.command && a.state.RouterID == desktopExternalPathProfileID(h.launch) && a.state.RuntimeMode == h.launch.mode) {
		a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", failure.Error()
	}
}

// Existing callers use this before Stop for legacy Router, external and
// multihop paths. An empty/released session may defer only through its actual
// original checkpoint/native absence proof; this never creates a session.
func (a *app) guardDesktopLinuxNodeLegacyTransition() error {
	return a.guardDesktopLinuxNodeLegacyTransitionContext(context.Background())
}

func (a *app) guardDesktopLinuxNodeLegacyTransitionContext(ctx context.Context) error {
	captured, err := a.captureDesktopNodeStopContext(ctx)
	if err != nil {
		return err
	}
	if captured != nil {
		return errors.New("the selected path cannot inherit the retained Linux protection; disconnect the current on-connect path first")
	}
	return ctx.Err()
}
