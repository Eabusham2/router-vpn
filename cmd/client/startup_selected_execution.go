package main

import (
	"context"
	"errors"
	"strings"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// The delayed selected transaction uses the same protected child/host owner
// as the interactive request, including its original transition and Stop.
func (a *app) startSelectedNodeChainStartupOwned(ctx context.Context, capture *startupPolicyCapture, supplied *desktopOrderedExecutionRuntime) error {
	if capture == nil || capture.nodeChain == nil {
		return errors.New("selected startup lost its original ordered capture")
	}
	mode := strings.ToLower(strings.TrimSpace(capture.profile.StartupMode))
	saved := capture.nodeChain.selectedLast
	if mode != "auto" && mode != "smart-auto" && mode != "last" || (mode == "last") != (saved != "") ||
		(saved != "") != (capture.nodeChain.last != nil) {
		return errors.New("selected startup lost its original policy or proved Last")
	}
	driver := desktopOrderedExecutionRuntime{capture: captureNativeMultihopForAppContext, prepare: prepareDesktopOrderedExecutionSession, prepareLast: prepareDesktopOrderedExecutionSessionWithLast}
	if supplied != nil {
		driver = *supplied
	}
	driver.startup = capture
	original := capture.nodeChain
	if err := driver.startupSelectedCurrent(ctx, a, original.selection, original.requested); err != nil {
		return err
	}
	s, err := a.connectDesktopOrderedExecutionWithRuntime(ctx, original.selection, original.requested, true, &driver)
	if err != nil {
		return err
	}
	a.startRouterNodeAutomaticMTU()
	if !desktopMultihopPlatformLaunch(s.launch) {
		a.monitorDesktopOwnedNodeRuntime(s.launch)
	}
	return nil
}

func (d *desktopOrderedExecutionRuntime) startupSelectedCurrent(ctx context.Context, a *app, selection multihopSelection, requested string) error {
	if d.startup == nil {
		return nil
	}
	c := d.startup.nodeChain
	if c == nil || requested != c.requested || requested != "server" && requested != "auto" {
		return errors.New("selected startup changed its original execution family")
	}
	return d.startup.nodeChainSelectionCurrent(ctx, a, selection)
}

func (d *desktopOrderedExecutionRuntime) checkPreparedStartup(ctx context.Context, a *app, s *desktopNodeChainExecutionSession, requested string) error {
	if d.startup == nil {
		return nil
	}
	if s == nil || s.execution == nil || s.execution.bound(s.launch) != nil || s.execution.preparation.Execution() != requested {
		return errors.New("selected startup prepared a different original family")
	}
	if err := d.startupSelectedCurrent(ctx, a, s.selection, requested); err != nil {
		return err
	}
	e := s.execution
	var last mobilemultihop.NodeChainExecutionLast
	var has bool
	var err error
	switch {
	case e.multiplePhysical != nil:
		last, has, err = e.preparation.MultipleImportedDesktopLast()
	case e.openvpnPhysical != nil:
		last, has, err = e.preparation.OpenVPNDesktopLast()
	case e.socksPhysical != nil:
		last, has, err = e.preparation.SOCKSDesktopLast()
	case e.connectPhysical != nil:
		last, has, err = e.preparation.CONNECTDesktopLast()
	default:
		last, has, err = e.preparation.DesktopLast()
	}
	saved := d.startup.nodeChain.selectedLast
	if err != nil || has != (saved != "") || has && last.JSON() != saved {
		return errors.Join(err, errors.New("selected startup failed to bind its original saved choice"))
	}
	return nil
}

func (d *desktopOrderedExecutionRuntime) checkStartupReady(ctx context.Context, a *app, s *desktopNodeChainExecutionSession, requested string) error {
	if err := d.startupSelectedCurrent(ctx, a, s.selection, requested); err != nil {
		return err
	}
	if d.startup == nil || d.startup.nodeChain.selectedLast == "" {
		return nil
	}
	last, err := mobilemultihop.ParseNodeChainExecutionLast(d.startup.nodeChain.selectedLast, s.execution.preparation)
	if err != nil {
		return err
	}
	result, err := s.Result(ctx)
	if err != nil || result.Winner == nil || string(result.Winner.Execution) != last.Execution() || result.Target != last.Target() {
		return errors.Join(err, errors.New("selected startup child changed its original frozen winner or target"))
	}
	return nil
}

func (a *app) selectedStartupSelectionAtReady(ctx context.Context, s *desktopNodeChainExecutionSession, startup *startupPolicyCapture) (startupSelection, error) {
	if s == nil || s.app != a || s.execution == nil || s.execution.draftPurpose != nil ||
		s.selection.Native == nil || s.selection.Native.chain == nil || s.execution.bound(s.launch) != nil {
		return startupSelection{}, errors.New("selected Last has no original prepared owner")
	}
	if err := s.Current(ctx); err != nil {
		return startupSelection{}, err
	}
	e := s.execution
	if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil {
		return startupSelection{}, err
	}
	if e.ready == nil || e.projection == nil {
		e.mu.Unlock()
		return startupSelection{}, errors.New("selected Last preceded native readiness")
	}
	ready := *e.ready
	e.mu.Unlock()
	last, err := e.provedLastAtReady(ctx, s.launch, ready)
	if err != nil {
		return startupSelection{}, err
	}
	var prior *startupSelection
	if startup != nil {
		prior = startup.nodeChain.last
	}
	return originalStartupNodeChainReceipt(s.selection, e.preparation.Execution(), last.JSON(), prior)
}
