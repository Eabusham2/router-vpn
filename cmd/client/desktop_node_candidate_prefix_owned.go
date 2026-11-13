package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// A prefix test retains the full saved control and original Windows host, but
// its executable policy and readiness are exclusively the selected prefix.
func prepareDesktopOwnedCandidatePrefixLaunch(ctx context.Context, capture *desktopNodeChainHostCapture,
	selection multihopSelection, purpose *orderedCandidatePreparation) (*desktopNodeLaunch, error) {
	if capture == nil || capture.windows == nil || capture.platform != nil || capture.app == nil || capture.sources == nil ||
		selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.host != capture || capture.sources.selection.Native != selection.Native ||
		purpose == nil || purpose.app != capture.app || purpose.prefixPreparation == nil || purpose.selection.Native != selection.Native {
		return nil, errors.New("prefix Windows launch lost its original saved source, purpose or controller")
	}
	if err := capture.current(ctx); err != nil {
		return nil, err
	}
	a := capture.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	operation := a.connectionContext
	err := a.checkCapturedConnectionOperationLocked(operation)
	a.mu.Unlock()
	if err != nil || operation != purpose.operation {
		return nil, errors.Join(err, errors.New("prefix Windows launch changed its original initiating operation"))
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	launch, err := newDesktopNodeCandidatePrefixLaunchForPurpose(ctx, selection, session, "windows", purpose)
	if err != nil {
		return nil, err
	}
	launch.candidatePrefix.capture = capture
	launch.ownedNode = &desktopOwnedNodeRuntime{host: capture.windows, candidatePrefix: launch.candidatePrefix,
		source: []byte(launch.candidatePrefix.input), network: capture.network,
		profileToken: desktopOwnedNodeProfileToken(selection.Control), options: capture.sources.options, operation: operation}
	return launch, errors.Join(capture.current(ctx), validateDesktopOwnedCandidatePrefixSourceContext(ctx, launch))
}

func validateDesktopOwnedCandidatePrefixSourceContext(ctx context.Context, launch *desktopNodeLaunch) error {
	if launch == nil || launch.candidatePrefix == nil || launch.ownedNode == nil || launch.ownedNode.candidatePrefix != launch.candidatePrefix ||
		launch.ownedNode.policy != nil || launch.ownedNode.imported != nil || launch.ownedNode.chain != nil || launch.candidatePrefix.platform != nil {
		return errors.New("prefix Windows source lost its exact concrete owner")
	}
	if err := validateDesktopNodeCandidatePrefixLaunch(ctx, launch); err != nil {
		return err
	}
	owned, prefix := launch.ownedNode, launch.candidatePrefix
	capture := prefix.selection.Native.chain.host
	if capture == nil || prefix.capture != capture || capture.sources == nil || capture.windows == nil || capture.platform != nil || owned.host != capture.windows ||
		owned.host.capture.dataRoot != launch.root || prefix.policy.Metadata().TargetOS != "windows" ||
		prefix.policy.Metadata().PolicyProfileID != prefix.selection.Control.ID || launch.policyProfileID != prefix.selection.Control.ID ||
		owned.network != capture.network || owned.profileToken != desktopOwnedNodeProfileToken(prefix.selection.Control) ||
		owned.options != capture.sources.options || prefix.preparation == nil || prefix.preparation.app != capture.app ||
		prefix.preparation.launch != launch || prefix.preparation.operation != owned.operation {
		return errors.New("prefix Windows source changed its native capture or full saved control")
	}
	if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	retired, source := owned.retired, string(owned.source)
	launch.workspaceMu.Unlock()
	if retired || source != prefix.input {
		return errors.New("prefix Windows source changed its private projected input")
	}
	return ctx.Err()
}

func (owned *desktopOwnedNodeRuntime) candidatePrefixSourceCurrentLocked(a *app) bool {
	if owned == nil || owned.candidatePrefix == nil {
		return true
	}
	prefix := owned.candidatePrefix
	if prefix.selection.Native == nil || prefix.selection.Native.chain == nil || prefix.selection.Native.chain.host == nil || prefix.preparation == nil {
		return false
	}
	capture := prefix.selection.Native.chain.host
	return capture.app == a && capture.windows == owned.host && capture.sources != nil && capture.sources.currentLocked(a) == nil &&
		prefix.preparation.app == a && prefix.preparation.currentLocked() == nil
}

func (owned *desktopOwnedNodeRuntime) candidatePrefixProtectionSlot(ctx context.Context, a *app) (*desktopNodeProtectionSlot, error) {
	if owned == nil || owned.candidatePrefix == nil || owned.candidatePrefix.capture == nil ||
		owned.candidatePrefix.capture.app != a || owned.candidatePrefix.capture.windows != owned.host {
		return nil, errors.New("prefix Windows protection lost its captured controller")
	}
	return desktopCapturedNodeProtectionSlot(ctx, a, owned.host)
}

func startDesktopOwnedCandidatePrefixLaunch(ctx, operation context.Context, a *app, launch *desktopNodeLaunch) error {
	if launch == nil || launch.candidatePrefix == nil || launch.ownedNode == nil || launch.ownedNode.candidatePrefix != launch.candidatePrefix ||
		launch.candidatePrefix.capture == nil || launch.candidatePrefix.capture.app != a {
		return errors.New("prefix Windows startup lost its original native owner")
	}
	return startDesktopOwnedNodeLaunchFor(ctx, operation, a, launch,
		func(call context.Context, arguments, environment []string, directory string) (desktopNodeProcess, error) {
			owner := launch.ownedNode.host
			if owner == nil {
				return nil, errors.New("prefix Windows startup lost its native controller")
			}
			if err := owner.currentContext(call); err != nil {
				return nil, err
			}
			return owner.host.start(call, a, launch, arguments, environment, directory)
		})
}

func (a *app) publishDesktopCandidatePrefixStartLocked(operation context.Context, launch *desktopNodeLaunch, selection multihopSelection) error {
	if err := a.checkCapturedConnectionOperationLocked(operation); err != nil {
		return err
	}
	if launch == nil || launch.command == nil || launch.candidatePrefix == nil || launch.chain != nil || launch.ownedNode == nil ||
		launch.ownedNode.candidatePrefix != launch.candidatePrefix || a.cmd != nil || launch.candidatePrefix.selection.Native != selection.Native {
		return errors.New("prefix Windows publication changed its unused original launch")
	}
	purpose, err := orderedCandidateLaunchPurposeLocked(a, launch)
	if err != nil || purpose == nil || purpose.prefixPreparation == nil {
		return errors.Join(err, errors.New("prefix Windows publication has no closed preparation purpose"))
	}
	owned := launch.ownedNode
	if owned.operation != operation || owned.slot == nil || owned.slot != a.nodeProtection || owned.attempt == nil ||
		!owned.attempt.matchesOwned(owned) || owned.attempt.launch != launch || !owned.candidatePrefixSourceCurrentLocked(a) {
		return errors.New("prefix Windows publication lost its original protection and full source")
	}
	if existing, exists := desktopNodeOwners.Load(a); exists && existing != launch {
		return errors.New("prefix Windows publication cannot replace another native launch")
	}
	a.cmd = launch.command
	a.state.Connected, a.state.Phase, a.state.LastError = false, "starting", ""
	a.state.RouterID, a.state.Mode, a.state.RuntimeMode, a.state.LogicalMode, a.state.Base = selection.Control.ID, "multihop", launch.mode, "multihop", selection.Base
	a.state.DAITA, a.state.Jumbo, a.state.Socks = owned.options[0], owned.options[1], owned.options[2]
	desktopNodeOwners.Store(a, launch)
	return nil
}

func (a *app) readDesktopOwnedCandidatePrefixReadyContext(ctx context.Context, launch *desktopNodeLaunch, fresh bool) (mobilemultihop.DesktopNodeCandidatePreparationReadyRecord, error) {
	var empty mobilemultihop.DesktopNodeCandidatePreparationReadyRecord
	if launch == nil || launch.candidatePrefix == nil || launch.ownedNode == nil || launch.ownedNode.candidatePrefix != launch.candidatePrefix ||
		launch.ownedNode.attempt == nil || !launch.ownedNode.attempt.matchesOwned(launch.ownedNode) {
		return empty, errors.New("prefix Windows readiness lost its original protection owner")
	}
	if err := a.desktopOwnedNodeCurrentContext(ctx, launch, true); err != nil {
		return empty, err
	}
	if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
		return empty, err
	}
	started := launch.ownedNode.started
	launch.workspaceMu.Unlock()
	live, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil {
		return empty, err
	}
	record, err := readDesktopNodeCandidatePrefixReadyContext(ctx, launch, launch.ownedNode.attempt.digest, started, fresh, live)
	if err != nil {
		return empty, err
	}
	if err := a.desktopOwnedNodeCurrentContext(ctx, launch, true); err != nil {
		return empty, err
	}
	return record, ctx.Err()
}

func desktopOwnedCandidatePrefixCurrent(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if a == nil || launch == nil || launch.candidatePrefix == nil || launch.ownedNode == nil || launch.ownedNode.candidatePrefix != launch.candidatePrefix {
		return errors.New("prefix Windows observation changed its original native owner")
	}
	_, err := a.readDesktopOwnedCandidatePrefixReadyContext(ctx, launch, false)
	return err
}

// Retirement deliberately accepts a cancelled purpose, but never another
// launch or a borrowed policy family. The positive native join is checked by
// the caller before Home, protection or workspace cleanup can be published.
func orderedCandidateWindowsLaunchOwned(p *orderedCandidatePreparation, launch *desktopNodeLaunch) bool {
	if p == nil || p.app == nil || launch == nil || p.launch != launch || launch.ownedNode == nil {
		return false
	}
	owned := launch.ownedNode
	if launch.candidatePrefix != nil {
		return p.prefixPreparation != nil && launch.chain == nil && launch.candidatePrefix.preparation == p &&
			owned.candidatePrefix == launch.candidatePrefix && owned.chain == nil && owned.policy == nil && owned.imported == nil &&
			launch.candidatePrefix.platform == nil && launch.candidatePrefix.selection.Native == p.selection.Native
	}
	return p.prefixPreparation == nil && launch.chain != nil && launch.chain.preparation == p && owned.chain == launch.chain &&
		owned.candidatePrefix == nil && owned.policy == nil && owned.imported == nil && launch.chain.platform == nil
}
