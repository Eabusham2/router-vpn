package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
)

func prepareDesktopOwnedNodeChainLaunch(ctx context.Context, capture *desktopNodeChainHostCapture,
	selection multihopSelection) (*desktopNodeLaunch, error) {
	return prepareDesktopOwnedNodeChainLaunchForPurpose(ctx, capture, selection, nil)
}

func prepareDesktopOwnedNodeChainLaunchForPurpose(ctx context.Context, capture *desktopNodeChainHostCapture,
	selection multihopSelection, purpose *orderedCandidatePreparation) (*desktopNodeLaunch, error) {
	if capture == nil || capture.windows == nil || capture.platform != nil || capture.app == nil || capture.sources == nil ||
		selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.host != capture || capture.sources.selection.Native != selection.Native {
		return nil, errors.New("ordered Windows launch lost its original full source and controller")
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
	if err != nil {
		return nil, err
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	launch, err := newDesktopNodeChainLaunchForPurpose(ctx, selection, session, "windows", purpose)
	if err != nil {
		return nil, err
	}
	launch.chain.capture = capture
	launch.ownedNode = &desktopOwnedNodeRuntime{host: capture.windows, chain: launch.chain, source: []byte(launch.chain.input),
		network: capture.network, profileToken: desktopOwnedNodeProfileToken(selection.Control), options: capture.sources.options, operation: operation}
	return launch, errors.Join(capture.current(ctx), validateDesktopOwnedNodeChainSourceContext(ctx, launch))
}

func validateDesktopOwnedNodeChainSourceContext(ctx context.Context, launch *desktopNodeLaunch) error {
	if launch == nil || launch.chain == nil || launch.ownedNode == nil || launch.ownedNode.chain != launch.chain ||
		launch.ownedNode.policy != nil || launch.ownedNode.imported != nil || launch.chain.platform != nil {
		return errors.New("ordered Windows source lost its exact concrete owner")
	}
	metadata, err := readValidatedDesktopNodeChainLaunch(ctx, launch)
	if err != nil {
		return err
	}
	owned, chain := launch.ownedNode, launch.chain
	capture := chain.selection.Native.chain.host
	if capture == nil || chain.capture != capture || capture.sources == nil || capture.windows == nil || capture.platform != nil || owned.host != capture.windows ||
		owned.host.capture.dataRoot != launch.root || metadata.TargetOS != "windows" ||
		owned.network != capture.network || owned.profileToken != desktopOwnedNodeProfileToken(chain.selection.Control) ||
		owned.options != capture.sources.options {
		return errors.New("ordered Windows source changed its native capture")
	}
	if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	retired, source := owned.retired, string(owned.source)
	launch.workspaceMu.Unlock()
	if retired || source != chain.input {
		return errors.New("ordered Windows source changed its private projected input")
	}
	return ctx.Err()
}

func (owned *desktopOwnedNodeRuntime) chainSourceCurrentLocked(a *app) bool {
	if owned == nil || owned.chain == nil {
		return true
	}
	selection := owned.chain.selection
	if selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.host == nil {
		return false
	}
	capture := selection.Native.chain.host
	return capture.app == a && capture.windows == owned.host && capture.sources != nil && capture.sources.currentLocked(a) == nil
}

func (owned *desktopOwnedNodeRuntime) chainProtectionSlot(ctx context.Context, a *app) (*desktopNodeProtectionSlot, error) {
	if owned == nil || owned.chain == nil || owned.chain.selection.Native == nil || owned.chain.selection.Native.chain == nil ||
		owned.chain.selection.Native.chain.host == nil || owned.chain.selection.Native.chain.host.app != a ||
		owned.chain.selection.Native.chain.host.windows != owned.host {
		return nil, errors.New("ordered Windows protection lost its captured controller")
	}
	return desktopCapturedNodeProtectionSlot(ctx, a, owned.host)
}

func startDesktopOwnedNodeChainLaunch(ctx, operation context.Context, a *app, launch *desktopNodeLaunch) error {
	if launch == nil || launch.chain == nil || launch.ownedNode == nil || launch.ownedNode.chain != launch.chain ||
		launch.chain.selection.Native == nil || launch.chain.selection.Native.chain.host == nil || launch.chain.selection.Native.chain.host.app != a {
		return errors.New("ordered Windows startup lost its original native owner")
	}
	return startDesktopOwnedNodeLaunchFor(ctx, operation, a, launch,
		func(call context.Context, arguments, environment []string, directory string) (desktopNodeProcess, error) {
			owner := launch.ownedNode.host
			if owner == nil {
				return nil, errors.New("ordered Windows startup lost its native controller")
			}
			if err := owner.currentContext(call); err != nil {
				return nil, err
			}
			return owner.host.start(call, a, launch, arguments, environment, directory)
		})
}

func (a *app) publishDesktopNodeChainStartLocked(operation context.Context, launch *desktopNodeLaunch, selection multihopSelection) error {
	if err := a.checkCapturedConnectionOperationLocked(operation); err != nil {
		return err
	}
	if launch == nil || launch.command == nil || launch.chain == nil || launch.ownedNode == nil ||
		launch.ownedNode.chain != launch.chain || a.cmd != nil || launch.chain.selection.Native != selection.Native {
		return errors.New("ordered Windows publication changed its unused original launch")
	}
	if _, err := orderedCandidateLaunchPurposeLocked(a, launch); err != nil {
		return err
	}
	owned := launch.ownedNode
	if owned.operation != operation || owned.slot == nil || owned.slot != a.nodeProtection || owned.attempt == nil ||
		!owned.attempt.matchesOwned(owned) || owned.attempt.launch != launch || !owned.chainSourceCurrentLocked(a) {
		return errors.New("ordered Windows publication lost its original protection and full source")
	}
	if existing, exists := desktopNodeOwners.Load(a); exists && existing != launch {
		return errors.New("ordered Windows publication cannot replace another native launch")
	}
	a.cmd = launch.command
	a.state.Connected, a.state.Phase, a.state.LastError = false, "starting", ""
	a.state.RouterID, a.state.Mode, a.state.RuntimeMode, a.state.LogicalMode, a.state.Base = selection.Control.ID, "multihop", selection.ExitMode, "multihop", selection.Base
	a.state.DAITA, a.state.Jumbo, a.state.Socks = owned.options[0], owned.options[1], owned.options[2]
	desktopNodeOwners.Store(a, launch)
	return nil
}
