package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"

	"router-vpn/internal/mobilemultihop"
)

func desktopMultihopPlatformLaunch(launch *desktopNodeLaunch) bool {
	return launch != nil && (launch.importedPlatform != nil || launch.chain != nil && launch.chain.platform != nil)
}

func startDesktopMultihopPlatform(ctx context.Context, a *app, selection multihopSelection, launch *desktopNodeLaunch) error {
	if launch == nil || launch.chain == nil {
		return startDesktopImportedPlatform(ctx, a, selection, launch)
	}
	if launch.chain.platform == nil || selection.Native == nil || selection.Native.chain == nil || launch.chain.selection.Native != selection.Native {
		return errors.New("ordered platform startup lost its exact original source")
	}
	budget, err := desktopNodeReadyBudget(launch)
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if err := launch.chain.platform.start(startup); err != nil {
		return err
	}
	if launch.command == nil {
		return errors.New("ordered platform startup returned no original created command")
	}
	if err := launch.chain.platform.current(ctx); err != nil {
		return err
	}
	return registerActiveDNSRuntimeConfigKind(a, selection.Exit.ID, selection.ExitMode, filepath.Join(launch.directory, "sing-box.json"), true)
}

// A platform with retained graph cleanup publishes and captures its exact
// receipt atomically under the original host/application/session ownership.
// Other platforms preserve their existing graph publication behavior.
func publishDesktopMultihopPlatformGraph(ctx context.Context, a *app, launch *desktopNodeLaunch,
	selection multihopSelection, execution string) (activeMultihopGraph, error) {
	if launch != nil && launch.chain != nil && launch.chain.platform != nil {
		if owner, ok := any(launch.chain.platform).(interface {
			PublishGraph(context.Context, *app, *desktopNodeLaunch, multihopSelection, string) (activeMultihopGraph, error)
		}); ok {
			return owner.PublishGraph(ctx, a, launch, selection, execution)
		}
	}
	graph := setActiveMultihopGraph(a, selection)
	if execution != graph.Execution {
		graph.Execution = execution
		activeMultihopGraphs.Store(a, graph)
	}
	return graph, nil
}

func (a *app) publishDesktopCapturedMultihopStartLocked(operation context.Context, launch *desktopNodeLaunch, selection multihopSelection) error {
	if launch != nil && launch.chain != nil {
		return a.publishDesktopNodeChainStartLocked(operation, launch, selection)
	}
	return a.publishDesktopImportedMultihopStartLocked(operation, launch, selection)
}

func startDesktopCapturedMultihopOwned(ctx, operation context.Context, a *app, launch *desktopNodeLaunch) error {
	if launch != nil && launch.chain != nil {
		return startDesktopOwnedNodeChainLaunch(ctx, operation, a, launch)
	}
	return startDesktopOwnedImportedLaunch(ctx, operation, a, launch)
}

func activateDesktopMultihopPlatform(ctx context.Context, launch *desktopNodeLaunch) error {
	if launch != nil && launch.chain != nil && launch.chain.platform != nil {
		return launch.chain.platform.activate(ctx)
	}
	if launch == nil || launch.importedPlatform == nil {
		return errors.New("native platform activation lost its original launch")
	}
	return launch.importedPlatform.Activate(ctx)
}

func closeDesktopMultihopPlatform(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if launch != nil && launch.chain != nil {
		return closeDesktopNodeChainLaunch(ctx, a, launch)
	}
	if launch == nil || launch.importedPlatform == nil {
		return errors.New("native platform retirement lost its original launch")
	}
	return launch.importedPlatform.Close(ctx)
}

func proveDesktopNodeChainContext(ctx context.Context, a *app, selection multihopSelection, command *exec.Cmd) error {
	graph, found := getActiveMultihopGraph(a)
	owner, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
	if err != nil || !found || owner == nil || owner.launch.chain == nil || owner.selection.Native != selection.Native ||
		owner.launch.chain.selection.Native != selection.Native || graph.ChainNodes != len(selection.Nodes) || graph.Execution != "local" {
		return errors.Join(err, errors.New("ordered native proof lost its full original runtime"))
	}
	if owner.launch.chain.platform != nil {
		return owner.launch.chain.platform.prove(ctx)
	}
	// The typed child owns all prefix authentication and the selected final DNS
	// proof. Its fresh heartbeat is checked alongside the actual native reader;
	// the legacy pair's loopback proof listeners are not part of this graph.
	if _, err := a.readDesktopOwnedNodeReadyContext(ctx, owner.launch, false); err != nil {
		return err
	}
	return desktopNodeChainCurrent(ctx, a, owner.launch)
}

func validateDesktopNodeChainRestore(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if err := desktopNodeChainCurrent(ctx, a, launch); err != nil {
		return err
	}
	if err := validateDesktopNodeChainLaunch(ctx, launch); err != nil {
		return err
	}
	config, err := readDesktopRuntimeFileContext(ctx, launch, "sing-box.json", mobilemultihop.NodeChainInputLimit)
	if err != nil {
		return err
	}
	defer clear(config)
	source, err := readDesktopRuntimeFileContext(ctx, launch, "node-chain-source.json", mobilemultihop.NodeChainInputLimit)
	if err != nil {
		return err
	}
	defer clear(source)
	if string(config) != launch.chain.policy.Config() || string(source) != launch.chain.input {
		return errors.New("ordered restoration changed its original staged graph or full source")
	}
	return desktopNodeChainCurrent(ctx, a, launch)
}
