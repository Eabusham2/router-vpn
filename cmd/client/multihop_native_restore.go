package main

import (
	"errors"
	"os/exec"

	"router-vpn/internal/common"
)

// Keep the actual proved graph and its frozen credentials. Recompiling from
// current saved measurements would create another source identity and could
// accidentally rerun the user's saved Compare choice instead of restoring it.
func captureNativeMultihopRestore(a *app, command *exec.Cmd, graph activeMultihopGraph, control, entry, exit common.RouterProfile) (multihopSelection, error) {
	owner, err := capturedNativeMultihopRuntime(a, command, graph)
	if err != nil {
		return multihopSelection{}, err
	}
	selection := owner.selection
	if graph.Execution != "local" && graph.Execution != "server" ||
		mtuProfileSnapshotToken(control) != mtuProfileSnapshotToken(selection.Control) ||
		mtuProfileSnapshotToken(entry) != mtuProfileSnapshotToken(selection.Entry) ||
		mtuProfileSnapshotToken(exit) != mtuProfileSnapshotToken(selection.Exit) {
		return multihopSelection{}, errors.New("previous multihop profiles differ from the proved captured graph")
	}
	selection.restoreMTU, err = captureDesktopNodeRestoreMTU(owner.launch)
	if err != nil {
		return multihopSelection{}, err
	}
	current, err := capturedNativeMultihopRuntime(a, command, graph)
	if err != nil || current != owner {
		return multihopSelection{}, errors.New("multihop owner changed while capturing live MTU restoration")
	}
	selection.Control = common.CloneRouterProfile(selection.Control)
	selection.Entry = common.CloneRouterProfile(selection.Entry)
	selection.Exit = common.CloneRouterProfile(selection.Exit)
	return selection, nil
}
