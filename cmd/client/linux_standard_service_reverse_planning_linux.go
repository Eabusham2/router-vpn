//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

// Resolve transport names and seal credentials while the original Node still
// carries traffic. Joining that Node leaves a deny-only creator, so bootstrap
// after Stop cannot be assumed to have a usable resolver.
func (t *linuxStandardNodeReverseTransfer) PrepareCommand() (*exec.Cmd, error) {
	ctx, cancel := context.WithDeadline(t.operation, t.deadline)
	defer cancel()
	bootstrap := standardExitSystemBootstrap()
	bootstrap.network = func() string {
		network, err := physicalNetworkIdentityContext(ctx)
		if err != nil {
			return ""
		}
		return network
	}
	return t.prepareCommand(ctx, bootstrap)
}

func (t *linuxStandardNodeReverseTransfer) prepareCommand(ctx context.Context, bootstrap standardExitBootstrap) (*exec.Cmd, error) {
	if t.command != nil || t.planning != nil || t.owner != nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("reverse planning lost original unused operation")
	}
	ctx, cancel := context.WithDeadline(ctx, t.deadline)
	defer cancel()
	a := t.session.parent.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	err := a.checkCapturedConnectionOperationLocked(t.operation)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var exit standardExit
	if err = json.Unmarshal([]byte(t.exitRaw), &exit); err != nil {
		return nil, err
	}
	command, err := nativeStandardExitCommandOwnedContext(ctx, a, t.profile, common.RouterProfile{}, exit, true, bootstrap, &t.planning)
	if err != nil {
		return nil, err
	}
	if err = t.capturePlannedCommand(command); err != nil {
		return nil, err
	}
	raw, err := readDesktopRuntimeFileContext(ctx, t.planning, "sing-box.json", 8<<20)
	if err != nil {
		return nil, err
	}
	t.plannedConfig = standardengine.SHA256(raw)
	if err = desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	err = a.checkCapturedConnectionOperationLocked(t.operation)
	a.mu.Unlock()
	return command, errors.Join(err, ctx.Err())
}

// The builder has already handed over its original directory handle before
// these fallible comparisons. Even a disappeared installed root cannot erase
// the private workspace cleanup capability.
func (t *linuxStandardNodeReverseTransfer) capturePlannedCommand(command *exec.Cmd) error {
	t.command = command
	t.plannedArgs, t.plannedEnv = append([]string(nil), command.Args...), append([]string(nil), command.Env...)
	t.plannedRoot = command.Dir
	var err error
	t.plannedRootInfo, err = os.Stat(command.Dir)
	return err
}

// Bind accepts only the bytes and original directory captured before Stop.
// The service owner then owns workspace retirement; this planning handle only
// retains the identity needed for this comparison and is closed separately.
func (t *linuxStandardNodeReverseTransfer) adoptPlanning(ctx context.Context, o *linuxStandardServiceLaunch) error {
	if t.command == nil || t.planning == nil || o.Command() != t.command || o.prepared.launch == nil ||
		o.prepared.protectionRoot != t.plannedRoot || t.command.Dir != t.plannedRoot ||
		!reflect.DeepEqual(t.command.Args, t.plannedArgs) || !reflect.DeepEqual(t.command.Env, t.plannedEnv) ||
		o.prepared.launch.directoryInfo == nil || t.planning.directoryInfo == nil || o.request.Directory != t.planning.directory ||
		o.request.ConfigSHA256 != t.plannedConfig || !os.SameFile(o.prepared.launch.directoryInfo, t.planning.directoryInfo) {
		return errors.New("reverse destination replaced pre-Stop sealed preparation")
	}
	root, err := os.Stat(t.plannedRoot)
	if err != nil || t.plannedRootInfo == nil || !os.SameFile(root, t.plannedRootInfo) {
		return errors.Join(err, errors.New("reverse destination replaced original installed root"))
	}
	raw, err := readDesktopRuntimeFileContext(ctx, t.planning, "sing-box.json", 8<<20)
	if err != nil || standardengine.SHA256(raw) != t.plannedConfig {
		return errors.Join(err, errors.New("reverse destination changed original private config"))
	}
	t.planningAdopted = true
	return nil
}

func (t *linuxStandardNodeReverseTransfer) DiscardPlanning() error {
	if t.planning == nil || t.planning.directoryRoot == nil {
		return nil
	}
	root := t.planning.directoryRoot
	// This terminal planning handle is independent of the service owner's
	// capture. Even if that owner already removed the directory after a Bind
	// rejection, close this duplicate without touching a replacement path.
	defer func() { _ = root.Close(); t.planning.directoryRoot = nil }()
	if !t.planningAdopted {
		return cleanupDesktopNodeLaunch(t.planning)
	}
	return nil
}
