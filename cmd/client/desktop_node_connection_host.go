package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// The Windows host owns controller capture, verification and child creation.
// It cannot select a candidate, compile another profile, stage files, accept a
// proof or restore a connection. The private per-app field lets composed tests
// model only those native boundaries; it has no request or profile override.
type desktopNodeConnectionHost struct {
	capture func(*app) (desktopOwnedNodePreparation, error)
	verify  func(context.Context, string) (string, error)
	lookup  applexray.Lookup
	start   func(context.Context, *app, *desktopNodeLaunch, []string, []string, string) (desktopNodeProcess, error)
}

func (a *app) desktopNodeConnectionHost() *desktopNodeConnectionHost {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	host := a.nodeConnectionHost
	a.mu.Unlock()
	if host != nil {
		return host
	}
	if runtime.GOOS != "windows" {
		return nil
	}
	return &desktopNodeConnectionHost{
		capture: captureDesktopOwnedNodePreparation,
		verify:  verifyBundledNativeContext,
		lookup: func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		},
		start: startDesktopOwnedNodeJournalProcess,
	}
}

func (a *app) desktopNodeConnectionSelected(mode string) bool {
	if !mobilemultihop.NodeProfileMode(mode) {
		return false
	}
	// A missing/changed Windows receipt must fail native verification rather
	// than silently select a legacy command with different protection ownership.
	return a.desktopNodeConnectionHost() != nil || desktopNodeNativeSelected(mode)
}

func (a *app) checkDesktopNodeConnectionPackage() (bool, string) {
	root := desktopAmneziaPackageRoot()
	if host := a.desktopNodeConnectionHost(); host != nil {
		if host.capture == nil {
			return false, "The native Router controller capture is unavailable."
		}
		capture, err := host.capture(a)
		if err != nil {
			return false, err.Error()
		}
		root = capture.packageRoot
	}
	if _, err := os.Stat(filepath.Join(root, "runtime", "native", nativeBinaryName())); err != nil {
		return false, "The packaged native engine is missing."
	}
	return true, ""
}

func (a *app) prepareDesktopNodeConnection(profile common.RouterProfile, mode string) (*desktopNodeLaunch, error) {
	if a.desktopNodeConnectionHost() != nil && desktopOwnedNodeProtectionPolicy(profile) != "off" {
		// Unsupported protected graphs remain catalog requirements. Reject them
		// before Stop; never retry their failure through the ordinary helper.
		return prepareDesktopOwnedNodeLaunch(a, profile, mode)
	}
	return prepareDesktopNodeLaunch(a, profile, mode)
}

// A restore keeps this original host and controller lifetime with its original
// graph. It may acquire the latest joined protection predecessor, but cannot
// pick a replacement package/controller from a later application setting.
type desktopNodeConnectionOwner struct {
	host    desktopNodeConnectionHost
	capture desktopOwnedNodePreparation
}

func (owner *desktopNodeConnectionOwner) current() error {
	if owner == nil || owner.capture.lifetime == nil || owner.capture.current == nil || owner.host.start == nil ||
		!filepath.IsAbs(owner.capture.packageRoot) || !filepath.IsAbs(owner.capture.dataRoot) {
		return errors.New("native Router connection lost its captured host")
	}
	if err := owner.capture.lifetime.Err(); err != nil {
		return err
	}
	return owner.capture.current()
}

func desktopNodeConnectionPackageRoot(launch *desktopNodeLaunch) (string, error) {
	if launch == nil || launch.ownedNode == nil {
		return "", errors.New("native Router package has no captured launch")
	}
	if owner := launch.ownedNode.host; owner != nil {
		if err := owner.current(); err != nil {
			return "", err
		}
		if launch.root != owner.capture.dataRoot {
			return "", errors.New("native Router package lost its original private root")
		}
		return owner.capture.packageRoot, nil
	}
	return desktopOwnedNodePackageRoot()
}

// All callers hold operationMu for the connection transaction. a.mu makes the
// final request/command check and presentation update indivisible with request
// cancellation, controller shutdown and other asynchronous state publication.
// An owned child was already published before native creation; never Store it
// again after a callback could have installed a different owner.
func (a *app) publishStartedDesktopNode(operation context.Context, launch *desktopNodeLaunch, command *exec.Cmd, profileID, mode, phase, base string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if launch != nil && launch.ownedNode != nil {
		return a.checkDesktopNodeStartupOwnerLocked(operation, launch, command)
	}
	if !a.sameConnectionOperationLocked(operation) {
		return errConnectionOperationCancelled
	}
	if command == nil || a.cmd != nil {
		return errors.New("started connection cannot replace another command")
	}
	if launch != nil {
		if prior, exists := desktopNodeOwners.LoadOrStore(a, launch); exists && prior != launch {
			return errors.New("started connection cannot replace another native owner")
		}
	}
	a.cmd = command
	a.state.Connected, a.state.Phase, a.state.LastError = false, phase, ""
	a.state.Mode, a.state.RuntimeMode, a.state.RouterID = mode, mode, profileID
	a.state.LogicalMode, a.state.Base = "", base
	// A command that actually started just before its own cancellation still
	// needs its captured mode/native Stop, not merely an OS process kill. Keep
	// only this same operation's cleanup identity; never acknowledge Connected.
	if err := a.checkCapturedConnectionOperationLocked(operation); err != nil {
		a.state.Phase = "stopping"
		return err
	}
	return nil
}

func (a *app) checkDesktopNodeStartupOwnerLocked(operation context.Context, launch *desktopNodeLaunch, command *exec.Cmd) error {
	if err := a.checkCapturedConnectionOperationLocked(operation); err != nil {
		return err
	}
	if command == nil || a.cmd != command {
		return errors.New("native startup command was replaced before publication")
	}
	if launch != nil {
		if current, exists := desktopNodeOwners.Load(a); !exists || current != launch {
			return errors.New("native startup owner was replaced before publication")
		}
	}
	return nil
}

// This command has never entered app ownership. Join only its captured process
// handle if publication loses the initiating request; Stop on the app could
// affect a replacement. Native owned children use their retained Job owner.
func joinUnpublishedDesktopCommand(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	_ = command.Wait()
	return nil
}
