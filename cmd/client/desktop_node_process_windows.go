//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"router-vpn/internal/windowscontroller"
)

func desktopOwnedNodePackageRoot() (string, error) {
	capture := windowsOwnedCapture.Load()
	if err := currentDesktopNodeController(capture); err != nil {
		return "", err
	}
	if err := windowscontroller.OwnProcessLifetime(); err != nil {
		return "", err
	}
	return capture.packageRoot, nil
}

func startDesktopOwnedNodeProcess(ctx context.Context, arguments, environment []string, directory string) (_ desktopNodeProcess, failure error) {
	return startDesktopOwnedNodeProcessWithJournal(ctx, arguments, environment, directory, nil)
}

func startDesktopOwnedNodeProcessWithJournal(ctx context.Context, arguments, environment []string, directory string, journal *desktopNodeWindowsJournalProcess) (_ desktopNodeProcess, failure error) {
	if ctx == nil {
		return nil, errors.New("the direct Node engine requires its captured operation")
	}
	arguments, err := validateDesktopNodeProcessArguments(arguments, directory)
	if err != nil {
		return nil, err
	}
	environment = append([]string(nil), environment...)
	capture := windowsOwnedCapture.Load()
	guard := func() error { return currentDesktopNodeController(capture) }
	if err := guard(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// This is an idempotent readback of the lifetime Job installed before the
	// controller authenticated. The short retained-package verification child
	// must remain contained by that same no-breakaway owner too.
	if err := windowscontroller.OwnProcessLifetime(); err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(capture.dataRoot, directory)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, errors.New("the direct Node workspace belongs to another controller root")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("the direct Node workspace is not its captured private directory"))
	}
	if err := validatePrivateRuntimePathPermissions(directory, info); err != nil {
		return nil, err
	}
	owner := newDesktopNodeProcessOwner(guard)
	var result desktopNodeProcess = owner
	if journal != nil {
		journal.desktopNodeProcessOwner = owner
		result = journal
	}
	defer func() {
		if failure != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			failure = errors.Join(failure, result.Close(cleanup))
		}
	}()
	launchContext, cancel := context.WithCancel(ctx)
	stopController := context.AfterFunc(capture.ctx, cancel)
	defer func() { stopController(); cancel() }()
	image, err := captureDesktopNodeRuntime(launchContext, capture, owner)
	if err != nil {
		return result, err
	}
	if err := guard(); err != nil {
		return result, err
	}
	if err := startDesktopCapturedNodeChildWithJournal(launchContext, owner, image, arguments, environment, directory, journal); err != nil {
		return result, err
	}
	return result, nil
}

// This is the actual same-token creation/observation composition. Package
// authority is established by startDesktopOwnedNodeProcess before it enters.
func startDesktopCapturedNodeChild(ctx context.Context, owner *desktopNodeProcessOwner, image *windowscontroller.Image,
	arguments, environment []string, directory string) error {
	return startDesktopCapturedNodeChildWithJournal(ctx, owner, image, arguments, environment, directory, nil)
}

func startDesktopCapturedNodeChildWithJournal(ctx context.Context, owner *desktopNodeProcessOwner, image *windowscontroller.Image,
	arguments, environment []string, directory string, journal *desktopNodeWindowsJournalProcess) error {
	if ctx == nil || owner == nil || owner.controller == nil || image == nil || owner.child != nil || owner.waiter != nil {
		return errors.New("the captured Node child has no unused native launch owner")
	}
	if err := owner.controller(); err != nil {
		return err
	}
	child, err := windowscontroller.LaunchGUIChild(ctx, image,
		func(parent uint64) ([]string, error) {
			if journal != nil {
				return journal.launchArguments(parent, arguments)
			}
			return append([]string(nil), arguments...), owner.controller()
		},
		nativeLibraryEnvironment(environment, filepath.Dir(image.Path())), directory)
	if child != nil {
		owner.child = child
		owner.started = child.PID() != 0
	}
	if journal != nil {
		journal.child, journal.image = child, image
	}
	if err != nil {
		return err
	}
	if child == nil || !owner.started {
		return errors.New("the direct Node launch returned no captured child")
	}
	waiter, err := child.RetainProcess()
	if err != nil {
		return err
	}
	owner.observe(waiter)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := owner.Alive(); err != nil {
		return err
	}
	return nil
}

func currentDesktopNodeController(capture *windowsOwnedController) error {
	if capture == nil || capture != windowsOwnedCapture.Load() || capture.ctx == nil || capture.parent == nil ||
		capture.selfImage == nil || capture.packageRoot == "" || capture.dataRoot == "" {
		return errors.New("the direct Node engine requires its authenticated Windows controller")
	}
	if err := capture.Alive(); err != nil {
		return err
	}
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil || !identity.Primary || !identity.Elevated || !identity.Administrator || identity != capture.elevated {
		return errors.Join(err, errors.New("the direct Node engine changed its captured controller token"))
	}
	if capture != windowsOwnedCapture.Load() {
		return errors.New("the direct Node engine lost its original controller")
	}
	return capture.Alive()
}

func captureDesktopNodeRuntime(ctx context.Context, capture *windowsOwnedController, owner *desktopNodeProcessOwner) (*windowscontroller.Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory := filepath.Join(capture.packageRoot, "runtime", "native")
	pin := func(name string) error {
		path := filepath.Join(directory, name)
		found := false
		for _, code := range capture.code {
			if code != nil && strings.EqualFold(code.Path(), path) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("the native Node payload lacks its captured package pin")
		}
		code, err := windowscontroller.PinFile(path)
		if err != nil {
			return err
		}
		owner.pins = append(owner.pins, code)
		if !strings.EqualFold(code.Path(), path) {
			return errors.New("the native Node payload moved outside its captured package")
		}
		return nil
	}
	if err := pin("NATIVE-RUNTIME.json"); err != nil {
		return nil, err
	}
	raw, err := bundledAmneziaRegular(filepath.Join(directory, "NATIVE-RUNTIME.json"), 32768)
	if err != nil {
		return nil, err
	}
	receipt, err := validateNativeReceipt(raw)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(receipt.Files))
	for name := range receipt.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := pin(name); err != nil {
			return nil, fmt.Errorf("capture native Node payload %s: %w", name, err)
		}
	}
	image, err := windowscontroller.PinImage(filepath.Join(directory, nativeBinaryName()))
	if err != nil {
		return nil, err
	}
	owner.pins = append(owner.pins, image)
	if !strings.EqualFold(image.Path(), filepath.Join(directory, nativeBinaryName())) {
		return nil, errors.New("the direct Node executable differs from its captured package")
	}
	if err := currentDesktopNodeController(capture); err != nil {
		return nil, err
	}
	// Preserve every existing receipt/hash/build-info and exact version check.
	// The short version command remains a child of OwnProcessLifetime's retained
	// controller Job and has its existing ten-second context. The long-running
	// Node itself is created below with an independently proved private child Job.
	verified, err := verifyBundledNativeContext(ctx, capture.packageRoot)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(verified, image.Path()) {
		return nil, errors.New("native runtime verification selected another captured executable")
	}
	if err := currentDesktopNodeController(capture); err != nil {
		return nil, err
	}
	return image, ctx.Err()
}
