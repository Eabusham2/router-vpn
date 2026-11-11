//go:build darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type desktopMacOSNodeChainBaselineRunner func(context.Context, *desktopMacOSSessionCapture, desktopMacOSNodeChainSelection,
	string, *desktopMacOSNodeChainReceipt, func()) (*desktopMacOSNodeChainReceipt, error)

// The concrete ordered entry uses the same installed helper, inherited locks,
// durable journal and bounded join as ordinary external protection. It cannot
// grant a PF namespace, endpoint exception, or retirement from process exit.
func runDesktopMacOSNodeChainBaseline(ctx context.Context, parent *desktopMacOSSessionCapture, selection desktopMacOSNodeChainSelection,
	action string, expected *desktopMacOSNodeChainReceipt, started func()) (*desktopMacOSNodeChainReceipt, error) {
	if ctx == nil || parent == nil {
		return nil, errors.New("macOS ordered baseline has no original bounded controller")
	}
	input, err := encodeDesktopMacOSNodeChainBaselineRequest(selection, action, expected)
	if err != nil {
		return nil, err
	}
	if err := parent.cleanupCurrent(ctx); err != nil {
		return nil, err
	}
	if action == "apply" || action == "current" {
		if err := parent.Current(ctx); err != nil {
			return nil, err
		}
	}
	// An entered journal mutation must finish its durable receipt even when
	// caller cancellation revokes later activation. The original parent keeps
	// ownership of a failed/ambiguous action for exact cleanup and retry.
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, filepath.Join(macOSOwnedControllerRoot, "bin", "python3"), "-BEsS",
		filepath.Join(macOSOwnedControllerRoot, "modes", "kill-switch-platform.py"), "ordered-native", action)
	command.Dir, command.Env = macOSOwnedControllerRoot, macOSOwnedEnvironment()
	command.ExtraFiles = []*os.File{parent.parent.installLock, parent.parent.processLock}
	command.Stdin = bytes.NewReader(input)
	output := &desktopMacOSBaselineOutput{}
	command.Stdout, command.Stderr = output, io.Discard
	if err := command.Start(); err != nil {
		return nil, err
	}
	if started != nil {
		started()
	}
	if err := command.Wait(); err != nil {
		return nil, errors.Join(err, errors.New("macOS ordered native baseline remains pending"))
	}
	if output.overflow {
		return nil, errors.New("macOS ordered baseline exceeded its bounded receipt")
	}
	phase := "active"
	if action == "release" {
		phase = "retired"
	}
	if action == "retire" {
		phase = "held"
	}
	value, err := decodeDesktopMacOSNodeChainReceipt(output.Bytes(), selection, phase)
	if err != nil {
		return nil, err
	}
	if expected != nil && (value.Token != expected.Token || action == "current" && value != *expected) {
		return nil, errors.New("macOS ordered baseline replaced its original native reference")
	}
	if err := parent.cleanupCurrent(ctx); err != nil {
		return nil, err
	}
	return &value, nil
}
