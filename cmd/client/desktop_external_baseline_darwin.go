//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type desktopMacOSBaselineOutput struct {
	bytes.Buffer
	overflow bool
}

type desktopMacOSBaselineRunner func(context.Context, *desktopMacOSSessionCapture, desktopMacOSExternalSelection,
	string, *desktopMacOSExternalReceipt, func()) (*desktopMacOSExternalReceipt, error)

func (b *desktopMacOSBaselineOutput) Write(raw []byte) (int, error) {
	n := len(raw)
	if b.Len()+n > 8192 {
		b.overflow = true
		return n, nil
	}
	return b.Buffer.Write(raw)
}

// Invoke only the installed helper under the same original controller locks.
// A failed or canceled mutation remains owned by the caller and durable native
// journal; neither empty output nor process exit means PF retirement.
func runDesktopMacOSExternalBaseline(ctx context.Context, parent *desktopMacOSSessionCapture, selection desktopMacOSExternalSelection,
	action string, expected *desktopMacOSExternalReceipt, started func()) (*desktopMacOSExternalReceipt, error) {
	if ctx == nil || !selection.valid() || action != "apply" && action != "current" && action != "retire" && action != "release" {
		return nil, errors.New("macOS external baseline has no captured action")
	}
	if err := parent.cleanupCurrent(ctx); err != nil {
		return nil, err
	}
	if action == "apply" || action == "current" {
		if err := parent.Current(ctx); err != nil {
			return nil, err
		}
	}
	input, err := json.Marshal(struct {
		Capture  desktopMacOSExternalSelection `json:"capture"`
		Expected *desktopMacOSExternalReceipt  `json:"expected"`
	}{selection, expected})
	if err != nil {
		return nil, err
	}
	// Once entered, join this bounded native journal action even if the HTTP
	// request is canceled. The original parent retains the host and locks;
	// caller cancellation must not kill a helper between reference acquisition
	// and its durable pre-commit record.
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, filepath.Join(macOSOwnedControllerRoot, "bin", "python3"), "-BEsS",
		filepath.Join(macOSOwnedControllerRoot, "modes", "kill-switch-platform.py"), "external-native", action)
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
		return nil, errors.Join(err, errors.New("macOS captured native baseline remains pending"))
	}
	if output.overflow {
		return nil, errors.New("macOS captured native baseline exceeded its bounded receipt")
	}
	phase := "active"
	if action == "release" {
		phase = "retired"
	}
	if action == "retire" {
		phase = "held"
	}
	value, err := decodeDesktopMacOSExternalReceipt(output.Bytes(), selection, phase)
	if err != nil {
		return nil, err
	}
	if expected != nil && (value.Token != expected.Token || action == "current" && value != *expected) {
		return nil, errors.New("macOS baseline replaced its original native reference")
	}
	if err := parent.cleanupCurrent(ctx); err != nil {
		return nil, err
	}
	return &value, nil
}
