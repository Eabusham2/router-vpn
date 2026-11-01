//go:build !linux

package main

import (
	"context"
	"errors"
	"os/exec"
)

type desktopNodeStopCapture struct{}

func (*app) captureDesktopNodeStop() (*desktopNodeStopCapture, error) { return nil, nil }

func (*desktopNodeStopCapture) Retire(context.Context, *exec.Cmd, bool) error {
	return errors.New("Linux Node Stop has no captured native owner on this platform")
}
