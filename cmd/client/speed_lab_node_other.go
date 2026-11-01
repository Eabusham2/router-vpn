//go:build !linux

package main

import (
	"context"
	"errors"
	"os/exec"
)

type desktopLinuxNodePath struct{}

func captureDesktopLinuxNodePath(context.Context, *app, *exec.Cmd) (*desktopLinuxNodePath, bool, error) {
	return nil, false, nil
}

func validateDesktopLinuxNodePath(_ context.Context, _ *app, path *desktopLinuxNodePath) error {
	if path != nil {
		return errors.New("Speed Lab Linux path has no matching native host")
	}
	return nil
}
