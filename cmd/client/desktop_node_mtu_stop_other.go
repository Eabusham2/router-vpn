//go:build !linux && !darwin

package main

import (
	"context"
	"os/exec"
)

func prepareDesktopPlatformMTUStop(context.Context, *app, *exec.Cmd, context.Context, *mtuLiveOwner, bool, error) (bool, error) {
	return false, nil
}
