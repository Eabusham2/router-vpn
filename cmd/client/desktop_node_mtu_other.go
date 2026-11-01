//go:build !linux

package main

import (
	"context"
	"errors"
	"os/exec"
)

func prepareDesktopPlatformMTUStop(context.Context, *app, *exec.Cmd, context.Context, *mtuLiveOwner, bool, error) (bool, error) {
	return false, nil
}

func captureDesktopPlatformMTUSnapshot(*app, mtuRetestSnapshot) (mtuLiveSnapshot, bool, error) {
	return mtuLiveSnapshot{}, false, nil
}

func openDesktopPlatformMTUOwner(_ *app, _ mtuRetestSnapshot, live mtuLiveSnapshot, _ string, _ *exec.Cmd) (mtuKernelOwner, bool, error) {
	if live.nodeRecord != nil {
		return nil, true, errors.New("native MTU snapshot belongs to another platform")
	}
	return nil, false, nil
}
