//go:build !linux

package main

import (
	"errors"
	"os/exec"
)

func captureDesktopPlatformMTUSnapshot(*app, mtuRetestSnapshot) (mtuLiveSnapshot, bool, error) {
	return mtuLiveSnapshot{}, false, nil
}

func openDesktopPlatformMTUOwner(_ *app, _ mtuRetestSnapshot, live mtuLiveSnapshot, _ string, _ *exec.Cmd) (mtuKernelOwner, bool, error) {
	if live.nodeRecord != nil {
		return nil, true, errors.New("native MTU snapshot belongs to another platform")
	}
	return nil, false, nil
}
