//go:build !linux && !darwin

package main

import (
	"context"
	"os/exec"
)

func (a *app) readPlatformDeviceMTUView(context.Context, *deviceMTUCapture, *exec.Cmd, *desktopNodeLaunch) (desktopDeviceMTUView, error) {
	return desktopDeviceMTUView{}, errDeviceMTUReadback
}
