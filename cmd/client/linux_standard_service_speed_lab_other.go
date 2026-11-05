//go:build !linux

package main

import (
	"context"
	"os/exec"
)

func captureStandardServiceSpeedLab(*app) (speedLabPathIdentity, speedLabPath, bool, error) {
	return speedLabPathIdentity{}, speedLabPath{}, false, nil
}

func captureStandardServiceSpeedLabCallerContext(context.Context, *app) (speedLabPathIdentity, speedLabPath, bool, error) {
	return speedLabPathIdentity{}, speedLabPath{}, false, nil
}

func standardServiceSpeedLabCurrentOptions(context.Context, *app, state, *exec.Cmd) (map[string]string, error) {
	return nil, nil
}
