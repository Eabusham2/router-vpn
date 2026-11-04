//go:build !linux

package main

import (
	"context"
	"os/exec"
)

func prepareLegacyStandardExitOwner(_ *app, _ *exec.Cmd, _, _, _ string) (legacyStandardExitLaunch, error) {
	return nil, nil
}
func captureLegacyStandardExitStop(_ *app) (desktopRetainedStopCapture, error) { return nil, nil }

func legacyStandardExitFailureOwned(_ *app, _ legacyStandardExitLaunch, _ bool) bool { return false }

func retireLegacyStandardPreparations(_ *app, _ context.Context) error { return nil }
