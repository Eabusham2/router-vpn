//go:build !linux

package main

import (
	"context"
	"errors"
)

func captureDesktopImportedPlatformContext(ctx context.Context, a *app, sel multihopSelection, modes []string) (multihopSelection, bool, error) {
	return sel, false, nil
}

func guardDesktopImportedPlatformTransition(context.Context, *app, *desktopNodeLaunch) error {
	return errors.New("imported platform transition has no retained native host on this platform")
}
