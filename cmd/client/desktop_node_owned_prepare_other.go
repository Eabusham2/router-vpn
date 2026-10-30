//go:build !windows

package main

import "errors"

func captureDesktopOwnedNodePreparation(a *app) (desktopOwnedNodePreparation, error) {
	return desktopOwnedNodePreparation{}, errors.New("captured Windows native Router preparation requires its Windows controller")
}
