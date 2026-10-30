//go:build !windows

package main

import "errors"

func desktopOwnedNodeProtectionBackend() (desktopNodeProtectionBackend, error) {
	return desktopNodeProtectionBackend{}, errors.New("this target has no admitted Windows Router protection backend")
}
