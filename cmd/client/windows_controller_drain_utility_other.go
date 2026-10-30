//go:build !windows

package main

import "errors"

func windowsControllerDrainUtility(args []string) (bool, error) {
	_, _, handled, err := parseWindowsControllerDrainUtility(args)
	if !handled || err != nil {
		return handled, err
	}
	return true, errors.New("captured Windows controller drain requires Windows")
}
