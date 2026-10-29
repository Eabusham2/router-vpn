//go:build !windows

package main

import "errors"

func windowsPhysicalProtectionUtility(args []string) (bool, error) {
	_, handled, err := parseWindowsProtectionUtility(args)
	if !handled || err != nil {
		return handled, err
	}
	return true, errors.New("owned Windows physical protection requires Windows")
}
