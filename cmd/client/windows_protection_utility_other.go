//go:build !windows

package main

import "errors"

func windowsPhysicalProtectionUtility(args []string) (bool, error) {
	if _, handled, err := parseWindowsPreparedProtectionUtility(args); handled {
		if err != nil {
			return true, err
		}
		return true, errors.New("owned Windows prepared protection requires Windows")
	}
	_, handled, err := parseWindowsProtectionUtility(args)
	if !handled || err != nil {
		return handled, err
	}
	return true, errors.New("owned Windows physical protection requires Windows")
}
