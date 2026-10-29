//go:build !darwin

package main

import "errors"

func macOSInstallerUtility(arguments []string) (bool, error) {
	for _, argument := range arguments {
		if argument == "--install-macos-native" {
			return true, errors.New("the native macOS installer requires an actual macOS host")
		}
	}
	return false, nil
}
