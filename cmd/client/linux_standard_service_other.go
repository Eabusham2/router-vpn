//go:build !linux

package main

import "errors"

func linuxStandardServiceUpgradeUtility(arguments []string) (bool, error) {
	for _, argument := range arguments {
		if argument == "--linux-standard-owner-upgrade" {
			return true, errors.New("Linux standard service upgrade is unavailable on this platform")
		}
	}
	return false, nil
}

func linuxStandardServiceUtility(arguments []string) (bool, error) {
	for _, argument := range arguments {
		if argument == "--linux-standard-owner-service" {
			return true, errors.New("Linux standard protection service is unavailable on this platform")
		}
	}
	return false, nil
}
func linuxStandardServiceImageUpgradeUtility(arguments []string) (bool, error) { return false, nil }
