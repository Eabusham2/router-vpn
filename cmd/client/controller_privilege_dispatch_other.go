//go:build !darwin && !windows

package main

import (
	"errors"
	"router-vpn/internal/common"
)

func prepareNativeOwnedController(arguments []string) (*ownedDesktopController, error) {
	for _, argument := range arguments {
		if argument == macOSOwnedControllerArgument || argument == macOSControllerSupervisorArgument {
			return nil, errors.New("the fixed macOS controller launcher requires macOS")
		}
	}
	return prepareLinuxOwnedController(arguments)
}
func validateNativeOwnedStartup(owned *ownedDesktopController) error {
	return validateLinuxOwnedStartup(owned)
}
func validateNativeOwnedConfiguration(config common.ClientConfig) error {
	return validateLinuxOwnedConfiguration(config)
}
func macOSControllerSupervisorUtility(arguments []string) (bool, error) {
	for _, argument := range arguments {
		if argument == macOSControllerSupervisorArgument {
			return true, errors.New("the fixed macOS controller supervisor requires macOS")
		}
	}
	return false, nil
}
