//go:build !linux

package main

import (
	"errors"

	"router-vpn/internal/common"
)

func prepareLinuxOwnedController(arguments []string) (*linuxOwnedController, error) {
	for _, argument := range arguments {
		if argument == linuxOwnedControllerArgument {
			return nil, errors.New("the fixed native controller launcher requires Linux")
		}
	}
	return nil, nil
}

func validateLinuxOwnedStartup(owned *linuxOwnedController) error {
	if owned != nil {
		return errors.New("the fixed native controller launcher requires Linux")
	}
	return nil
}

func validateLinuxOwnedConfiguration(common.ClientConfig) error {
	return errors.New("the fixed native controller launcher requires Linux")
}
