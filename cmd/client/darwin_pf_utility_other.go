//go:build !darwin

package main

import "errors"

func macOSOwnedPFUtility(args []string) (bool, error) {
	handled, _, err := darwinPFUtilityPhase(args)
	if !handled || err != nil {
		return handled, err
	}
	return true, errors.New("the installed Darwin PF utility requires macOS")
}
