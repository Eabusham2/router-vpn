package main

import (
	"errors"
	"regexp"
	"strconv"
)

const darwinOwnedPFArgument = "--darwin-owned-pf"
const darwinOwnedPFInstallArgument = "--darwin-owned-pf-install"

var darwinPFInstallGeneration = regexp.MustCompile(`^[0-9a-f]{32}$`)

func darwinPFUtilityPhase(args []string) (handled, apply bool, err error) {
	if len(args) == 0 || (args[0] != darwinOwnedPFArgument && args[0] != darwinOwnedPFInstallArgument) {
		return false, false, nil
	}
	expected := 2
	if args[0] == darwinOwnedPFInstallArgument {
		expected = 5
	}
	if len(args) != expected || (args[1] != "plan" && args[1] != "apply" && args[1] != "reference") {
		return true, false, errors.New("the fixed Darwin PF utility requires exactly plan, apply or reference")
	}
	if expected == 5 {
		descriptor, descriptorErr := strconv.Atoi(args[2])
		issuer, issuerErr := strconv.Atoi(args[4])
		if descriptorErr != nil || descriptor < 3 || descriptor > 1<<31-1 || strconv.Itoa(descriptor) != args[2] ||
			issuerErr != nil || issuer <= 0 || issuer > 1<<31-1 || strconv.Itoa(issuer) != args[4] || !darwinPFInstallGeneration.MatchString(args[3]) {
			return true, false, errors.New("the installer PF utility requires one canonical inherited capability")
		}
	}
	return true, args[1] == "apply", nil
}
