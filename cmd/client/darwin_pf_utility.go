package main

import "errors"

const darwinOwnedPFArgument = "--darwin-owned-pf"

func darwinPFUtilityPhase(args []string) (handled, apply bool, err error) {
	if len(args) == 0 || args[0] != darwinOwnedPFArgument {
		return false, false, nil
	}
	if len(args) != 2 || (args[1] != "plan" && args[1] != "apply" && args[1] != "reference") {
		return true, false, errors.New("the fixed Darwin PF utility requires exactly plan, apply or reference")
	}
	return true, args[1] == "apply", nil
}
