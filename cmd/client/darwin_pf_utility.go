package main

import "errors"

const darwinOwnedPFArgument = "--darwin-owned-pf"

func darwinPFUtilityPhase(args []string) (handled, apply bool, err error) {
	if len(args) == 0 || args[0] != darwinOwnedPFArgument {
		return false, false, nil
	}
	if len(args) != 2 || (args[1] != "plan" && args[1] != "apply") {
		return true, false, errors.New("the fixed Darwin PF utility requires exactly plan or apply")
	}
	return true, args[1] == "apply", nil
}
