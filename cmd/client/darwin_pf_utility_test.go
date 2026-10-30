package main

import "testing"

func TestDarwinPFUtilityExactDispatch(t *testing.T) {
	for _, args := range [][]string{nil, {"--ordinary"}, {"plan"}, {"--darwin-owned-pf-other", "apply"}} {
		if handled, _, err := darwinPFUtilityPhase(args); handled || err != nil {
			t.Fatal("Darwin PF utility adopted a different command", args, handled, err)
		}
	}
	for _, phase := range []string{"plan", "apply", "reference"} {
		if handled, apply, err := darwinPFUtilityPhase([]string{darwinOwnedPFArgument, phase}); !handled || err != nil || apply != (phase == "apply") {
			t.Fatal("Darwin PF utility lost its exact private phase boundary", phase, handled, apply, err)
		}
	}
	for _, args := range [][]string{{darwinOwnedPFArgument}, {darwinOwnedPFArgument, ""}, {darwinOwnedPFArgument, "clear"}, {darwinOwnedPFArgument, "apply", "/com.apple/foreign"}, {darwinOwnedPFArgument, "plan", "--root=/tmp/foreign"}} {
		if handled, apply, err := darwinPFUtilityPhase(args); !handled || err == nil || apply {
			t.Fatal("Darwin PF utility accepted another phase or ambient authority", args, handled, apply, err)
		}
	}
}
