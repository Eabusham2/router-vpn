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
		args := []string{darwinOwnedPFInstallArgument, phase, "3", "0123456789abcdef0123456789abcdef", "123"}
		if handled, apply, err := darwinPFUtilityPhase(args); !handled || err != nil || apply != (phase == "apply") {
			t.Fatal("installer PF utility lost its exact phase or inherited capability shape", phase, handled, apply, err)
		}
		for field, rejected := range map[int][]string{
			2: {"", "0", "1", "2", "03", "+3", "3 ", "-3", "2147483648", "4294967299", "99999999999999999999"},
			3: {"", "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdeg", "0123456789abcdef0123456789ABCDEF"},
			4: {"", "0", "-1", "+1", "01", "2147483648"},
		} {
			for _, value := range rejected {
				invalid := append([]string(nil), args...)
				invalid[field] = value
				if handled, apply, err := darwinPFUtilityPhase(invalid); !handled || apply || err == nil {
					t.Fatal("installer PF utility accepted ambient or noncanonical authority", invalid, handled, apply, err)
				}
			}
		}
	}
	for _, args := range [][]string{{darwinOwnedPFArgument}, {darwinOwnedPFArgument, ""}, {darwinOwnedPFArgument, "clear"}, {darwinOwnedPFArgument, "apply", "/com.apple/foreign"}, {darwinOwnedPFArgument, "plan", "--root=/tmp/foreign"}} {
		if handled, apply, err := darwinPFUtilityPhase(args); !handled || err == nil || apply {
			t.Fatal("Darwin PF utility accepted another phase or ambient authority", args, handled, apply, err)
		}
	}
	for _, args := range [][]string{{darwinOwnedPFInstallArgument}, {darwinOwnedPFInstallArgument, "plan"},
		{darwinOwnedPFInstallArgument, "plan", "3", "0123456789abcdef0123456789abcdef", "123", "/tmp/other"},
		{darwinOwnedPFInstallArgument, "clear", "3", "0123456789abcdef0123456789abcdef", "123"}} {
		if handled, apply, err := darwinPFUtilityPhase(args); !handled || apply || err == nil {
			t.Fatal("installer PF utility accepted another operation or root", args, handled, apply, err)
		}
	}
}
