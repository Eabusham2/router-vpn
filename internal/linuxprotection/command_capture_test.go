package linuxprotection

import (
	"strings"
	"testing"
)

func TestLinuxNodeCommandCaptureBindsSessionAndBothSources(t *testing.T) {
	input := [3]string{strings.Repeat("1", 32), strings.Repeat("2", 64), strings.Repeat("3", 64)}
	expected, err := NodeCommandCaptureSHA256(input[0], input[1], input[2])
	if err != nil || !lowerHex(expected, 64) {
		t.Fatal(err)
	}
	for index := range input {
		changed := input
		changed[index] = strings.Repeat("a", len(changed[index]))
		value, err := NodeCommandCaptureSHA256(changed[0], changed[1], changed[2])
		if err != nil || value == expected {
			t.Fatal("Linux command channel accepted another session, private source or graph", index, err)
		}
		for _, invalid := range []string{"", input[index] + "0", strings.Repeat("A", len(input[index])), strings.Repeat("x", len(input[index]))} {
			changed[index] = invalid
			if _, err := NodeCommandCaptureSHA256(changed[0], changed[1], changed[2]); err == nil {
				t.Fatal("ambiguous command identity became a bootstrap capture", index)
			}
		}
	}
	if swapped, err := NodeCommandCaptureSHA256(input[0], input[2], input[1]); err != nil || swapped == expected {
		t.Fatal("source and graph identity were interchangeable", err)
	}
}
