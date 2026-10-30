package windowsapp

import "testing"

func TestEntryArgumentsDoNotAcceptControllerOverrides(t *testing.T) {
	for _, arguments := range [][]string{nil, {"--self-test"}} {
		selfTest, err := selfTestArgument(arguments)
		if err != nil || selfTest != (len(arguments) == 1) {
			t.Fatalf("valid application entry arguments failed: %v", err)
		}
	}
	for _, arguments := range [][]string{
		{"--self-test", "--self-test"}, {"--self-test=true"}, {"-self-test"},
		{"--config", "another.json"}, {"--controller-pipe", "another-owner"},
		{"--self-test", "--controller-parent-handle", "1"}, {""},
	} {
		if _, err := selfTestArgument(arguments); err == nil {
			t.Fatal("public application entry accepted an alternate controller or startup override", arguments)
		}
	}
}
