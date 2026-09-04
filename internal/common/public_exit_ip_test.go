package common

import "testing"

func TestNormalizeExpectedPublicIP(t *testing.T) {
	accepted := map[string]string{
		"203.0.113.9": "203.0.113.9",
		"2001:db8::9": "2001:db8::9",
	}
	for input, want := range accepted {
		got, err := NormalizeExpectedPublicIP(input)
		if err != nil {
			t.Fatalf("NormalizeExpectedPublicIP(%q) unexpectedly failed: %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeExpectedPublicIP(%q) = %q, want %q", input, got, want)
		}
	}

	for _, input := range []string{
		"",
		"0.0.0.0",
		"10.0.0.1",
		"100.64.0.1",
		"127.0.0.1",
		"169.254.1.1",
		"224.0.0.1",
		"255.255.255.255",
		"::",
		"::1",
		"fc00::1",
		"fe80::1",
		"ff02::1",
	} {
		if got, err := NormalizeExpectedPublicIP(input); err == nil {
			t.Fatalf("NormalizeExpectedPublicIP(%q) unexpectedly accepted %q", input, got)
		}
	}
}
