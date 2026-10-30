package mobiletor

import "testing"

func TestDesktopPFABIRejectsUnprovedKernel(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		if err := desktopPFValidateABI("24.6.0", "24G830", architecture); err != nil {
			t.Fatal("the captured qualification target was rejected", err)
		}
	}
	for _, capture := range [][3]string{
		{"", "24G830", "amd64"}, {"24.6.0", "", "amd64"}, {"24.6.0", "24G830", ""},
		{"25.0.0", "24G830", "amd64"}, {"23.6.0", "24G830", "arm64"},
		{"24.6.0", "24G831", "amd64"}, {"24.6.0", "24G830\x00", "amd64"},
		{"24.6.0\n", "24G830", "arm64"}, {"24.6.0", "24G830", "386"},
	} {
		if err := desktopPFValidateABI(capture[0], capture[1], capture[2]); err == nil {
			t.Fatal("an unproved kernel/architecture reached the private PF ABI", capture)
		}
	}
}
