package main

import "testing"

func TestPlatformAssets(t *testing.T) {
	cases := []struct {
		os, arch string
		portable bool
		asset string
	}{
		{"windows", "amd64", false, "RouterVPN-Windows-amd64.zip"},
		{"windows", "arm64", false, "RouterVPN-Windows-arm64.zip"},
		{"windows", "amd64", true, "RouterVPN-Portable-Windows-amd64.zip"},
		{"windows", "arm64", true, "RouterVPN-Portable-Windows-arm64.zip"},
		{"darwin", "amd64", false, "RouterVPN-darwin-amd64.tar.gz"},
		{"darwin", "arm64", false, "RouterVPN-darwin-arm64.tar.gz"},
		{"linux", "amd64", false, "RouterVPN-linux-amd64.tar.gz"},
		{"linux", "arm64", false, "RouterVPN-linux-arm64.tar.gz"},
	}
	for _, tc := range cases {
		asset, mode, err := platformAsset(tc.os, tc.arch, tc.portable)
		if err != nil {
			t.Fatalf("%s/%s portable=%t: %v", tc.os, tc.arch, tc.portable, err)
		}
		if asset != tc.asset || mode == "" {
			t.Fatalf("%s/%s portable=%t: asset=%q mode=%q", tc.os, tc.arch, tc.portable, asset, mode)
		}
	}
}

func TestUnsupportedMobileDoesNotFakeSelfUpdate(t *testing.T) {
	for _, osName := range []string{"android", "ios"} {
		if _, _, err := platformAsset(osName, "arm64", false); err == nil {
			t.Fatalf("%s incorrectly exposed desktop self-update", osName)
		}
	}
}

func TestValidSHA(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef01234567"
	if !validSHA(good) {
		t.Fatal("full SHA rejected")
	}
	for _, bad := range []string{"", good[:39], good[:39] + "G", good + "0"} {
		if validSHA(bad) {
			t.Fatalf("invalid SHA accepted: %q", bad)
		}
	}
}
