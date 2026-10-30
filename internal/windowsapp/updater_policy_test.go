package windowsapp

import (
	"strings"
	"testing"
)

func TestWindowsUpdaterCapturedPackageProvenance(t *testing.T) {
	sha := strings.Repeat("e", 40)
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, portable := range []bool{false, true} {
			family := "windows-"
			if portable {
				family = "windows-portable-"
			}
			raw := []byte(`{"schema_version":1,"repository":"Eabusham2/router-vpn","source_sha":"` + sha + `","artifact_family":"` + family + architecture + `"}`)
			got, err := updateSourceSHA(raw, portable, architecture)
			if err != nil || got != sha {
				t.Fatal("exact updater package identity was rejected", err)
			}
			if _, err := updateSourceSHA(raw, !portable, architecture); err == nil {
				t.Fatal("updater adopted another package layout's provenance")
			}
			other := "amd64"
			if architecture == other {
				other = "arm64"
			}
			if _, err := updateSourceSHA(raw, portable, other); err == nil {
				t.Fatal("updater adopted another architecture's provenance")
			}
			if _, err := updateSourceSHA(raw, portable, "386"); err == nil {
				t.Fatal("updater accepted an unsupported source architecture")
			}
		}
	}
}

func TestWindowsUpdaterRejectsForeignCacheNames(t *testing.T) {
	for _, name := range []string{"app-update-state.json", ".router-vpn-update-state-123456", ".router-vpn-update-123456",
		"abcdef0123456789-RouterVPN-Windows-amd64.zip", "0123456789abcdef-RouterVPN-Portable-Windows-arm64.zip"} {
		if !updateCacheFilename(name) {
			t.Fatal("actual staged updater filename was rejected", name)
		}
	}
	for _, name := range []string{"", "foreign.json", "app-update-state.json:secret", ".router-vpn-update-", ".router-vpn-update-state-foreign",
		".router-vpn-update-" + strings.Repeat("9", 21), "abcdef0123456789-RouterVPN-Windows-amd64.zip:stream", "ABCDEF0123456789-RouterVPN-Windows-amd64.zip",
		"abcdef0123456789-foreign.zip", "abcdef0123456789-RouterVPN-Windows-amd64.zip.", "../app-update-state.json", `..\app-update-state.json`} {
		if updateCacheFilename(name) {
			t.Fatal("foreign updater cache content was accepted", name)
		}
	}
}
