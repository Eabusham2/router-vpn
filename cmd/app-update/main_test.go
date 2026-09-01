package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlatformAssets(t *testing.T) {
	cases := []struct {
		os, arch string
		portable bool
		asset    string
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

func TestExactReleaseIdentityAcceptsAuthoritativePrerelease(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	rel := release{
		TagName:         releaseTagPrefix + sha,
		TargetCommitish: sha,
		Prerelease:      true,
	}
	got, ok := exactReleaseIdentity(rel)
	if !ok || got != sha {
		t.Fatalf("authoritative exact-SHA prerelease rejected: sha=%q ok=%t", got, ok)
	}
	rel.Draft = true
	if _, ok := exactReleaseIdentity(rel); ok {
		t.Fatal("draft release was accepted")
	}
	rel.Draft = false
	rel.TargetCommitish = "fedcba9876543210fedcba9876543210fedcba98"
	if _, ok := exactReleaseIdentity(rel); ok {
		t.Fatal("mismatched release target was accepted")
	}
}

func validReleaseManifestJSON() string {
	sha := strings.Repeat("a", 40)
	digest := strings.Repeat("b", 64)
	return `{"schema_version":1,"repository":"Eabusham2/router-vpn","source_sha":"` + sha + `","tag":"router-vpn-sha-` + sha + `","producer_workflow":"build-all.yml","assets":[{"name":"RouterVPN-linux-amd64.tar.gz","size":123,"sha256":"` + digest + `"}]}`
}
func TestDecodeReleaseManifestFailsClosed(t *testing.T) {
	raw := []byte(validReleaseManifestJSON())
	if _, err := decodeReleaseManifest(raw); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	for _, suffix := range []string{` {}`, ` true`, ` null`} {
		if _, err := decodeReleaseManifest(append(append([]byte(nil), raw...), suffix...)); err == nil {
			t.Fatalf("trailing release JSON %q was accepted", suffix)
		}
	}
	unknown := strings.Replace(validReleaseManifestJSON(), `"schema_version":1`, `"schema_version":1,"unexpected":true`, 1)
	if _, err := decodeReleaseManifest([]byte(unknown)); err == nil {
		t.Fatal("unknown release manifest field was accepted")
	}
}
func TestReadSourceManifestRequiresExactRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ROUTER-VPN-SOURCE.json")
	sha := strings.Repeat("c", 40)
	raw := []byte(`{"repository":"Eabusham2/router-vpn","source_sha":"` + sha + `"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readSourceManifest(path)
	if err != nil || got.SourceSHA != sha {
		t.Fatalf("canonical provenance failed: got=%+v err=%v", got, err)
	}
	if runtime.GOOS != "windows" {
		target := filepath.Join(dir, "target.json")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := readSourceManifest(path); err == nil {
			t.Fatal("symlink provenance was accepted")
		}
	}
}

func TestCompareProvesStrictUpgrade(t *testing.T) {
	current := strings.Repeat("a", 40)
	target := strings.Repeat("b", 40)
	comparison := compareResult{Status: "ahead", AheadBy: 5, BehindBy: 0}
	comparison.BaseCommit.SHA = current
	comparison.MergeBaseCommit.SHA = current
	if !compareProvesStrictUpgrade(current, target, comparison) {
		t.Fatal("strict descendant was rejected")
	}
	for name, mutate := range map[string]func(*compareResult){
		"diverged":         func(c *compareResult) { c.Status = "diverged" },
		"behind":           func(c *compareResult) { c.Status, c.AheadBy, c.BehindBy = "behind", 0, 3 },
		"wrong base":       func(c *compareResult) { c.BaseCommit.SHA = target },
		"wrong merge base": func(c *compareResult) { c.MergeBaseCommit.SHA = target },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := comparison
			mutate(&candidate)
			if compareProvesStrictUpgrade(current, target, candidate) {
				t.Fatal("unsafe update ancestry was accepted")
			}
		})
	}
	if compareProvesStrictUpgrade(current, current, comparison) {
		t.Fatal("same SHA was treated as an upgrade")
	}
}
