package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeBundleTokenRejectsTraversalSeparatorsAndDriveSyntax(t *testing.T) {
	valid := []string{"wg", "wg.conf", "sing-box.json", "cert.pem", "a_b-c.1"}
	for _, value := range valid {
		if !safeBundleToken(value) {
			t.Fatalf("valid bundle token rejected: %q", value)
		}
	}
	invalid := []string{"", ".", "..", "../wg", "a/b", `a\b`, "C:x", "C:\\x", "nul\x00x", strings.Repeat("a", maxBundleNameBytes+1)}
	for _, value := range invalid {
		if safeBundleToken(value) {
			t.Fatalf("unsafe bundle token accepted: %q", value)
		}
	}
}

func TestBundleStagingFailureLeavesNoGeneratedProfile(t *testing.T) {
	root := t.TempDir()
	stage, err := newStagedBundle(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	profiles := map[string]map[string]string{
		"wg": {
			"wg.conf":   base64.StdEncoding.EncodeToString([]byte("ok")),
			"../escape": base64.StdEncoding.EncodeToString([]byte("bad")),
		},
	}
	if err := stage.writeProfiles(profiles); err == nil {
		t.Fatal("unsafe bundle filename was accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "generated", "router-test")); !os.IsNotExist(err) {
		t.Fatalf("failed import left final generated profile behind: %v", err)
	}
	stage.cleanup()
	entries, err := os.ReadDir(filepath.Join(root, ".bundle-staging"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed import left staging directories: %v", entries)
	}
}

func TestBundleStagingCommitsAtomicallyWithPrivateModes(t *testing.T) {
	root := t.TempDir()
	stage, err := newStagedBundle(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	profiles := map[string]map[string]string{
		"wg":          {"wg.conf": base64.StdEncoding.EncodeToString([]byte("[Peer]\nPublicKey = abc\n"))},
		"shadowsocks": {"sing-box.json": base64.StdEncoding.EncodeToString([]byte(`{"outbounds":[]}`))},
	}
	if err := stage.writeProfiles(profiles); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "generated", "router-test")); !os.IsNotExist(err) {
		t.Fatalf("profile became visible before commit: %v", err)
	}
	if err := stage.commit(root, "router-test"); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(root, "generated", "router-test", "wg", "wg.conf")
	st, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("staged private profile permissions too broad: %o", st.Mode().Perm())
	}
	stage.cleanup()
	entries, err := os.ReadDir(filepath.Join(root, ".bundle-staging"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("successful import left staging directories: %v", entries)
	}
}

func TestBundleStagingBoundsIndividualFileAndTotalCount(t *testing.T) {
	root := t.TempDir()
	stage, err := newStagedBundle(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	oversizedEncoded := strings.Repeat("A", ((maxBundleFileBytes+2)/3)*4+12)
	if err := stage.writeProfiles(map[string]map[string]string{"wg": {"huge": oversizedEncoded}}); err == nil {
		t.Fatal("oversized staged file accepted")
	}
}
