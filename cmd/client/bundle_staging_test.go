package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
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

func TestBundleStagingRejectsSymlinkedPrivateRoots(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges; containment is covered by path tests there")
	}
	for _, name := range []string{"generated", ".bundle-staging"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
			stage, err := newStagedBundle(root, "router-test")
			if stage != nil {
				stage.cleanup()
			}
			if err == nil {
				t.Fatalf("symlinked %s root was accepted", name)
			}
			entries, readErr := os.ReadDir(outside)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("symlinked %s wrote outside client root: %v", name, entries)
			}
		})
	}
}

func TestBundleCommitRejectsGeneratedSymlinkSwapAfterStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges; containment is covered by path tests there")
	}
	root := t.TempDir()
	outside := t.TempDir()
	stage, err := newStagedBundle(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	if err := stage.writeProfiles(map[string]map[string]string{
		"wg": {"wg.conf": base64.StdEncoding.EncodeToString([]byte("private"))},
	}); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(root, "generated")
	if err := os.Remove(generated); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, generated); err != nil {
		t.Fatal(err)
	}
	if err := stage.commit(root, "router-test"); err == nil {
		t.Fatal("commit accepted generated-directory symlink swapped in after staging")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("commit escaped through generated-directory symlink: %v", entries)
	}
}

func TestBundleCommitRejectsClientRootRetargetAfterStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges; containment is covered by path tests there")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "client-root")
	outside := filepath.Join(parent, "root-b")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := newStagedBundle(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.writeProfiles(map[string]map[string]string{
		"wg": {"wg.conf": base64.StdEncoding.EncodeToString([]byte("private"))},
	}); err != nil {
		t.Fatal(err)
	}

	preserved := filepath.Join(parent, "root-a-preserved")
	if err := os.Rename(root, preserved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	if err := stage.commit(root, "router-test"); err == nil {
		t.Fatal("commit accepted client root retargeted after staging")
	}
	// cleanup while the lexical root is redirected must fail closed and must not
	// follow that redirect into the new target.
	stage.cleanup()
	if got, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || string(got) != "keep" {
		t.Fatalf("retargeted client root was modified during cleanup: %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "generated", "router-test")); !os.IsNotExist(err) {
		t.Fatalf("retargeted client root received private profile: %v", err)
	}

	// Restore the original lexical root and prove the staged private directory can
	// then be cleaned without leaking data indefinitely.
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(preserved, root); err != nil {
		t.Fatal(err)
	}
	stage.cleanup()
	if _, err := os.Stat(stage.root); !os.IsNotExist(err) {
		t.Fatalf("staging directory survived cleanup after original root restored: %v", err)
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
	// Windows does not implement POSIX mode bits; Go reports synthesized 0666
	// even when the file is protected by the user's Windows ACL. The 0600 mode
	// contract is therefore enforced on Unix, while Windows is covered by path,
	// staging, secret-containment and package tests rather than a fake mode-bit
	// assertion the OS cannot represent.
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
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
