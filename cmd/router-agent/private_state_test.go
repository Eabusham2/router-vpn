package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivilegedStateAtomicPrivateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-state.json")
	if err := atomicWritePrivilegedState(path, []byte("{\"version\":1}\n")); err != nil {
		t.Fatal(err)
	}
	body, err := readPrivilegedState(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "{\"version\":1}\n" {
		t.Fatalf("body=%q", string(body))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".admin-state.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files survived commit: %v", matches)
	}
}

func TestPrivilegedStateRejectsSymlinkAndBroadPermissions(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.json")
	linkPath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(realPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readPrivilegedState(linkPath, 1024); err == nil {
		t.Fatal("symlink privileged state was accepted")
	}
	if err := atomicWritePrivilegedState(linkPath, []byte("replacement\n")); err == nil {
		t.Fatal("symlink privileged state was accepted for replacement")
	}
	if got, err := os.ReadFile(realPath); err != nil || string(got) != "secret\n" {
		t.Fatalf("symlink target changed: %q err=%v", string(got), err)
	}

	broadPath := filepath.Join(dir, "broad.json")
	if err := os.WriteFile(broadPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivilegedState(broadPath, 1024); err == nil {
		t.Fatal("group/world-readable privileged state was accepted")
	}
	if err := atomicWritePrivilegedState(broadPath, []byte("{}\n")); err == nil {
		t.Fatal("group/world-readable privileged target was silently replaced")
	}
}

func TestPrivilegedStateRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(linkedDir, "admin-state.json")
	if err := atomicWritePrivilegedState(path, []byte("{}\n")); err == nil {
		t.Fatal("symlink privileged-state parent was accepted")
	}
	if _, err := os.Stat(filepath.Join(realDir, "admin-state.json")); !os.IsNotExist(err) {
		t.Fatalf("privileged state escaped through symlink parent: %v", err)
	}
}

func TestPrivilegedStateRejectsOversizedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivilegedState(path, 4); err == nil {
		t.Fatal("oversized privileged state was accepted")
	}
}
