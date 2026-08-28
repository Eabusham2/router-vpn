package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateStoreHardensAndPublishesPrivateRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateRegular(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old\n" {
		t.Fatalf("read=%q", string(got))
	}
	if mode := mustPrivateMode(t, path); mode != 0o600 {
		t.Fatalf("hardened mode=%#o", mode)
	}
	if err := atomicWritePrivate(path, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new\n" {
		t.Fatalf("published=%q", string(got))
	}
	if mode := mustPrivateMode(t, path); mode != 0o600 {
		t.Fatalf("published mode=%#o", mode)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".client.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files survived commit: %v", matches)
	}
}

func TestPrivateStoreRejectsSymlinkTargets(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.json")
	linkPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(realPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	if _, err := readPrivateRegular(linkPath, 1024); err == nil {
		t.Fatal("symlink private store was accepted for read")
	}
	if err := atomicWritePrivate(linkPath, []byte("replacement\n")); err == nil {
		t.Fatal("symlink private store was accepted for write")
	}
	got, err := os.ReadFile(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret\n" {
		t.Fatalf("symlink target changed: %q", string(got))
	}
}

func TestPrivateStoreRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	path := filepath.Join(linkedDir, "routers.json")
	if err := atomicWritePrivate(path, []byte("secret\n")); err == nil {
		t.Fatal("symlink parent was accepted for private store write")
	}
	if _, err := os.Stat(filepath.Join(realDir, "routers.json")); !os.IsNotExist(err) {
		t.Fatalf("symlink-parent write escaped into real directory: %v", err)
	}
}

func TestPrivateStoreRejectsNestedSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(realDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	path := filepath.Join(linkedDir, "nested", "state", "routers.json")
	if err := atomicWritePrivate(path, []byte("secret\n")); err == nil {
		t.Fatal("nested symlink ancestor was accepted for private store write")
	}
	if _, err := os.Stat(filepath.Join(realDir, "nested", "state")); !os.IsNotExist(err) {
		t.Fatalf("nested symlink-ancestor write created redirected state: %v", err)
	}
}

func TestPrivateStoreRejectsOversizedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routers.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateRegular(path, 4); err == nil {
		t.Fatal("oversized private store was accepted")
	}
}

func mustPrivateMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}


func TestPrivateStoreRejectsTargetReplacementBeforeAdoption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, []byte("owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "foreign-replacement")
	if err := os.WriteFile(replacement, []byte("foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := atomicWritePrivateTargetUnchanged(path, before); err == nil {
		t.Fatal("foreign regular-file replacement was accepted before private adoption")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "foreign\n" {
		t.Fatalf("foreign replacement was modified: %q", string(got))
	}
}

