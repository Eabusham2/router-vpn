package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateRuntimeCreatesUniquePrivateSession(t *testing.T) {
	root := t.TempDir()
	first, err := newPrivateRuntimeDir(root, "native-standard-exit")
	if err != nil {
		t.Fatal(err)
	}
	second, err := newPrivateRuntimeDir(root, "native-standard-exit")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("private runtime allocator reused a session directory")
	}
	for _, path := range []string{filepath.Join(root, "run"), filepath.Join(root, "run", "native-standard-exit"), first, second} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("runtime path is not a real directory: %s", path)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("runtime directory %s mode=%#o", path, info.Mode().Perm())
		}
	}
	secret := filepath.Join(first, "secret.json")
	if err := writePrivateRuntimeFile(secret, []byte("private\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(secret); err != nil || string(got) != "private\n" {
		t.Fatalf("runtime secret=%q err=%v", got, err)
	}
	if runtime.GOOS != "windows" && mustPrivateMode(t, secret) != 0o600 {
		t.Fatalf("runtime secret mode=%#o", mustPrivateMode(t, secret))
	}
}

func TestPrivateRuntimeRejectsInvalidCategory(t *testing.T) {
	for _, category := range []string{"", "../escape", "a/b", "a\\b"} {
		if _, err := newPrivateRuntimeDir(t.TempDir(), category); err == nil {
			t.Fatalf("unsafe runtime category %q was accepted", category)
		}
	}
}

func TestPrivateRuntimeRejectsSymlinkedRunAndNestedAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges")
	}
	t.Run("run", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(root, "run")); err != nil {
			t.Fatal(err)
		}
		if _, err := newPrivateRuntimeDir(root, "native-standard-exit"); err == nil {
			t.Fatal("symlinked run root was accepted")
		}
		entries, err := os.ReadDir(outside)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("symlinked runtime target was touched: %v", entries)
		}
	})
	t.Run("ancestor", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "real")
		if err := os.MkdirAll(filepath.Join(real, "nested"), 0o700); err != nil {
			t.Fatal(err)
		}
		linked := filepath.Join(parent, "linked")
		if err := os.Symlink(real, linked); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(linked, "nested", "client")
		if _, err := newPrivateRuntimeDir(root, "native-multihop"); err == nil {
			t.Fatal("nested symlink ancestor was accepted for private runtime")
		}
		if _, err := os.Stat(filepath.Join(real, "nested", "client")); !os.IsNotExist(err) {
			t.Fatalf("runtime state escaped through nested ancestor: %v", err)
		}
	})
}

func TestPrivateRuntimeRejectsSymlinkedCategory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges")
	}
	root := t.TempDir()
	if err := ensurePrivateRuntimeDirectory(filepath.Join(root, "run")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	category := filepath.Join(root, "run", "native-multihop")
	if err := os.Symlink(outside, category); err != nil {
		t.Fatal(err)
	}
	if _, err := newPrivateRuntimeDir(root, "native-multihop"); err == nil {
		t.Fatal("symlinked runtime category was accepted")
	}
}
