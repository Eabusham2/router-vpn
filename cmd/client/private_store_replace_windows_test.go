//go:build windows

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func requireWindowsPrivateStoreBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := readPrivateRegular(path, maxPrivateStoreBytes)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("actual Windows private publication readback = %q, %v", got, err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("private publication retained abandoned temporary files: %v, %v", matches, err)
	}
}

func TestWindowsPrivateStoreWriteThroughReplace(t *testing.T) {
	for _, kind := range []string{"unicode", "long-portable-path"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "Router VPN-資料")
			if kind == "long-portable-path" {
				for len(root) < 320 {
					root = filepath.Join(root, strings.Repeat("nested", 5))
				}
			}
			path := filepath.Join(root, "routers.json")
			first, next := []byte("{\"revision\":1}\n"), []byte("{\"revision\":2,\"off\":true}\n")
			if err := atomicWritePrivate(path, first); err != nil {
				t.Fatal("first actual Windows private publication", err)
			}
			requireWindowsPrivateStoreBytes(t, path, first)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := atomicWritePrivate(path, next); err != nil {
				t.Fatal("replacement actual Windows private publication", err)
			}
			requireWindowsPrivateStoreBytes(t, path, next)
			after, err := os.Stat(path)
			if err != nil || os.SameFile(before, after) {
				t.Fatal("private replacement modified the old file instead of promoting its new private file", err)
			}
		})
	}
}

func TestWindowsPrivateStoreWriteThroughFailureAndRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	before, after := []byte("saved-always\n"), []byte("saved-off\n")
	if err := atomicWritePrivate(path, before); err != nil {
		t.Fatal(err)
	}
	// Go's ordinary Windows read handle does not share DELETE. This is an
	// actual kernel publication failure, independent of a scripted API result.
	snapshot, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	err = atomicWritePrivate(path, after)
	if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) && !errors.Is(err, syscall.Errno(32)) {
		t.Fatalf("retained Windows snapshot did not reject private replacement: %v", err)
	}
	requireWindowsPrivateStoreBytes(t, path, before)
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if err := atomicWritePrivate(path, after); err != nil {
		t.Fatal("private replacement could not retry its actual failed publication", err)
	}
	requireWindowsPrivateStoreBytes(t, path, after)
}

func TestWindowsPrivateStoreWriteThroughFlags(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "prepared.tmp"), filepath.Join(root, "profiles.json")
	if err := os.WriteFile(source, []byte("prepared\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := replaceWindowsPrivateStoreFile(source, target, func(oldName, newName *uint16, flags uint32) error {
		calls++
		if flags != 0x9 {
			t.Fatal("private replacement omitted write-through or permitted deferred/cross-volume publication")
		}
		return moveWindowsPrivateStoreFile(oldName, newName, flags)
	})
	if err != nil || calls != 1 {
		t.Fatalf("actual write-through private move = %v, calls=%d", err, calls)
	}
	requireWindowsPrivateStoreBytes(t, target, []byte("prepared\n"))
	if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful private replacement left the prepared source", err)
	}
	// Preserve native failure identity for callers; never retry via weaker flags.
	calls = 0
	err = replaceWindowsPrivateStoreFile(source, target, func(_, _ *uint16, flags uint32) error {
		calls++
		return syscall.ERROR_ACCESS_DENIED
	})
	var linked *os.LinkError
	if calls != 1 || !errors.Is(err, syscall.ERROR_ACCESS_DENIED) || !errors.As(err, &linked) || linked.Old != source || linked.New != target {
		t.Fatalf("private replacement hid or retried its native failure: %v, calls=%d", err, calls)
	}
	requireWindowsPrivateStoreBytes(t, target, []byte("prepared\n"))
}

func TestWindowsPrivateStoreRejectsInvalidReplacement(t *testing.T) {
	root := t.TempDir()
	for _, pair := range [][2]string{
		{filepath.Join(root, "a", "prepared.tmp"), filepath.Join(root, "b", "profiles.json")},
		{filepath.Join(root, "prepared\x00.tmp"), filepath.Join(root, "profiles.json")},
		{filepath.Join(root, "prepared.tmp"), filepath.Join(root, "profiles\x00.json")},
	} {
		called := false
		err := replaceWindowsPrivateStoreFile(pair[0], pair[1], func(_, _ *uint16, _ uint32) error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Fatal("invalid private replacement reached native publication")
		}
	}
}
