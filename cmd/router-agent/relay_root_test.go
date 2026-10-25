package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRelayRootCleanupRetainsOutsideSymlinkTargets(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "retained")
	if err := os.WriteFile(secret, []byte("foreign owner"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nested", "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "child", "owned"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "nested", "outside")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := removeRelayRootContents(root); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("owned nested state was not removed", err)
	}
	if raw, err := os.ReadFile(secret); err != nil || string(raw) != "foreign owner" {
		t.Fatal("cleanup traversed a foreign symlink", err)
	}
}

func TestRelayRootRenameRejectsTraversalBeforePublication(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"", ".", "..", "../foreign", "nested/file", `nested\file`, "/absolute", "a\x00b"} {
		if renameRelayRootFile(root, name, "query.json") == nil || renameRelayRootFile(root, "query.tmp", name) == nil {
			t.Fatalf("invalid mailbox component accepted: %q", name)
		}
	}
}
