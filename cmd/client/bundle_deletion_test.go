package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStagedProfileDeletionMovesThenCleansWithinPrivateRoot(t *testing.T) {
	root := t.TempDir()
	profile := filepath.Join(root, "generated", "router-test")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "secret"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := stageGeneratedProfileDeletion(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatalf("profile remained visible after staged delete: %v", err)
	}
	if !stage.moved || stage.tombstone == "" {
		t.Fatalf("profile was not moved to private tombstone: %+v", stage)
	}
	if err := stage.commitCleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage.holder); !os.IsNotExist(err) {
		t.Fatalf("deletion tombstone holder remained after commit: %v", err)
	}
}

func TestStagedProfileDeletionRollbackRestoresProfile(t *testing.T) {
	root := t.TempDir()
	profile := filepath.Join(root, "generated", "router-test")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "secret"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := stageGeneratedProfileDeletion(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.rollback(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(profile, "secret")); err != nil || string(got) != "private" {
		t.Fatalf("rollback did not restore original profile: data=%q err=%v", string(got), err)
	}
}

func TestStagedProfileDeletionRejectsSymlinkedGeneratedRootAndTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges")
	}
	t.Run("generated-root", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(root, "generated")); err != nil {
			t.Fatal(err)
		}
		if _, err := stageGeneratedProfileDeletion(root, "router-test"); err == nil {
			t.Fatal("symlinked generated root was accepted for deletion")
		}
		if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
			t.Fatalf("outside target was touched: entries=%v err=%v", entries, err)
		}
	})
	t.Run("profile-target", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		generated := filepath.Join(root, "generated")
		if err := os.Mkdir(generated, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(generated, "router-test")); err != nil {
			t.Fatal(err)
		}
		if _, err := stageGeneratedProfileDeletion(root, "router-test"); err == nil {
			t.Fatal("symlinked profile target was accepted for deletion")
		}
		if got, err := os.ReadFile(filepath.Join(outside, "keep")); err != nil || string(got) != "keep" {
			t.Fatalf("outside symlink target was altered: data=%q err=%v", string(got), err)
		}
	})
}
