package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStagedBundleImportCommitsInsidePrivateRoot(t *testing.T) {
	root := t.TempDir()
	stage, err := newStagedBundle(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	profiles := map[string]map[string]string{
		"wg": {"wg.conf": base64.StdEncoding.EncodeToString([]byte("private-profile\n"))},
	}
	if err := stage.writeProfiles(profiles); err != nil {
		t.Fatal(err)
	}
	if err := stage.commit(root, "router-test"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "generated", "router-test", "wg", "wg.conf")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "private-profile\n" {
		t.Fatalf("imported profile=%q", got)
	}
	if mode := mustPrivateMode(t, path); mode != 0o600 {
		t.Fatalf("imported mode=%#o", mode)
	}
}

func TestStagedBundleImportRejectsExistingDestination(t *testing.T) {
	root := t.TempDir()
	final := filepath.Join(root, "generated", "router-test")
	if err := os.MkdirAll(final, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(final, "keep")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := newStagedBundle(root, "router-test")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	if err := stage.writeProfiles(map[string]map[string]string{
		"wg": {"wg.conf": base64.StdEncoding.EncodeToString([]byte("new"))},
	}); err != nil {
		t.Fatal(err)
	}
	if err := stage.commit(root, "router-test"); err == nil {
		t.Fatal("bundle import replaced an existing generated profile")
	}
	if got, err := os.ReadFile(keep); err != nil || string(got) != "keep" {
		t.Fatalf("existing profile was altered: %q err=%v", got, err)
	}
}

func TestBundleOperationsRejectSymlinkedClientRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges")
	}
	outside := t.TempDir()
	rootParent := t.TempDir()
	linkedRoot := filepath.Join(rootParent, "client-root")
	if err := os.Symlink(outside, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := newStagedBundle(linkedRoot, "router-test"); err == nil {
		t.Fatal("bundle import accepted a symlinked client root")
	}
	if _, err := stageGeneratedProfileDeletion(linkedRoot, "router-test"); err == nil {
		t.Fatal("bundle deletion accepted a symlinked client root")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlinked client root was touched: %v", entries)
	}
}

func TestBundleOperationsRejectNestedSymlinkAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows CI may not grant symlink privileges")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(real, linked); err != nil {
		t.Fatal(err)
	}
	clientRoot := filepath.Join(linked, "nested", "client")
	if _, err := newStagedBundle(clientRoot, "router-test"); err == nil {
		t.Fatal("bundle import accepted a nested symlink ancestor")
	}
	if _, err := stageGeneratedProfileDeletion(clientRoot, "router-test"); err == nil {
		t.Fatal("bundle deletion accepted a nested symlink ancestor")
	}
	if _, err := os.Stat(filepath.Join(real, "nested", "client")); !os.IsNotExist(err) {
		t.Fatalf("nested symlink ancestor caused redirected state creation: %v", err)
	}
}
