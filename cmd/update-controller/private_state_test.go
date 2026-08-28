package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdaterPrivateFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-controller.json")
	if err := atomicWriteUpdaterPrivate(path, []byte("{\"version\":1}\n")); err != nil {
		t.Fatal(err)
	}
	body, err := readUpdaterPrivate(path, 1024)
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
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".update-controller.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files survived commit: %v", matches)
	}
}

func TestUpdaterPrivateFileRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-controller.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpdaterPrivate(path, 1024); err == nil {
		t.Fatal("group/world-readable updater state was accepted")
	}
	if err := atomicWriteUpdaterPrivate(path, []byte("{}\n")); err == nil {
		t.Fatal("group/world-readable updater target was silently replaced")
	}
}

func TestUpdaterPrivateFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.json")
	linkPath := filepath.Join(dir, "update-controller.json")
	if err := os.WriteFile(realPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readUpdaterPrivate(linkPath, 1024); err == nil {
		t.Fatal("symlink updater file was accepted")
	}
	if err := atomicWriteUpdaterPrivate(linkPath, []byte("replacement\n")); err == nil {
		t.Fatal("symlink updater file was accepted for replacement")
	}
	got, err := os.ReadFile(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret\n" {
		t.Fatalf("symlink target changed: %q", string(got))
	}
}

func TestUpdaterPrivateFileRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(linkedDir, "update-controller.json")
	if err := atomicWriteUpdaterPrivate(path, []byte("{}\n")); err == nil {
		t.Fatal("symlink updater-state parent was accepted")
	}
	if _, err := os.Stat(filepath.Join(realDir, "update-controller.json")); !os.IsNotExist(err) {
		t.Fatalf("updater state escaped through symlink parent: %v", err)
	}
}

func TestUpdaterPrivateFileRejectsNestedSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(realDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(linkedDir, "nested", "state", "update-controller.json")
	if err := atomicWriteUpdaterPrivate(path, []byte("{}\n")); err == nil {
		t.Fatal("nested symlink ancestor was accepted for updater state")
	}
	if _, err := os.Stat(filepath.Join(realDir, "nested", "state")); !os.IsNotExist(err) {
		t.Fatalf("updater state created redirected nested state: %v", err)
	}
}

func TestUpdaterPrivateFileRejectsOversizedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-controller.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpdaterPrivate(path, 4); err == nil {
		t.Fatal("oversized updater state was accepted")
	}
}

func TestValidateUpdateStateRejectsUnknownStatusAndInvalidSHA(t *testing.T) {
	for _, state := range []updateState{
		{Version: 1, Status: "future-state"},
		{Version: 2, Status: "idle"},
		{Version: 1, Status: "applying", FromSHA: "short", TargetSHA: testNewSHA},
		{Version: 1, Status: "applying", FromSHA: testOldSHA, TargetSHA: "SHORT"},
	} {
		if err := validateUpdateState(state); err == nil {
			t.Fatalf("invalid recovery state accepted: %+v", state)
		}
	}
}

func TestValidateUpdateStateRejectsImpossibleRecoveryShapes(t *testing.T) {
	invalid := []updateState{
		{Version: 1, Status: "idle", TargetSHA: testNewSHA},
		{Version: 1, Status: "idle", FromSHA: testOldSHA},
		{Version: 1, Status: "applying"},
		{Version: 1, Status: "finalizing", TargetSHA: testNewSHA},
		{Version: 1, Status: "finalizing", FromSHA: testOldSHA},
		{Version: 1, Status: "rolling-back", TargetSHA: testNewSHA},
		{Version: 1, Status: "rolling-back", FromSHA: testOldSHA},
		{Version: 1, Status: "complete", TargetSHA: testNewSHA},
		{Version: 1, Status: "complete", FromSHA: testOldSHA},
		{Version: 1, Status: "failed"},
	}
	for _, state := range invalid {
		if err := validateUpdateState(state); err == nil {
			t.Fatalf("impossible recovery state accepted: %+v", state)
		}
	}

	valid := []updateState{
		{Version: 1, Status: "idle"},
		{Version: 1, Status: "applying", TargetSHA: testNewSHA},
		{Version: 1, Status: "applying", FromSHA: testOldSHA, TargetSHA: testNewSHA},
		{Version: 1, Status: "finalizing", FromSHA: testOldSHA, TargetSHA: testNewSHA},
		{Version: 1, Status: "rolling-back", FromSHA: testOldSHA, TargetSHA: testNewSHA},
		{Version: 1, Status: "failed", TargetSHA: testNewSHA},
		{Version: 1, Status: "failed", FromSHA: testOldSHA, TargetSHA: testNewSHA},
		{Version: 1, Status: "complete", FromSHA: testOldSHA, TargetSHA: testNewSHA},
	}
	for _, state := range valid {
		if err := validateUpdateState(state); err != nil {
			t.Fatalf("valid recovery state rejected: %+v: %v", state, err)
		}
	}
}


func TestUpdaterPrivateFileRejectsTargetReplacementBeforeAdoption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-controller.json")
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
	if err := atomicWriteUpdaterPrivateTargetUnchanged(path, before); err == nil {
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

