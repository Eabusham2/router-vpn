package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStandardExitRuntimeUsesPrivateSessionDirectory(t *testing.T) {
	root := t.TempDir()
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "password": "private-test-secret"}},
	}
	dir, alias, err := writeStandardExitRuntime(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if alias != "router-vpn" {
		t.Fatalf("alias=%q", alias)
	}
	base := filepath.Join(root, "run", "native-standard-exit")
	rel, err := filepath.Rel(base, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		t.Fatalf("runtime escaped private category: dir=%q rel=%q err=%v", dir, rel, err)
	}
	if info, err := os.Lstat(dir); err != nil {
		t.Fatal(err)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime dir mode/type=%v", info.Mode())
	}
	config := filepath.Join(dir, "sing-box.json")
	body, err := readPrivateRegular(config, maxPrivateStoreBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "private-test-secret") {
		t.Fatal("private runtime config did not contain expected test secret")
	}
	if info, err := os.Lstat(config); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime config mode=%#o", info.Mode().Perm())
	}
}

func TestStandardExitRuntimeRejectsPoisonedPrivateCategory(t *testing.T) {
	root := t.TempDir()
	run := filepath.Join(root, "run")
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	category := filepath.Join(run, "native-standard-exit")
	if err := os.Symlink(outside, category); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	if _, _, err := writeStandardExitRuntime(root, map[string]any{"outbounds": []any{}}); err == nil {
		t.Fatal("standard-exit runtime accepted a symlinked private category")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("poisoned category received runtime files: %v", entries)
	}
}

func TestOpenVPNPrivateFileUsesPrivateRuntimeWriter(t *testing.T) {
	root := t.TempDir()
	dir, err := newOpenVPNRuntimeDir(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "auth.txt")
	if err := writePrivateFile(path, "user\npassword\n"); err != nil {
		t.Fatal(err)
	}
	if body, err := readPrivateRegular(path, 1024); err != nil {
		t.Fatal(err)
	} else if string(body) != "user\npassword\n" {
		t.Fatalf("auth body=%q", body)
	}

	outside := t.TempDir()
	linkDir := filepath.Join(dir, "redirect")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	if err := writePrivateFile(filepath.Join(linkDir, "auth.txt"), "should-not-land\n"); err == nil {
		t.Fatal("OpenVPN private runtime writer followed a symlinked runtime subdirectory")
	}
	if entries, err := os.ReadDir(outside); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Fatalf("OpenVPN secret escaped through symlinked runtime subdirectory: %v", entries)
	}
}
