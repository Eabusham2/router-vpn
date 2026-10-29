//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateRuntimePreservesSharedInstallationRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	if err := preflightPrivateConnectionRuntime(); err != nil {
		t.Fatal(err)
	}
	directory, err := newPrivateRuntimeDir(root, "native-node")
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(directory, "captured.json")
	if err := writePrivateRuntimeFile(secret, []byte("private fixture\n")); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(root)
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		t.Fatal("connection preflight made the shared native application inaccessible", err)
	}
	for _, path := range []string{filepath.Join(root, "run"), filepath.Join(root, "run", "native-node"), directory} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatal("shared application traversal exposed private runtime state", path, err)
		}
	}
	if info, err := os.Stat(secret); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("shared application traversal exposed a private runtime file", err)
	}
}

func TestPrivateRuntimeRejectsUnsafeRootWithoutRepair(t *testing.T) {
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := newPrivateRuntimeDir(root, "native-node"); err == nil {
				t.Fatal("untrusted mutation authority acquired a runtime directory")
			}
			if after, err := os.Lstat(root); err != nil || after.Mode().Perm() != mode {
				t.Fatal("rejected runtime root was silently repaired", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "run")); !os.IsNotExist(err) {
				t.Fatal("rejected runtime root was mutated", err)
			}
		})
	}
}

func TestPrivateRuntimeRootRejectsReplacedCapturedDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openPrivateRuntimeForRead(root, before)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(root, root+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateRuntimeRoot(file, before); err == nil {
		t.Fatal("replacement installation root acquired captured runtime authority")
	}
}

func TestPrivateRuntimeRootRejectsForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("an actual foreign owner fixture requires root")
	}
	root := t.TempDir()
	if err := os.Chown(root, 65534, 65534); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
			t.Skipf("the host cannot create the actual foreign-owner fixture: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := newPrivateRuntimeDir(root, "native-node"); err == nil {
		t.Fatal("another owner's directory acquired privileged runtime state")
	}
	if _, err := os.Lstat(filepath.Join(root, "run")); !os.IsNotExist(err) {
		t.Fatal("another owner's directory was mutated", err)
	}
}
