//go:build (linux || darwin) && routervpn_installer_privileged

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNativeInstallerPythonTrust(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the interpreter trust gate requires actual root")
	}
	if err := os.MkdirAll("/opt", 0755); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/opt", ".routervpn-python-trust-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	fixture := func(t *testing.T) (string, string, string) {
		directory, err := os.MkdirTemp(base, "case-")
		if err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(directory, "framework")
		if err := os.MkdirAll(filepath.Join(root, "lib"), 0755); err != nil {
			t.Fatal(err)
		}
		binary, library := filepath.Join(root, "python3"), filepath.Join(root, "lib", "module.py")
		if err := os.WriteFile(binary, []byte("trusted fixture executable"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(library, []byte("trusted library fixture"), 0644); err != nil {
			t.Fatal(err)
		}
		return root, binary, library
	}
	t.Run("complete-root-owned-tree", func(t *testing.T) {
		root, binary, library := fixture(t)
		if err := os.Symlink(library, filepath.Join(root, "module-link")); err != nil {
			t.Fatal(err)
		}
		if err := validateMacPythonTree(root, binary); err != nil {
			t.Fatal(err)
		}
	})
	for _, defect := range []string{"library-owner", "library-write", "ancestor-write", "escape-link", "pipe", "not-executable", "outside-root"} {
		t.Run(defect, func(t *testing.T) {
			root, binary, library := fixture(t)
			var err error
			switch defect {
			case "library-owner":
				err = os.Chown(library, 65534, 0)
			case "library-write":
				err = os.Chmod(library, 0666)
			case "ancestor-write":
				err = os.Chmod(filepath.Dir(root), 0777)
			case "escape-link":
				err = os.Symlink(binary, filepath.Join(base, "target"))
				if err == nil {
					err = os.Symlink(filepath.Join(base, "target"), filepath.Join(root, "escape"))
				}
				if err == nil {
					_ = os.Remove(filepath.Join(base, "target"))
					err = os.Symlink("/bin/sh", filepath.Join(base, "target"))
				}
			case "pipe":
				err = syscall.Mkfifo(filepath.Join(root, "pipe"), 0600)
			case "not-executable":
				err = os.Chmod(binary, 0600)
			case "outside-root":
				binary = "/bin/sh"
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := validateMacPythonTree(root, binary); err == nil {
				t.Fatal("untrusted privileged interpreter tree was accepted", defect)
			}
		})
	}
	for _, candidate := range []string{"python3", "/usr/local/bin/python3", "/opt/homebrew/bin/python3", "/bin/sh"} {
		if _, _, err := macOSPythonTrustRoot(candidate); err == nil {
			t.Fatal("ambient interpreter received privileged authority", candidate)
		}
	}
}
