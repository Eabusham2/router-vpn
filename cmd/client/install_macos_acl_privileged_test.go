//go:build darwin && routervpn_installer_privileged

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeInstallerDarwinACLTrust(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("the native ACL gate requires actual root")
	}
	base, err := os.MkdirTemp("/opt", ".routervpn-acl-trust-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	for _, test := range []struct {
		name, target, entry string
		private, accepted   bool
	}{
		{"public-read", "library", "everyone allow read,readattr,readextattr,readsecurity", false, true},
		{"deny-delete", "library", "everyone deny delete", false, true},
		{"file-write", "library", "everyone allow write", false, false},
		{"file-delete", "library", "everyone allow delete", false, false},
		{"security-write", "library", "everyone allow writesecurity", false, false},
		{"ancestor-add-file", "ancestor", "everyone allow add_file", false, false},
		{"private-read", "library", "everyone allow read", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent, err := os.MkdirTemp(base, "case-")
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(parent, "framework")
			if err := os.MkdirAll(root, 0755); err != nil {
				t.Fatal(err)
			}
			binary, library := filepath.Join(root, "python3"), filepath.Join(root, "library.py")
			if err := os.WriteFile(binary, []byte("fixture executable"), 0755); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0644)
			if test.private {
				mode = 0600
			}
			if err := os.WriteFile(library, []byte("fixture library"), mode); err != nil {
				t.Fatal(err)
			}
			if err := validateMacPythonTree(root, binary); err != nil {
				t.Fatal("native baseline", err)
			}
			target := library
			if test.target == "ancestor" {
				target = parent
			}
			before, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/bin/chmod", "+a", test.entry, target)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("actual owned ACL fixture: %v %s", err, output)
			}
			t.Cleanup(func() {
				if output, err := exec.Command("/bin/chmod", "-N", target).CombinedOutput(); err != nil {
					t.Errorf("remove owned fixture ACL: %v %s", err, output)
				}
			})
			after, err := os.Stat(target)
			if err != nil || before.Mode().Perm() != after.Mode().Perm() || after.Mode().Perm()&0022 != 0 {
				t.Fatal("fixture did not preserve apparently safe Unix mode bits", err)
			}
			err = validateMacPythonTree(root, binary)
			if (err == nil) != test.accepted {
				t.Fatalf("native ACL decision accepted=%v, want %v: %v", err == nil, test.accepted, err)
			}
		})
	}
	for _, test := range []struct {
		name, entry       string
		ancestor, private bool
		accepted          bool
	}{
		{"runtime-public-read", "everyone allow read,readattr,readextattr,readsecurity", false, false, true},
		{"runtime-extension-write", "everyone allow write", false, false, false},
		{"runtime-import-parent-write", "everyone allow add_file", true, false, false},
		{"runtime-private-read", "everyone allow read", false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := macPythonRuntimeFiles(t, base)
			target := fixture.extension
			if test.ancestor {
				target = filepath.Dir(fixture.dependency)
			}
			if test.private {
				if err := os.Chmod(target, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := validateMacPythonRuntime(fixture.entry, fixture.framework); err != nil {
				t.Fatal("native captured runtime baseline", err)
			}
			before, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command("/bin/chmod", "+a", test.entry, target).CombinedOutput(); err != nil {
				t.Fatalf("actual runtime ACL fixture: %v %s", err, output)
			}
			t.Cleanup(func() {
				if output, err := exec.Command("/bin/chmod", "-N", target).CombinedOutput(); err != nil {
					t.Errorf("remove exact runtime fixture ACL: %v %s", err, output)
				}
			})
			after, err := os.Stat(target)
			if err != nil || before.Mode().Perm() != after.Mode().Perm() || after.Mode().Perm()&0022 != 0 {
				t.Fatal("runtime ACL fixture changed its apparently safe Unix mode bits", err)
			}
			_, err = validateMacPythonRuntime(fixture.entry, fixture.framework)
			if (err == nil) != test.accepted {
				t.Fatalf("actual runtime ACL accepted=%v, want %v: %v", err == nil, test.accepted, err)
			}
		})
	}
}
