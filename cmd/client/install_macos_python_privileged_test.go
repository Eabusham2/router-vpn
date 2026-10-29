//go:build (linux || darwin) && routervpn_installer_privileged

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	for _, defect := range []string{"outside-installation", "dangling", "cycle", "foreign-owner", "bounded-untrusted-name"} {
		t.Run("rejected-link-diagnostic/"+defect, func(t *testing.T) {
			root, binary, library := fixture(t)
			link := filepath.Join(root, "rejected-link")
			target := library
			switch defect {
			case "outside-installation":
				target = filepath.Join(filepath.Dir(root), "foreign-module.py")
				if err := os.WriteFile(target, []byte("foreign installation"), 0600); err != nil {
					t.Fatal(err)
				}
			case "dangling":
				target = filepath.Join(root, "missing-module.py")
			case "cycle":
				target = link
			case "bounded-untrusted-name":
				link = filepath.Join(root, "untrusted\n\x1b-link")
				target = "\n\x1b" + strings.Repeat("untrusted-", 80) + "-target-end"
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if defect == "foreign-owner" {
				if err := os.Lchown(link, 65534, 0); err != nil {
					t.Fatal(err)
				}
			}
			err := validateMacPythonTree(root, binary)
			if err == nil {
				t.Fatal("untrusted link passed the actual interpreter trust gate", defect)
			}
			diagnostic := err.Error()
			if !strings.HasPrefix(diagnostic, "privileged Python contains a foreign or escaping link:") ||
				!strings.Contains(diagnostic, "path="+strconv.QuoteToASCII(link)) {
				t.Fatal("rejected link did not identify its actual captured path", diagnostic)
			}
			if strings.ContainsAny(diagnostic, "\n\r\x1b") || len(diagnostic) > 8192 {
				t.Fatal("untrusted link escaped the bounded single-line diagnostic", len(diagnostic))
			}
			if defect == "bounded-untrusted-name" {
				if !strings.Contains(diagnostic, "...[truncated]...") || !strings.Contains(diagnostic, "-target-end") || strings.Contains(diagnostic, target) {
					t.Fatal("long untrusted target was not bounded while retaining its identity", diagnostic)
				}
			} else if !strings.Contains(diagnostic, "link="+strconv.QuoteToASCII(target)) {
				t.Fatal("rejected link omitted its actual lexical target", diagnostic)
			}
			if defect == "outside-installation" || defect == "foreign-owner" {
				if !strings.Contains(diagnostic, "resolved="+strconv.QuoteToASCII(target)) {
					t.Fatal("rejected link omitted its resolved target", diagnostic)
				}
			} else if !strings.Contains(diagnostic, "resolution_error=") {
				t.Fatal("unresolvable link omitted its resolution failure", diagnostic)
			}
			uid := "0"
			if defect == "foreign-owner" {
				uid = "65534"
			}
			if !strings.Contains(diagnostic, "owner_uid="+uid) {
				t.Fatal("rejected link omitted its actual owner", diagnostic)
			}
		})
	}
}
