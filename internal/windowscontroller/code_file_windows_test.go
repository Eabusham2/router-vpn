//go:build windows

package windowscontroller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsControllerFoundationPinnedPackageCode(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "client")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"app.ps1", "transport.psm1", "transport.cs", "transport.dll"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name)
			body := []byte("captured package code\n")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			code, err := PinFile(path)
			if err != nil {
				t.Fatal("actual package code did not retain its native object", err)
			}
			t.Cleanup(func() { _ = code.Close() })
			if !strings.HasPrefix(strings.ToLower(code.Path()), strings.ToLower(volumeGUIDPrefix)) {
				t.Fatal("package code used a caller's mutable DOS spelling")
			}
			if read, err := os.ReadFile(code.Path()); err != nil || string(read) != string(body) {
				t.Fatal("retained package code was not independently readable", err)
			}
			if image, err := PinImage(code.Path()); err == nil || image != nil {
				if image != nil {
					_ = image.Close()
				}
				t.Fatal("a non-executable code pin acquired a process launch capability")
			}
			if err := os.WriteFile(path, []byte("replacement code"), 0600); err == nil {
				t.Fatal("retained package code allowed another writer")
			}
			if err := os.Rename(directory, directory+"-replacement"); err == nil {
				_ = os.Rename(directory+"-replacement", directory)
				t.Fatal("retained package code allowed ancestor replacement")
			}
			if err := os.Remove(path); err == nil {
				t.Fatal("retained package code allowed deletion")
			}
			if err := code.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("owner released code"), 0600); err != nil {
				t.Fatal("retired package capture kept the file locked", err)
			}
		})
	}
}

func TestWindowsControllerFoundationPinnedPackageCodeRejectsAliases(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "app.ps1")
	if err := os.WriteFile(path, []byte("private code\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias.ps1")
	if err := os.Link(path, alias); err != nil {
		t.Fatal("actual package hardlink fixture could not be created", err)
	}
	for _, candidate := range []string{path, alias, filepath.Join(root, "..", "missing.ps1"), path + ":stream", `\\server\share\app.ps1`} {
		code, err := PinFile(candidate)
		if code != nil {
			_ = code.Close()
		}
		if err == nil || code != nil {
			t.Fatal("ambiguous or unowned package code acquired a retained file", candidate)
		}
	}
}
