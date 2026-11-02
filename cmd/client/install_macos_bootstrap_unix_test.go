//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

var macInstallerTestModules = []string{
	"client/install-linux-native.py",
	"client/install-macos-generation.py",
	"client/install-macos-image.py",
	"client/install-macos-native.py",
	"modes/darwin_install_capability.py",
}

func macInstallerWrite(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatal(err)
	}
}

func macInstallerFixture(t *testing.T) (source, private string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("installer fixture lost its actual source location")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source = filepath.Join(base, "selected package ' with $(literal)")
	private = filepath.Join(base, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range macInstallerTestModules {
		value, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal("read actual installer module", name, err)
		}
		macInstallerWrite(t, filepath.Join(source, name), value)
	}
	for _, name := range []string{"client/foreign.py", "modes/foreign.py", "client.json", "routers.json", "generated/private-state.json"} {
		macInstallerWrite(t, filepath.Join(source, name), []byte("not an installer input\n"))
	}
	return source, private
}

const macInstallerImportProbe = `
import importlib.util
from pathlib import Path
import sys
entry, private = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('captured_native_installer', entry)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
expected = {
    'client/install-macos-native.py': installer,
    'client/install-linux-native.py': installer.FILES,
    'client/install-macos-generation.py': installer.GENERATION,
    'client/install-macos-image.py': installer.GENERATION.IMAGE,
    'modes/darwin_install_capability.py': installer.CAPABILITY,
}
for relative, module in expected.items():
    assert Path(module.__file__).resolve() == private / relative, relative
assert installer.ROOT == Path('/opt/router-vpn-client')
assert installer.LABEL == 'com.routervpn.client'
assert installer.CAPABILITY.ROOT == installer.ROOT
assert installer.CAPABILITY.LOCK == Path('/opt/router-vpn-client.install.lock')
assert callable(installer.CAPABILITY.run_reassert)
print('captured installer imports all five original package modules')
`

func macInstallerPython(t *testing.T, entry, private string, help bool) ([]byte, error) {
	t.Helper()
	// This import-only fixture uses the fixed system interpreter and the actual
	// shipping isolation flags. It never invokes installation, inventory,
	// launchd, PF, or the interpreter-trust authority being tested elsewhere.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	arguments := []string{"-BEsS", "-c", macInstallerImportProbe, entry, private}
	if help {
		arguments = []string{"-BEsS", entry, "--help"}
	}
	command := exec.CommandContext(ctx, "/usr/bin/python3", arguments...)
	command.Dir = private
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + private, "LC_ALL=C", "PYTHONPATH=" + filepath.Dir(private)}
	return command.CombinedOutput()
}

func macInstallerAssertSnapshot(t *testing.T, source, private string) {
	t.Helper()
	var files []string
	err := filepath.WalkDir(private, func(path string, entry fs.DirEntry, failure error) error {
		if failure != nil {
			return failure
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) {
			t.Fatal("captured installer lost its original private owner", path)
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0700 {
				t.Fatal("captured installer directory became accessible to another user", path)
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner.Nlink != 1 {
			t.Fatal("captured installer module became linked or nonprivate", path)
		}
		relative, err := filepath.Rel(private, path)
		if err != nil {
			return err
		}
		files = append(files, relative)
		original, err := os.ReadFile(filepath.Join(source, relative))
		if err != nil {
			return err
		}
		copied, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(original, copied) {
			t.Fatal("captured installer module changed its original bytes", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	if !slices.Equal(files, macInstallerTestModules) {
		t.Fatal("installer capture omitted a dependency or bundled foreign/private files", files)
	}
}

func TestMacOSInstallerBootstrapPackage(t *testing.T) {
	for _, mode := range []string{"actual-import", "actual-entrypoint"} {
		t.Run(mode, func(t *testing.T) {
			source, private := macInstallerFixture(t)
			entry, err := captureMacInstallerPackage(source, private)
			if err != nil {
				t.Fatal(err)
			}
			// Exercise Python before inspecting the output layout so the original
			// flat capture fails at its actual missing dependency import.
			output, err := macInstallerPython(t, entry, private, mode == "actual-entrypoint")
			if err != nil {
				t.Fatalf("actual captured installer bootstrap failed: %v\n%s", err, output)
			}
			marker := "captured installer imports all five original package modules"
			if mode == "actual-entrypoint" {
				marker = "--caller-uid"
			}
			if !bytes.Contains(output, []byte(marker)) {
				t.Fatalf("actual captured installer entry did not execute: %s", output)
			}
			if entry != filepath.Join(private, "client", "install-macos-native.py") {
				t.Fatal("bootstrap selected an entry outside the captured package", entry)
			}
			macInstallerAssertSnapshot(t, source, private)
			if err := os.RemoveAll(source); err != nil {
				t.Fatal(err)
			}
			if output, err := macInstallerPython(t, entry, private, false); err != nil {
				t.Fatalf("captured installer reloaded its removed original inputs: %v\n%s", err, output)
			}
		})
	}
}

func TestMacOSInstallerBootstrapRejectsUnsafeCapture(t *testing.T) {
	for _, defect := range []string{"missing-helper", "wrong-helper-location", "linked-helper", "directory-helper", "empty-helper", "oversized-helper", "existing-client", "existing-modes", "linked-client", "linked-modes", "linked-private", "public-private", "linked-source-root", "linked-source-client", "linked-source-modes"} {
		t.Run(defect, func(t *testing.T) {
			source, private := macInstallerFixture(t)
			helper := filepath.Join(source, "modes", "darwin_install_capability.py")
			switch defect {
			case "linked-source-root", "linked-source-client", "linked-source-modes":
				target := source
				if defect != "linked-source-root" {
					target = filepath.Join(source, strings.TrimPrefix(defect, "linked-source-"))
				}
				original := target + "-original"
				if err := os.Rename(target, original); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(original, target); err != nil {
					t.Fatal(err)
				}
			case "missing-helper", "wrong-helper-location", "linked-helper", "directory-helper":
				value, err := os.ReadFile(helper)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(helper); err != nil {
					t.Fatal(err)
				}
				wrong := filepath.Join(source, "client", "darwin_install_capability.py")
				if defect != "missing-helper" {
					macInstallerWrite(t, wrong, value)
				}
				if defect == "linked-helper" {
					if err := os.Symlink(wrong, helper); err != nil {
						t.Fatal(err)
					}
				}
				if defect == "directory-helper" {
					if err := os.Mkdir(helper, 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "empty-helper":
				macInstallerWrite(t, helper, nil)
			case "oversized-helper":
				macInstallerWrite(t, helper, bytes.Repeat([]byte{'x'}, (2<<20)+1))
			case "existing-client", "existing-modes":
				if err := os.Mkdir(filepath.Join(private, strings.TrimPrefix(defect, "existing-")), 0700); err != nil {
					t.Fatal(err)
				}
			case "linked-client", "linked-modes":
				name := strings.TrimPrefix(defect, "linked-")
				if err := os.Symlink(filepath.Join(source, name), filepath.Join(private, name)); err != nil {
					t.Fatal(err)
				}
			case "linked-private":
				link := private + "-alias"
				if err := os.Symlink(private, link); err != nil {
					t.Fatal(err)
				}
				private = link
			case "public-private":
				if err := os.Chmod(private, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if entry, err := captureMacInstallerPackage(source, private); err == nil || entry != "" {
				t.Fatal("unsafe installer capture acquired an executable entry", defect, entry, err)
			}
		})
	}
}

func TestMacOSInstallerBootstrapRejectsMissingOrWrongImport(t *testing.T) {
	for _, defect := range []string{"missing-with-ambient-helper", "wrong-captured-helper"} {
		t.Run(defect, func(t *testing.T) {
			source, private := macInstallerFixture(t)
			entry, err := captureMacInstallerPackage(source, private)
			if err != nil {
				t.Fatal(err)
			}
			helper := filepath.Join(private, "modes", "darwin_install_capability.py")
			witness := "FileNotFoundError"
			if defect == "missing-with-ambient-helper" {
				if err := os.Remove(helper); err != nil {
					t.Fatal(err)
				}
				// A complete helper elsewhere must not fill a missing captured
				// dependency through PYTHONPATH, a flat layout or a sibling file.
				value, err := os.ReadFile(filepath.Join(source, "modes", "darwin_install_capability.py"))
				if err != nil {
					t.Fatal(err)
				}
				for _, wrong := range []string{filepath.Join(private, "client", "darwin_install_capability.py"), filepath.Join(filepath.Dir(private), "modes", "darwin_install_capability.py"), filepath.Join(filepath.Dir(private), "darwin_install_capability.py")} {
					macInstallerWrite(t, wrong, value)
				}
			} else {
				value, err := os.ReadFile(filepath.Join(source, "client", "install-macos-image.py"))
				if err != nil {
					t.Fatal(err)
				}
				macInstallerWrite(t, helper, value)
				witness = "run_reassert"
			}
			output, err := macInstallerPython(t, entry, private, false)
			if err == nil || !bytes.Contains(output, []byte(witness)) {
				t.Fatalf("missing or wrong captured helper was not refused at actual import: %v\n%s", err, output)
			}
		})
	}
}

func TestMacOSInstallerBootstrapRetainsOriginalDirectories(t *testing.T) {
	for _, replaced := range []string{"root", "client", "modes"} {
		t.Run(replaced, func(t *testing.T) {
			source, private := macInstallerFixture(t)
			original := make(map[string][]byte)
			for _, name := range macInstallerTestModules {
				data, err := os.ReadFile(filepath.Join(source, name))
				if err != nil {
					t.Fatal(err)
				}
				original[name] = data
			}
			captured, err := openMacInstallerPackageSource(source)
			if err != nil {
				t.Fatal(err)
			}
			defer captured.close()
			path := source
			if replaced != "root" {
				path = filepath.Join(source, replaced)
			}
			if err := os.Rename(path, path+"-original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range macInstallerTestModules {
				if replaced == "root" || filepath.Dir(name) == replaced {
					macInstallerWrite(t, filepath.Join(source, name), []byte("foreign replacement module\n"))
				}
			}
			if entry, err := captured.capture(private); err == nil || entry != "" {
				t.Fatal("replaced installer directory acquired an executable entry", replaced, entry, err)
			}
			for name, expected := range original {
				actual, err := os.ReadFile(filepath.Join(private, name))
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("module read followed a replacement instead of its retained original directory", name, err)
				}
			}
		})
	}
}
