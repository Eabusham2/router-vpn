//go:build (linux || darwin) && routervpn_installer_privileged

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type macPythonRuntimeFixture struct {
	distribution, framework, root, entry, core, stdlib, extension, dependency string
}

func macPythonWriteFixture(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func macPythonRuntimeFiles(t *testing.T, base string) macPythonRuntimeFixture {
	t.Helper()
	directory, err := os.MkdirTemp(base, "runtime-")
	if err != nil {
		t.Fatal(err)
	}
	f := macPythonRuntimeFixture{distribution: directory + "/CommandLineTools"}
	f.framework = f.distribution + "/Library/Frameworks/Python3.framework"
	f.root = f.framework + "/Versions/3.9"
	f.core, f.entry = f.root+"/Python3", f.distribution+"/usr/bin/python3"
	f.stdlib = f.root + "/lib/python3.9"
	f.extension = f.stdlib + "/lib-dynload/_capture.so"
	f.dependency = f.root + "/lib/libcaptured.dylib"
	macPythonWriteFixture(t, f.core, macPythonTestImage(0x01000007, 6), 0755)
	macPythonWriteFixture(t, f.entry, macPythonTestImage(0x01000007, 2,
		macPythonTestPathCommand(0x8000001c, "@executable_path/../../Library/Frameworks"),
		macPythonTestPathCommand(0xc, "@rpath/Python3.framework/Versions/3.9/Python3")), 0755)
	macPythonWriteFixture(t, f.stdlib+"/os.py", []byte("# actual protected standard library fixture\n"), 0644)
	macPythonWriteFixture(t, f.stdlib+"/encodings/__init__.py", []byte("# actual protected encoding startup\n"), 0644)
	macPythonWriteFixture(t, f.dependency, macPythonTestImage(0x01000007, 6), 0644)
	macPythonWriteFixture(t, f.extension, macPythonTestImage(0x01000007, 8,
		macPythonTestPathCommand(0x20, "@loader_path/../../libcaptured.dylib")), 0755)
	return f
}

func testNativeInstallerPythonRuntime(t *testing.T, base string) {
	t.Run("actual-loader-closure-excludes-unrelated-tools", func(t *testing.T) {
		f := macPythonRuntimeFiles(t, base)
		// Neither the filename nor LLDB is special-cased. This unrelated tool
		// has both an unresolvable target and a foreign-owned peer; neither is
		// an import path of the actual selected Python image.
		if err := os.Symlink("../../../UnrelatedDebugger/missing-tool.py", filepath.Dir(f.entry)+"/unrelated-tool"); err != nil {
			t.Fatal(err)
		}
		foreign := filepath.Dir(f.entry) + "/unrelated-foreign-tool"
		macPythonWriteFixture(t, foreign, []byte("not a Python dependency"), 0666)
		if err := os.Chown(foreign, 65534, 0); err != nil {
			t.Fatal(err)
		}
		root, err := validateMacPythonRuntime(f.entry, f.framework)
		if err != nil || root != f.root {
			t.Fatal("actual loader runtime was confused with unrelated developer tools", root, err)
		}
		if err := os.Chmod(f.dependency, 0666); err != nil {
			t.Fatal(err)
		}
		if _, err := validateMacPythonRuntime(f.entry, f.framework); err == nil {
			t.Fatal("the actual extension's lazy imported library was omitted from trust")
		}
	})
	for _, defect := range []string{"entry-owner", "core-owner", "stdlib-write", "extension-owner", "dependency-write", "dependency-owner", "dependency-parent-write", "missing-import", "runtime-dangling-link", "runtime-foreign-link", "runtime-escaping-link", "runtime-pipe", "library-archive-owner", "embedded-loader-environment", "untrusted-rpath", "lexical-link-before-parent", "venv-override", "pth-override", "missing-landmark", "wrong-core-architecture"} {
		t.Run(defect, func(t *testing.T) {
			f := macPythonRuntimeFiles(t, base)
			var err error
			switch defect {
			case "entry-owner":
				err = os.Chown(f.entry, 65534, 0)
			case "core-owner":
				err = os.Chown(f.core, 65534, 0)
			case "stdlib-write":
				err = os.Chmod(f.stdlib+"/os.py", 0666)
			case "extension-owner":
				err = os.Chown(f.extension, 65534, 0)
			case "dependency-write":
				err = os.Chmod(f.dependency, 0666)
			case "dependency-owner":
				err = os.Chown(f.dependency, 65534, 0)
			case "dependency-parent-write":
				err = os.Chmod(filepath.Dir(f.dependency), 0777)
			case "missing-import":
				err = os.Remove(f.dependency)
			case "runtime-dangling-link":
				err = os.Symlink(f.stdlib+"/missing.py", f.stdlib+"/linked.py")
			case "runtime-foreign-link":
				err = os.Symlink(f.stdlib+"/os.py", f.stdlib+"/linked.py")
				if err == nil {
					err = os.Lchown(f.stdlib+"/linked.py", 65534, 0)
				}
			case "runtime-escaping-link":
				outside := filepath.Dir(f.distribution) + "/outside.py"
				macPythonWriteFixture(t, outside, []byte("# root-owned outside the captured stdlib\n"), 0644)
				err = os.Symlink(outside, f.stdlib+"/linked.py")
			case "runtime-pipe":
				err = syscall.Mkfifo(f.stdlib+"/unsafe-pipe", 0600)
			case "library-archive-owner":
				archive := f.root + "/lib/python39.zip"
				macPythonWriteFixture(t, archive, []byte("archive is still an import source"), 0644)
				err = os.Chown(archive, 65534, 0)
			case "embedded-loader-environment":
				macPythonWriteFixture(t, f.core, macPythonTestImage(0x01000007, 6,
					macPythonTestPathCommand(0x27, "DYLD_LIBRARY_PATH=/untrusted")), 0755)
			case "untrusted-rpath":
				untrusted := f.distribution + "/untrusted-search"
				err = os.Mkdir(untrusted, 0777)
				if err == nil {
					err = os.Chown(untrusted, 65534, 0)
				}
				macPythonWriteFixture(t, f.entry, macPythonTestImage(0x01000007, 2,
					macPythonTestPathCommand(0x8000001c, untrusted), macPythonTestPathCommand(0xc, f.core)), 0755)
			case "lexical-link-before-parent":
				foreign := filepath.Dir(f.distribution) + "/foreign"
				err = os.Mkdir(foreign, 0777)
				if err == nil {
					err = os.Chown(foreign, 65534, 0)
				}
				if err == nil {
					err = os.Symlink(foreign, filepath.Dir(f.dependency)+"/alias")
				}
				macPythonWriteFixture(t, f.extension, macPythonTestImage(0x01000007, 8,
					macPythonTestPathCommand(0xc, "@loader_path/../../alias/../libcaptured.dylib")), 0755)
			case "venv-override":
				macPythonWriteFixture(t, filepath.Dir(f.entry)+"/pyvenv.cfg", []byte("home = /untrusted\n"), 0644)
			case "pth-override":
				macPythonWriteFixture(t, f.root+"/Python3._pth", []byte("/untrusted\n"), 0644)
			case "missing-landmark":
				err = os.Remove(f.stdlib + "/encodings/__init__.py")
			case "wrong-core-architecture":
				macPythonWriteFixture(t, f.core, macPythonTestImage(0x0100000c, 6), 0755)
			}
			if err != nil {
				t.Fatal("could not install actual negative fixture", err)
			}
			if _, err := validateMacPythonRuntime(f.entry, f.framework); err == nil {
				t.Fatal("untrusted actual Python runtime input received privileged authority", defect)
			}
		})
	}
	t.Run("every-universal-slice-binds-one-framework", func(t *testing.T) {
		f := macPythonRuntimeFiles(t, base)
		intel := macPythonTestImage(0x01000007, 2, macPythonTestPathCommand(0xc, f.core))
		arm := macPythonTestImage(0x0100000c, 2, macPythonTestPathCommand(0xc, f.core))
		macPythonWriteFixture(t, f.entry, macPythonTestUniversal(intel, arm), 0755)
		macPythonWriteFixture(t, f.core, macPythonTestUniversal(macPythonTestImage(0x01000007, 6), macPythonTestImage(0x0100000c, 6)), 0755)
		if _, err := validateMacPythonRuntime(f.entry, f.framework); err != nil {
			t.Fatal("the complete actual universal runtime was rejected", err)
		}
		foreignCore := strings.Replace(f.core, "/3.9/", "/3.10/", 1)
		macPythonWriteFixture(t, foreignCore, macPythonTestImage(0x0100000c, 6), 0755)
		arm = macPythonTestImage(0x0100000c, 2, macPythonTestPathCommand(0xc, foreignCore))
		macPythonWriteFixture(t, f.entry, macPythonTestUniversal(intel, arm), 0755)
		if _, err := validateMacPythonRuntime(f.entry, f.framework); err == nil {
			t.Fatal("the unselected universal slice escaped the captured Python framework")
		}
	})
	t.Run("app-executable-has-its-own-loader-context", func(t *testing.T) {
		f := macPythonRuntimeFiles(t, base)
		app := f.root + "/Resources/Python.app/Contents/MacOS/Python3"
		appLibrary := filepath.Dir(app) + "/libapp-runtime.dylib"
		macPythonWriteFixture(t, appLibrary, macPythonTestImage(0x01000007, 6), 0644)
		macPythonWriteFixture(t, app, macPythonTestImage(0x01000007, 2,
			macPythonTestPathCommand(0xc, f.core), macPythonTestPathCommand(0xc, "@executable_path/libapp-runtime.dylib")), 0755)
		if _, err := validateMacPythonRuntime(f.entry, f.framework); err != nil {
			t.Fatal("actual framework app used the outer launcher's directory", err)
		}
		if err := os.Chown(appLibrary, 65534, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := validateMacPythonRuntime(f.entry, f.framework); err == nil {
			t.Fatal("actual framework app imported a foreign native runtime")
		}
		if err := os.Chown(appLibrary, 0, 0); err != nil {
			t.Fatal(err)
		}
		macPythonWriteFixture(t, filepath.Dir(filepath.Dir(app))+"/pyvenv.cfg", []byte("home = /untrusted\n"), 0644)
		if _, err := validateMacPythonRuntime(f.entry, f.framework); err == nil {
			t.Fatal("a framework app prefix override escaped the selected entry's guard")
		}
	})
	t.Run("app-and-transitive-imports-cannot-select-another-python", func(t *testing.T) {
		for _, direct := range []bool{true, false} {
			f := macPythonRuntimeFiles(t, base)
			app := f.root + "/Resources/Python.app/Contents/MacOS/Python3"
			macPythonWriteFixture(t, app, macPythonTestImage(0x01000007, 2, macPythonTestPathCommand(0xc, f.core)), 0755)
			if _, err := validateMacPythonRuntime(f.entry, f.framework); err != nil {
				t.Fatal("the actual app baseline did not bind its captured runtime", err)
			}
			alternate := filepath.Dir(f.distribution) + "/Alternate/Python3.framework/Versions/3.10"
			core := alternate + "/Python3"
			macPythonWriteFixture(t, core, macPythonTestImage(0x01000007, 6), 0755)
			macPythonWriteFixture(t, alternate+"/lib/python3.10/os.py", []byte("# unproved alternate standard library\n"), 0666)
			if err := os.Chown(alternate+"/lib/python3.10/os.py", 65534, 0); err != nil {
				t.Fatal(err)
			}
			if direct {
				macPythonWriteFixture(t, app, macPythonTestImage(0x01000007, 2, macPythonTestPathCommand(0xc, core)), 0755)
			} else {
				macPythonWriteFixture(t, f.dependency, macPythonTestImage(0x01000007, 6, macPythonTestPathCommand(0xc, core)), 0644)
			}
			if _, err := validateMacPythonRuntime(f.entry, f.framework); err == nil {
				t.Fatal("the app or imported native image selected an unchecked alternate Python standard library", direct)
			}
		}
	})
	t.Run("system-namespace-does-not-select-another-python-core", func(t *testing.T) {
		f := macPythonRuntimeFiles(t, base)
		if _, err := validateMacPythonRuntime(f.entry, f.framework); err != nil {
			t.Fatal("actual protected runtime baseline", err)
		}
		macPythonWriteFixture(t, f.dependency, macPythonTestImage(0x01000007, 6,
			macPythonTestPathCommand(0xc, "/System/Library/Frameworks/Python.framework/Versions/2.7/Python")), 0644)
		if _, err := validateMacPythonRuntime(f.entry, f.framework); err == nil {
			t.Fatal("the OS dependency namespace bypassed the single captured Python core")
		}
	})
}
