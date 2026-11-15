//go:build windows && routervpn_windows_candidate_prefix_native

package routervpnamnezia

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// These controls run on the actual Windows host. They exercise the projected
// original image capture and worker reader against real DACLs and file handles.
func TestRouterVPNWindowsExecutionPrivateWorker(t *testing.T) {
	for _, kind := range []string{"private", "original-posix-modes", "public-input", "null-input", "unknown-input", "public-code-writer", "public-code-reader", "hardlink-input", "replaced-input", "worker-environment"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			info, err := os.Lstat(directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := preparePrivateRuntimeDirectoryPermissions(directory, info); err != nil {
				t.Fatal(err)
			}
			if err := validatePrivateRuntimePathPermissions(directory, info); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "captured.json")
			if err := os.WriteFile(path, []byte("original private source\n"), 0600); err != nil {
				t.Fatal(err)
			}
			original, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			user, err := windowsRuntimeCurrentUser()
			if err != nil {
				t.Fatal(err)
			}
			set := func(sddl string) {
				t.Helper()
				security, err := windowsRuntimeSecurityFromSDDL(sddl)
				if err != nil {
					t.Fatal(err)
				}
				defer security.close()
				file, err := openWindowsPrivateRuntime(path, original, windowsRuntimeReadControl|windowsRuntimeWriteDAC)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				code, _, _ := windowsRuntimeSetSecurityInfo.Call(file.Fd(), windowsRuntimeFileObject, windowsRuntimeDACLInformation|windowsRuntimeProtectedDACL, 0, 0, uintptr(unsafe.Pointer(security.dacl)), 0)
				if code != 0 {
					t.Fatal(syscall.Errno(code))
				}
			}
			switch kind {
			case "original-posix-modes":
				if err := os.Chmod(directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				dir, err := os.Stat(directory)
				if err != nil {
					t.Fatal(err)
				}
				file, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if dir.Mode().Perm() == 0700 || file.Mode().Perm() == 0600 || file.Mode().Perm()&0111 != 0 {
					t.Fatal("Windows acquired unsupported POSIX private/executable permissions")
				}
			case "public-input", "public-code-reader":
				set("O:" + user + "D:P(A;;FA;;;" + user + ")(A;;GR;;;WD)")
			case "public-code-writer":
				set("O:" + user + "D:P(A;;FA;;;" + user + ")(A;;GW;;;WD)")
			case "null-input":
				set("O:" + user)
			case "unknown-input":
				set("O:" + user + "D:P(A;;FA;;;" + user + ")(A;;GR;;;S-1-5-21-111-222-333-444)")
			case "hardlink-input":
				if err := os.Link(path, filepath.Join(directory, "other.json")); err != nil {
					t.Fatal(err)
				}
			case "replaced-input":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("foreign private source\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if validatePrivateRuntimePathPermissions(path, original) == nil {
					t.Fatal("replacement acquired original file authority")
				}
				return
			case "worker-environment":
				environment, err := windowsCONNECTExecutionWorkerEnvironment()
				if err != nil {
					t.Fatal(err)
				}
				if len(environment) != 4 {
					t.Fatal("uncaptured worker environment")
				}
				found := map[string]string{}
				for _, value := range environment {
					key, value, ok := strings.Cut(value, "=")
					if !ok || found[key] != "" {
						t.Fatal("malformed worker environment")
					}
					found[key] = value
				}
				if found["SystemRoot"] == "" || found["SystemRoot"] != found["WINDIR"] || !filepath.IsAbs(found["PATH"]) || found["GORACE"] != "atexit_sleep_ms=0" {
					t.Fatal("worker lost actual Windows machine environment")
				}
			}
			if kind == "public-code-writer" || kind == "public-code-reader" {
				file, _, _, err := captureImportedExecutionImage(path)
				if file != nil {
					file.Close()
				}
				if (err == nil) != (kind == "public-code-reader") {
					t.Fatal("original Windows code DACL boundary changed", kind, err)
				}
				return
			}
			raw, err := windowsCONNECTExecutionRead(root, "captured.json", 128)
			positive := kind == "private" || kind == "original-posix-modes" || kind == "worker-environment"
			if (err == nil) != positive || positive && string(raw) != "original private source\n" {
				t.Fatal("original Windows worker DACL boundary changed", kind, err)
			}
		})
	}
}
