//go:build windows

package windowsapp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

func updateNativeFixture(t *testing.T) (string, string) {
	t.Helper()
	_, packageRoot, dataRoot, desktop := portableNativeFixture(t)
	if err := preparePortableCaptured(context.Background(), packageRoot, dataRoot, desktop, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	return dataRoot, desktop
}

func TestWindowsUpdaterCacheRetainsPrivateIdentity(t *testing.T) {
	for _, components := range [][]string{{"updates"}, {"RouterVPN", "updates"}} {
		t.Run(strings.Join(components, "-"), func(t *testing.T) {
			base, desktop := updateNativeFixture(t)
			cache, err := captureUpdateCache(context.Background(), base, components, desktop)
			if cache != nil {
				defer cache.Close()
			}
			if err != nil {
				t.Fatal("private original-user updater cache was rejected", err)
			}
			assertPortablePrivateNative(t, cache.Path(), desktop, true)
			state := filepath.Join(cache.Path(), "app-update-state.json")
			if err := os.WriteFile(state, []byte("first owned state"), 0600); err != nil {
				t.Fatal("retained cache prevented ordinary updater writes", err)
			}
			temporary := filepath.Join(cache.Path(), ".router-vpn-update-state-123456")
			if err := os.WriteFile(temporary, []byte("new owned state"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(temporary, state); err != nil {
				t.Fatal("retained cache prevented atomic updater state replacement", err)
			}
			if body, err := os.ReadFile(state); err != nil || string(body) != "new owned state" {
				t.Fatal("retained cache prevented actual updater readback", err)
			}
			if err := cache.Verify(); err != nil {
				t.Fatal("original-user update contents were not reusable", err)
			}
			// Test both the selected directory and an ancestor while ownership is
			// live. READ_ATTRIBUTES alone is deliberately insufficient here.
			for _, path := range []string{cache.Path(), base} {
				if err := os.Rename(path, path+"-rebound"); !errors.Is(err, syscall.Errno(32)) && !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
					t.Fatal("retained updater cache allowed directory or ancestor replacement", err)
				}
			}
			if err := cache.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(base, base+"-released"); err != nil {
				t.Fatal("retired updater cache retained an owned directory", err)
			}
			if err := cache.Verify(); err == nil {
				t.Fatal("retired updater cache was reusable")
			}
		})
	}
}

func TestWindowsUpdaterCacheRejectsForeignObjects(t *testing.T) {
	for _, scenario := range []string{"cache-link", "file-link", "file-hardlink", "foreign-name", "foreign-directory", "foreign-cache-acl", "foreign-file-acl"} {
		t.Run(scenario, func(t *testing.T) {
			base, desktop := updateNativeFixture(t)
			cache, err := captureUpdateCache(context.Background(), base, []string{"updates"}, desktop)
			if err != nil {
				if cache != nil {
					cache.Close()
				}
				t.Fatal(err)
			}
			path := cache.Path()
			if err := cache.Close(); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(path, "app-update-state.json")
			outside := filepath.Join(base, "unrelated-original.txt")
			const sentinel = "preserve unrelated original bytes"
			if err := os.WriteFile(outside, []byte(sentinel), 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "cache-link":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				other := filepath.Join(base, "unrelated-directory")
				if err := os.Mkdir(other, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Fatal("native cache-link fixture could not be created", err)
				}
			case "file-link":
				if err := os.Symlink(outside, state); err != nil {
					t.Fatal("native file-link fixture could not be created", err)
				}
			case "file-hardlink":
				if err := os.Link(outside, state); err != nil {
					t.Fatal(err)
				}
			case "foreign-name":
				if err := os.WriteFile(filepath.Join(path, "foreign.json"), []byte(sentinel), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-directory":
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
			case "foreign-cache-acl":
				updateFixtureForeignReader(t, path, true, desktop)
			case "foreign-file-acl":
				if err := os.WriteFile(state, []byte(sentinel), 0600); err != nil {
					t.Fatal(err)
				}
				updateFixtureForeignReader(t, state, false, desktop)
			}
			candidate, err := captureUpdateCache(context.Background(), base, []string{"updates"}, desktop)
			if candidate != nil {
				if closeErr := candidate.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if err == nil {
				t.Fatal("unsafe existing updater cache was admitted")
			}
			if body, err := os.ReadFile(outside); err != nil || string(body) != sentinel {
				t.Fatal("rejected updater cache changed unrelated bytes", err)
			}
			if scenario == "foreign-cache-acl" || scenario == "foreign-file-acl" {
				inspect := path
				if scenario == "foreign-file-acl" {
					inspect = state
				}
				if !updateFixtureHasForeignReader(t, inspect, scenario == "foreign-cache-acl") {
					t.Fatal("updater silently repaired a foreign existing ACL")
				}
			}
		})
	}
}

func updateFixtureForeignReader(t *testing.T, path string, directory bool, desktop string) {
	t.Helper()
	api, err := portableNative()
	if err != nil {
		t.Fatal(err)
	}
	text, err := syscall.UTF16PtrFromString("O:" + desktop + "D:P(A;;FA;;;" + desktop + ")(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	security := &portableSecurity{api: api}
	ok, _, callErr := api.convert.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&security.descriptor)), 0)
	runtime.KeepAlive(text)
	defer security.close()
	if ok == 0 || security.descriptor == nil {
		t.Fatal(callErr)
	}
	_, acl, _, err := security.inspect()
	if err != nil {
		t.Fatal(err)
	}
	file, err := portableOpenExisting(path, directory, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	status, _, _ := api.set.Call(file.Fd(), 1, 4|0x80000000, 0, 0, uintptr(unsafe.Pointer(acl)), 0)
	runtime.KeepAlive(security)
	if status != 0 {
		t.Fatal("fixture could not apply its foreign-reader ACL", syscall.Errno(status))
	}
	if !updateFixtureHasForeignReader(t, path, directory) {
		t.Fatal("fixture did not establish its actual foreign reader")
	}
}

func updateFixtureHasForeignReader(t *testing.T, path string, directory bool) bool {
	t.Helper()
	api, err := portableNative()
	if err != nil {
		t.Fatal(err)
	}
	handle, err := updateOpenMetadata(path, directory, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)
	security := &portableSecurity{api: api}
	status, _, _ := api.get.Call(uintptr(handle), 1, 1|4, 0, 0, 0, 0, uintptr(unsafe.Pointer(&security.descriptor)))
	defer security.close()
	if status != 0 {
		t.Fatal(syscall.Errno(status))
	}
	_, _, grants, err := security.inspect()
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if grant.allow && grant.principal == "S-1-1-0" && grant.mask != 0 {
			return true
		}
	}
	return false
}

func TestWindowsUpdaterPinnedProvenance(t *testing.T) {
	base, desktop := updateNativeFixture(t)
	path := filepath.Join(base, "ROUTER-VPN-SOURCE.json")
	sha := strings.Repeat("b", 40)
	raw := `{"schema_version":1,"repository":"Eabusham2/router-vpn","source_sha":"` + sha + `","artifact_family":"windows-portable-` + runtime.GOARCH + `"}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	pin, err := windowscontroller.PinFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	actual, err := readUpdateSource(pin, desktop, true)
	if err != nil || actual != sha {
		t.Fatal("actual pinned provenance was rejected", err)
	}
	if _, err := readUpdateSource(pin, desktop, false); err == nil {
		t.Fatal("pinned updater provenance selected another package layout")
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); !errors.Is(err, syscall.Errno(32)) {
		t.Fatal("actual updater provenance was writable while retained", err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal("updater provenance pin did not retire", err)
	}
}

func TestWindowsUpdaterCacheCancellation(t *testing.T) {
	base, desktop := updateNativeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cache, err := captureUpdateCache(ctx, base, []string{"updates"}, desktop)
	if cache != nil {
		defer cache.Close()
	}
	if err == nil {
		t.Fatal("cancelled updater operation acquired its cache")
	}
	if _, err := os.Lstat(filepath.Join(base, "updates")); !os.IsNotExist(err) {
		t.Fatal("cancelled updater operation changed the original-user filesystem", err)
	}
}
