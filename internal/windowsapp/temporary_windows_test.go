//go:build windows

package windowsapp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsPortableTemporaryRetainsPrivateIdentity(t *testing.T) {
	_, packageRoot, dataRoot, desktop := portableNativeFixture(t)
	if err := preparePortableCaptured(context.Background(), packageRoot, dataRoot, desktop, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing", "junction", "private"} {
		t.Run(scenario, func(t *testing.T) {
			generated := filepath.Join(dataRoot, "generated")
			if scenario != "private" {
				if err := os.Remove(generated); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Remove(generated); err != nil && !os.IsNotExist(err) {
						t.Error(err)
					}
					api, err := portableNative()
					if err != nil {
						t.Fatal(err)
					}
					restored, err := portablePrivateDirectory(api, generated, desktop)
					if err != nil {
						t.Fatal(err)
					}
					if err := restored.Close(); err != nil {
						t.Fatal(err)
					}
				}()
				if scenario == "junction" {
					if err := os.Symlink(t.TempDir(), generated); err != nil {
						t.Fatal("actual Portable temporary reparse negative could not be created", err)
					}
				}
			}
			capture, err := capturePortableTemporary(dataRoot, desktop)
			if capture != nil {
				defer func() {
					if err := capture.Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			if scenario != "private" {
				if err == nil {
					t.Fatal("unsafe Portable temporary directory was admitted")
				}
				return
			}
			if err != nil || capture == nil {
				t.Fatal("private Portable temporary capture failed", err)
			}
			if strings.HasPrefix(capture.path, `\\`) || !filepath.IsAbs(capture.path) {
				t.Fatal("Portable temporary handoff retained a CodeDOM-incompatible name")
			}
			actual, err := os.Stat(capture.path)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.Stat(generated)
			if err != nil || !os.SameFile(actual, want) {
				t.Fatal("Portable temporary handoff escaped its captured private Data", err)
			}
			if err := os.Rename(generated, generated+"-moved"); err == nil {
				t.Fatal("live Portable temporary capture allowed its directory to move")
			}
			if err := capture.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(generated, generated+"-moved"); err != nil {
				t.Fatal("retired Portable temporary capture still held its directory", err)
			}
			if err := os.Rename(generated+"-moved", generated); err != nil {
				t.Fatal(err)
			}
		})
	}
}
