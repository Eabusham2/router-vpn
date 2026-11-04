//go:build linux && routervpn_controller_privileged

package standardengine

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestCleanupOriginalDescriptorAndStableFrames(t *testing.T) {
	for _, scenario := range []string{"complete", "wrong-source", "torn", "foreign-object", "closed", "replaced-descriptor", "missing-result"} {
		t.Run(scenario, func(t *testing.T) {
			original, err := NewCleanupFile()
			if err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			device, inode := original.Identity()
			duplicate, err := syscall.Dup(int(original.File().Fd()))
			if err != nil {
				t.Fatal(err)
			}
			child, err := CaptureCleanupFile(os.NewFile(uintptr(duplicate), "original-child-cleanup"), device, inode)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			expected := strings.Repeat("a", 64)
			request := CleanupRequest{1, expected, 1, 1234567}
			if err := original.WriteRequest(request); err != nil {
				t.Fatal(err)
			}
			if got, err := child.ReadRequest(expected); err != nil || got != request {
				t.Fatal("original control frame", got, err)
			}
			result := CleanupResult{Schema: 1, CaptureSHA256: expected, Sequence: 1, DeadlineNS: request.DeadlineNS, StartedNS: 1, Authority: "request", Complete: true, Ledger: "actual captured native ledger"}
			if scenario != "missing-result" {
				if err := child.WriteResult(result); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "wrong-source":
				expected = strings.Repeat("b", 64)
			case "torn":
				if _, err := child.File().WriteAt([]byte("changed"), cleanupRequestSize+40); err != nil {
					t.Fatal(err)
				}
			case "foreign-object":
				foreign, err := NewCleanupFile()
				if err != nil {
					t.Fatal(err)
				}
				defer foreign.Close()
				fd, err := syscall.Dup(int(foreign.File().Fd()))
				if err != nil {
					t.Fatal(err)
				}
				wrong, err := CaptureCleanupFile(os.NewFile(uintptr(fd), "foreign"), device, inode)
				defer wrong.Close()
				if err == nil || wrong.Current() == nil {
					t.Fatal("foreign same-shaped object supplied original authority")
				}
				return
			case "closed":
				if err := original.Close(); err != nil {
					t.Fatal(err)
				}
			case "replaced-descriptor":
				saved, err := syscall.Dup(int(original.File().Fd()))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = syscall.Dup2(saved, int(original.File().Fd())); _ = syscall.Close(saved) }()
				foreign, err := NewCleanupFile()
				if err != nil {
					t.Fatal(err)
				}
				defer foreign.Close()
				if err := syscall.Dup2(int(foreign.File().Fd()), int(original.File().Fd())); err != nil {
					t.Fatal(err)
				}
				if err := original.Close(); err == nil {
					t.Fatal("cleanup closed a replacement descriptor")
				}
				if _, err := original.File().Stat(); err != nil {
					t.Fatal("replacement descriptor was touched", err)
				}
			}
			got, err := original.ReadResult(expected)
			if scenario == "complete" {
				if err != nil || got != result {
					t.Fatal("original child result", got, err)
				}
			} else if err == nil {
				t.Fatal("missing, torn or replaced result accepted", scenario)
			}
		})
	}
}

func TestCleanupRejectsMutableSizeAndUnsealedFiles(t *testing.T) {
	original, err := NewCleanupFile()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	if err := original.File().Truncate(1); err == nil {
		t.Fatal("original result size could change")
	}
	file, err := os.CreateTemp(t.TempDir(), "unowned")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(cleanupSize); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	captured, err := CaptureCleanupFile(file, stat.Dev, stat.Ino)
	defer captured.Close()
	if err == nil {
		t.Fatal("pathname file became inherited original result authority")
	}
	if err := original.WriteResult(CleanupResult{Schema: 1, CaptureSHA256: strings.Repeat("a", 64), DeadlineNS: 1, Complete: true}); err == nil {
		t.Fatal("empty final ledger fabricated native cleanup")
	}
	if err := original.WriteRequest(CleanupRequest{Schema: 1, CaptureSHA256: strings.Repeat("a", 64), DeadlineNS: 1}); err == nil {
		t.Fatal("request omitted its original attempt")
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	if err := original.Current(); err == nil {
		t.Fatal("closed original object was reused", err)
	}
}
