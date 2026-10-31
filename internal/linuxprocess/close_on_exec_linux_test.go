//go:build linux

package linuxprocess

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
)

func retainedDescriptorFlags(t *testing.T, file *os.File) (descriptor, status uintptr) {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var nativeErr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		descriptor, _, nativeErr = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if nativeErr == 0 {
			status, _, nativeErr = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		}
	})
	if err != nil || nativeErr != 0 {
		t.Fatal("could not observe the original retained descriptor flags", err, nativeErr)
	}
	return descriptor, status
}

func clearRetainedCloseOnExec(t *testing.T, file *os.File) {
	t.Helper()
	flags, _ := retainedDescriptorFlags(t, file)
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var nativeErr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		_, _, nativeErr = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, flags & ^uintptr(syscall.FD_CLOEXEC))
	})
	if err != nil || nativeErr != 0 {
		t.Fatal(err, nativeErr)
	}
}

func TestRetainedCloseOnExecPreservesFileState(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "retained-file-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write([]byte("original owned file")); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(3, 0); err != nil {
		t.Fatal(err)
	}
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	clearRetainedCloseOnExec(t, file)
	flags, status := retainedDescriptorFlags(t, file)
	if err := SetCloseOnExec(file); err != nil {
		t.Fatal(err)
	}
	actual, actualStatus := retainedDescriptorFlags(t, file)
	after, statErr := file.Stat()
	position, seekErr := file.Seek(0, 1)
	if actual != flags|syscall.FD_CLOEXEC || actualStatus != status || statErr != nil || seekErr != nil ||
		!os.SameFile(before, after) || position != 3 {
		t.Fatal("CLOEXEC changed the original file, open flags or retained offset", actual, actualStatus, statErr, seekErr)
	}
	if err := SetCloseOnExec(file); err != nil {
		t.Fatal("an already marked original descriptor could not be read back", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := SetCloseOnExec(file); err == nil {
		t.Fatal("CLOEXEC accepted a retired original file")
	}
	if err := SetCloseOnExec(nil); err == nil {
		t.Fatal("CLOEXEC accepted an absent original file")
	}
}

func TestRetainedCloseOnExecKeepsPartialCaptureOwners(t *testing.T) {
	for _, kind := range []string{"channel", "directory", "cancelled-directory", "closed-channel", "closed-directory"} {
		t.Run(kind, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "partial-original-")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			clearRetainedCloseOnExec(t, file)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			closed := kind == "closed-channel" || kind == "closed-directory"
			var replacement *os.File
			if closed {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				replacement, err = os.CreateTemp(t.TempDir(), "independent-replacement-")
				if err != nil {
					t.Fatal(err)
				}
				defer replacement.Close()
				clearRetainedCloseOnExec(t, replacement)
			} else if kind == "cancelled-directory" {
				cancel()
			}
			var closeOwner func(context.Context) error
			if kind == "channel" || kind == "closed-channel" {
				owner, err := CaptureChannel(file)
				if err == nil || owner == nil || owner.file != file || owner.conn != nil {
					t.Fatal("failed channel capture lost its exact partial descriptor owner", err)
				}
				closeOwner = owner.Close
			} else {
				owner, err := CaptureDirectory(ctx, file, os.Getpid())
				if err == nil || owner == nil || owner.directory != file || owner.complete {
					t.Fatal("failed directory capture lost its exact partial descriptor owner", err)
				}
				closeOwner = owner.Close
			}
			if !closed {
				flags, _ := retainedDescriptorFlags(t, file)
				if flags&syscall.FD_CLOEXEC == 0 {
					t.Fatal("partial capture retained an inheritable original descriptor")
				}
			}
			if err := closeOwner(context.Background()); err != nil {
				t.Fatal("partial capture did not close only its original owner", err)
			}
			if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("partial cleanup left its original descriptor open", err)
			}
			if replacement != nil {
				flags, _ := retainedDescriptorFlags(t, replacement)
				if flags&syscall.FD_CLOEXEC != 0 {
					t.Fatal("retired original descriptor marked an independent replacement")
				}
			}
		})
	}
}
