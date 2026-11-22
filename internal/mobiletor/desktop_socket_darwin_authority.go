//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

type desktopDarwinProcessAuthorityKey struct{}

// WithDesktopDarwinProcessAuthority carries already validated installation
// descriptions into exact native command descendants. It grants no namespace,
// executable, rule or credential selector and cannot change a kernel verdict.
func WithDesktopDarwinProcessAuthority(ctx context.Context, files []*os.File) context.Context {
	return context.WithValue(ctx, desktopDarwinProcessAuthorityKey{}, append([]*os.File(nil), files...))
}

func desktopDarwinProcessAuthority(ctx context.Context) []*os.File {
	files, _ := ctx.Value(desktopDarwinProcessAuthorityKey{}).([]*os.File)
	return append([]*os.File(nil), files...)
}

// The guardian receives the same open descriptions after control FD 3 and
// observation FD 4. No pathname or independently reopened lock is accepted.
func desktopDarwinAttachGuardianLocks(ctx context.Context, command *exec.Cmd) (bool, error) {
	files := desktopDarwinProcessAuthority(ctx)
	if len(files) == 0 {
		return false, nil
	}
	if len(command.ExtraFiles) != 2 || len(files) != 2 || files[0] == nil || files[1] == nil {
		return false, errors.New("Darwin guardian requires the original installation and process lock pair")
	}
	command.ExtraFiles = append(command.ExtraFiles, files...)
	return true, nil
}

var desktopDarwinGuardianLocks struct {
	sync.RWMutex
	files []*os.File
}

// Called only after the actual root guardian authenticates its first prepare.
// Keep these descriptions until its native cleanup finishes. Mark them
// close-on-exec so isolated creator and UID-observer processes cannot inherit
// them. Only the fixed privileged utility launcher below passes them onward.
func desktopDarwinHoldGuardianLocks(present bool) (func(), error) {
	if !present {
		return func() {}, nil
	}
	desktopDarwinGuardianLocks.Lock()
	defer desktopDarwinGuardianLocks.Unlock()
	if desktopDarwinGuardianLocks.files != nil {
		return nil, errors.New("Darwin guardian already holds an original lock pair")
	}
	files := []*os.File{os.NewFile(5, "native-install-lock"), os.NewFile(6, "native-process-lock")}
	closeFiles := func() {
		for _, file := range files {
			_ = file.Close()
		}
	}
	var install os.FileInfo
	for index, file := range files {
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || index == 1 && os.SameFile(install, info) {
			closeFiles()
			return nil, errors.Join(err, errors.New("Darwin guardian did not inherit two distinct original locks"))
		}
		if index == 0 {
			install = info
		}
		fd := file.Fd()
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if errno == 0 {
			_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, flags|syscall.FD_CLOEXEC)
		}
		if errno != 0 {
			closeFiles()
			return nil, errno
		}
	}
	desktopDarwinGuardianLocks.files = files
	return func() {
		desktopDarwinGuardianLocks.Lock()
		defer desktopDarwinGuardianLocks.Unlock()
		if len(desktopDarwinGuardianLocks.files) == 2 && desktopDarwinGuardianLocks.files[0] == files[0] {
			desktopDarwinGuardianLocks.files = nil
			closeFiles()
		}
	}, nil
}

// Hold the guardian's scope through Start, when the kernel transfers the
// descriptions to the utility. A surviving utility therefore retains the same
// locks even if its guardian dies. No observation or rule verdict is changed.
func desktopDarwinStartPrivilegedCommand(ctx context.Context, command *exec.Cmd) error {
	command.ExtraFiles = desktopDarwinProcessAuthority(ctx)
	if len(command.ExtraFiles) != 0 {
		return command.Start()
	}
	desktopDarwinGuardianLocks.RLock()
	defer desktopDarwinGuardianLocks.RUnlock()
	command.ExtraFiles = desktopDarwinGuardianLocks.files
	return command.Start()
}
