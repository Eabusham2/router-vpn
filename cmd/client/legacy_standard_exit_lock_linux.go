//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"router-vpn/internal/mobiletor"
)

// The fd is the same flock inode used by every Linux Python policy mutation.
// It is never unlinked or explicitly unlocked: any inherited child must keep
// exclusion until that child's own descriptor closes.
type legacyExitMutationLease struct {
	rootPath                    string
	root, run, lock             *os.File
	rootInfo, runInfo, lockInfo os.FileInfo
}

func legacyExitPrivate(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0022 == 0 && (directory && info.IsDir() || !directory && info.Mode().Perm()&0077 == 0 && info.Mode().IsRegular() && st.Nlink == 1)
}
func (l *legacyExitMutationLease) Close() {
	for _, f := range []*os.File{l.lock, l.run, l.root} {
		if f != nil {
			_ = f.Close()
		}
	}
}
func (l *legacyExitMutationLease) Current() error {
	if l == nil || l.root == nil || l.run == nil || l.lock == nil {
		return errors.New("standard mutation lease lost its original descriptors")
	}
	for _, entry := range []struct {
		file      *os.File
		original  os.FileInfo
		path      string
		directory bool
	}{{l.root, l.rootInfo, l.rootPath, true}, {l.run, l.runInfo, filepath.Join(l.rootPath, "run"), true}, {l.lock, l.lockInfo, filepath.Join(l.rootPath, "run", "kill-switch.lock"), false}} {
		actual, err := entry.file.Stat()
		named, nameErr := os.Lstat(entry.path)
		if err != nil || nameErr != nil || !legacyExitPrivate(actual, entry.directory) || entry.file == l.run && actual.Mode().Perm()&0077 != 0 || !os.SameFile(actual, entry.original) || !os.SameFile(actual, named) {
			return errors.New("standard mutation lease changed its private original inode")
		}
	}
	return nil
}
func acquireLegacyExitMutationLease(ctx context.Context, root string) (*legacyExitMutationLease, error) {
	if ctx == nil || !filepath.IsAbs(root) {
		return nil, errors.New("standard mutation admission has no original root or deadline")
	}
	// Stop may spend its original budget joining the captured engine before
	// reaching policy retirement. Preserve that cancellation cause without
	// opening or creating any mutation descriptors.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	root = filepath.Clean(root)
	for path := root; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("standard mutation root has an unsafe ancestor")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	l := &legacyExitMutationLease{rootPath: root}
	valid := false
	defer func() {
		if !valid {
			l.Close()
		}
	}()
	open := func(path string, flags int) (*os.File, error) {
		fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	var err error
	l.root, err = open(root, syscall.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	l.rootInfo, err = l.root.Stat()
	if err != nil || !legacyExitPrivate(l.rootInfo, true) {
		return nil, errors.New("standard mutation root must be private and owned")
	}
	if err = syscall.Mkdirat(int(l.root.Fd()), "run", 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, err
	}
	fd, err := syscall.Openat(int(l.root.Fd()), "run", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	l.run = os.NewFile(uintptr(fd), "original-standard-run")
	l.runInfo, err = l.run.Stat()
	if err != nil || !legacyExitPrivate(l.runInfo, true) || l.runInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("standard mutation run directory must be private and owned")
	}
	fd, err = syscall.Openat(int(l.run.Fd()), "kill-switch.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	l.lock = os.NewFile(uintptr(fd), "original-standard-mutation")
	l.lockInfo, err = l.lock.Stat()
	if err != nil {
		return nil, err
	}
	for {
		if err = l.Current(); err != nil {
			return nil, err
		}
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			stopTimerWithoutBlocking(timer)
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err = l.Current(); err != nil {
		return nil, err
	}
	valid = true
	return l, nil
}
func legacyExitStateAbsent(l *legacyExitMutationLease) error {
	fd, err := syscall.Openat(int(l.run.Fd()), "kill-switch.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		_ = syscall.Close(fd)
		return errors.New("captured Off cannot adopt or release persisted protection; original owner required")
	}
	if !errors.Is(err, syscall.ENOENT) {
		return err
	}
	return l.Current()
}
func legacyExitVerifyOffProtection(ctx context.Context, root string, expectedNamespace os.FileInfo) error {
	l, err := acquireLegacyExitMutationLease(ctx, root)
	if err != nil {
		return err
	}
	defer l.Close()
	if err = legacyExitStateAbsent(l); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || expectedNamespace == nil || !os.SameFile(before, expectedNamespace) {
		return errors.Join(err, errors.New("Off protection readback lost its captured network namespace"))
	}
	if err = mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return err
	}
	after, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(before, after) {
		return errors.New("Off protection readback left its original namespace")
	}
	return legacyExitStateAbsent(l)
}
