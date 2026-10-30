//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	windowsPrivateReplaceExisting = 0x1
	windowsPrivateWriteThrough    = 0x8
)

var windowsPrivateMoveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replacePrivateStoreFile(source, target string) error {
	return replaceWindowsPrivateStoreFile(source, target, moveWindowsPrivateStoreFile)
}

// The caller has already flushed and closed a same-directory private temporary
// file and rechecked the old target. Request the documented write-through move
// before acknowledging publication. Do not enable cross-volume copy, defer to
// reboot, fall back to an ordinary rename, or add a fallible step after success:
// callers must not roll RAM back after the new file has become authoritative.
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
func replaceWindowsPrivateStoreFile(source, target string, move func(*uint16, *uint16, uint32) error) error {
	before, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	after, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Dir(before), filepath.Dir(after)) {
		return errors.New("private replacement requires the captured same-directory temporary file")
	}
	oldName, err := windowsPrivateStoreName(before)
	if err != nil {
		return err
	}
	newName, err := windowsPrivateStoreName(after)
	if err != nil {
		return err
	}
	if err := move(oldName, newName, windowsPrivateReplaceExisting|windowsPrivateWriteThrough); err != nil {
		return &os.LinkError{Op: "replace-private", Old: source, New: target, Err: err}
	}
	return nil
}

func windowsPrivateStoreName(path string) (*uint16, error) {
	// Abs has already resolved relative paths and separators. Preserve existing
	// device prefixes; extend ordinary DOS/UNC paths so Portable private stores
	// retain the long-path behavior of the previous os.Rename implementation.
	if !strings.HasPrefix(path, `\\?\`) && !strings.HasPrefix(path, `\\.\`) && !strings.HasPrefix(path, `\??\`) {
		if strings.HasPrefix(path, `\\`) {
			path = `\\?\UNC\` + path[2:]
		} else {
			path = `\\?\` + path
		}
	}
	return syscall.UTF16PtrFromString(path)
}

func moveWindowsPrivateStoreFile(source, target *uint16, flags uint32) error {
	ok, _, err := windowsPrivateMoveFileEx.Call(uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(target)), uintptr(flags))
	runtime.KeepAlive(source)
	runtime.KeepAlive(target)
	if ok != 0 {
		return nil
	}
	if err == syscall.Errno(0) {
		return errors.New("Windows private replacement failed without an error code")
	}
	return err
}
