//go:build windows

package windowsapp

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

// portableTemporary retains the original desktop's private Data/generated
// directory. Only the original-user GUI receives its compatible DOS spelling:
// Windows PowerShell 5.1 CodeDOM rejects the otherwise valid volume-GUID form.
// This spelling grants no elevated image, configuration or socket authority.
type portableTemporary struct {
	path  string
	files []*os.File
}

func capturePortableTemporary(dataRoot, desktop string) (_ *portableTemporary, failure error) {
	capture := &portableTemporary{}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, capture.Close())
		}
	}()
	api, err := portableNative()
	if err != nil {
		return capture, err
	}
	retain := func(path string) (*os.File, error) {
		name, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		// FILE_LIST_DIRECTORY makes the no-delete share participate in native
		// sharing enforcement. An attributes-only handle can inspect an object
		// while still allowing its pathname to be renamed underneath the owner.
		handle, err := syscall.CreateFile(name, 0x00020000|0x80|syscall.FILE_LIST_DIRECTORY, /* READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY */
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING,
			syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(handle), path)
		capture.files = append(capture.files, file)
		if _, err := portableFileIdentity(file, true); err != nil {
			return nil, err
		}
		security, err := portableInspectSecurity(api, file)
		if err != nil {
			return nil, err
		}
		owner, _, grants, inspectErr := security.inspect()
		if err := errors.Join(inspectErr, validatePortablePrivateGrants(owner, desktop, grants), security.close()); err != nil {
			return nil, err
		}
		if security.control&0x1000 == 0 {
			return nil, errors.New("Portable GUI temporary state has unprotected inheritance")
		}
		return file, nil
	}
	if _, err := retain(dataRoot); err != nil {
		return capture, err
	}
	temporary, err := retain(filepath.Join(dataRoot, "generated"))
	if err != nil {
		return capture, err
	}
	system, err := windowscontroller.SystemDirectory()
	if err != nil {
		return capture, err
	}
	library, err := syscall.LoadDLL(filepath.Join(system, "kernel32.dll"))
	if err != nil {
		return capture, err
	}
	defer func() { failure = errors.Join(failure, library.Release()) }()
	finalPath, err := library.FindProc("GetFinalPathNameByHandleW")
	if err != nil {
		return capture, err
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := finalPath.Call(temporary.Fd(), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0 /* VOLUME_NAME_DOS */)
	runtime.KeepAlive(temporary)
	if length == 0 || length >= uintptr(len(buffer)) {
		return capture, errors.Join(callErr, errors.New("Portable GUI temporary directory has no captured compatible name"))
	}
	path := strings.TrimPrefix(syscall.UTF16ToString(buffer[:length]), `\\?\`)
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' ||
		!(path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z') || filepath.Clean(path) != path {
		return capture, errors.New("Portable GUI temporary directory has no unambiguous local DOS spelling")
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || strings.TrimRight(part, ". ") != part || strings.ContainsAny(part, ":/\x00") {
			return capture, errors.New("Portable GUI temporary directory has an ambiguous path component")
		}
	}
	spelling, err := retain(path)
	if err != nil {
		return capture, err
	}
	want, wantErr := temporary.Stat()
	actual, actualErr := spelling.Stat()
	if wantErr != nil || actualErr != nil || !os.SameFile(want, actual) {
		return capture, errors.Join(wantErr, actualErr, errors.New("Portable GUI temporary spelling changed its captured directory"))
	}
	capture.path = path
	return capture, nil
}

func (c *portableTemporary) Close() error {
	if c == nil {
		return nil
	}
	var failures []error
	for index := len(c.files) - 1; index >= 0; index-- {
		if c.files[index] == nil {
			continue
		}
		if err := c.files[index].Close(); err != nil {
			failures = append(failures, err)
		} else {
			c.files[index] = nil
		}
	}
	return errors.Join(failures...)
}
