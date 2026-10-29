//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func ownedPathACL(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	name, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	attributes := struct {
		Count, Reserved                       uint16
		Common, Volume, Directory, File, Fork uint32
	}{Count: 5, Common: 0x00400000} // ATTR_CMN_EXTENDED_SECURITY
	var data [4096]byte // Header + all 128 public kauth_ace entries.
	_, _, callErr := syscall.Syscall6(syscall.SYS_GETATTRLIST, uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		1 /* FSOPT_NOFOLLOW */, 0)
	runtime.KeepAlive(name)
	if callErr != 0 {
		return fmt.Errorf("cannot read privileged path ACL: %w", callErr)
	}
	if err = validateOwnedDarwinACL(data[:], before.Mode().Perm()&0077 == 0); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("the privileged path changed during its ACL readback")
	}
	first, ok1 := before.Sys().(*syscall.Stat_t)
	last, ok2 := after.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 || first.Ctimespec != last.Ctimespec || first.Mode != last.Mode || first.Uid != last.Uid || first.Gid != last.Gid || first.Nlink != last.Nlink {
		return errors.New("privileged path permissions changed during ACL capture")
	}
	return nil
}
