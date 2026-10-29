//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// The installation root also contains the original user's native application.
// Validate its mutation authority without making that application inaccessible.
// Secret-bearing runtime directories below run/ retain their separate 0700
// preparation, and every runtime file retains its private permission contract.
func preparePrivateRuntimeRoot(path string) error {
	if err := validatePrivateParent(filepath.Join(path, ".runtime-root-check")); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	file, err := openPrivateRuntimeForRead(path, info)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := validatePrivateRuntimeRoot(file, info); err != nil {
		return err
	}
	if err := validatePrivateParent(filepath.Join(path, ".runtime-root-check")); err != nil {
		return err
	}
	return validatePrivateRuntimeRoot(file, info)
}

func validatePrivateRuntimeRoot(file *os.File, info os.FileInfo) error {
	if err := privateRuntimeObjectUnchanged(file, info); err != nil {
		return err
	}
	current, err := file.Stat()
	if err != nil {
		return err
	}
	owner, ok := current.Sys().(*syscall.Stat_t)
	if !ok || !current.IsDir() || owner.Uid != uint32(os.Geteuid()) ||
		current.Mode().Perm()&0o022 != 0 || current.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("private runtime installation root has unsafe ownership or mutation permissions")
	}
	if err := ownedPathACL(file.Name()); err != nil {
		return err
	}
	return privateRuntimeObjectUnchanged(file, info)
}
