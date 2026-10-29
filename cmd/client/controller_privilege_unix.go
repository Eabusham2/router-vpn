//go:build linux || darwin

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func ownedDesktopInfo(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && info.Mode()&0022 == 0 &&
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) == 0 &&
		(info.IsDir() || info.Mode().IsRegular() && stat.Nlink == 1)
}

func ownedDesktopAncestors(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("the native controller requires a canonical installed path")
	}
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || !ownedDesktopInfo(info) {
			return errors.New("the installed controller path is not exclusively root-owned")
		}
		if err := ownedPathACL(path); err != nil {
			return err
		}
		if path == string(filepath.Separator) {
			return nil
		}
		path = filepath.Dir(path)
	}
}

func ownedDesktopInstall(root string) error {
	if err := ownedDesktopAncestors(root); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, failure error) error {
		if failure != nil {
			return errors.New("the installed controller files cannot be checked safely")
		}
		info, err := entry.Info()
		if err != nil || !ownedDesktopInfo(info) {
			return errors.New("installed controller code or state has unsafe ownership, permissions or links")
		}
		return ownedPathACL(path)
	})
}

func ownedDesktopLock(path string, exclusive bool) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedDesktopInfo(info) || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, errors.New("unsafe installed controller lock")
	}
	if err = ownedPathACL(path); err != nil {
		file.Close()
		return nil, err
	}
	entry, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, entry) {
		file.Close()
		return nil, errors.New("the installed controller lock changed during ownership capture")
	}
	operation := syscall.LOCK_SH
	if exclusive {
		operation = syscall.LOCK_EX
	}
	if err = syscall.Flock(fd, operation|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
