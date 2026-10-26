package main

import (
	"errors"
	"io"
	"os"
)

// Check the opened object and its current name together. Permission checks must
// never authorize a replacement file or repair a different owner's workspace.
func privateRuntimeObjectUnchanged(file *os.File, expected os.FileInfo) error {
	if file == nil || expected == nil {
		return errors.New("private runtime object has no captured identity")
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(file.Name())
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSymlink != 0 || !(current.IsDir() || current.Mode().IsRegular()) ||
		current.IsDir() != expected.IsDir() || !os.SameFile(expected, opened) || !os.SameFile(expected, current) {
		return errors.New("private runtime object changed while being inspected")
	}
	return nil
}

func validatePrivateRuntimePathPermissions(path string, info os.FileInfo) error {
	file, err := openPrivateRuntimeForRead(path, info)
	if err != nil {
		return err
	}
	defer file.Close()
	return validatePrivateRuntimeOpenPermissions(file, info)
}

// An active proof is read-only. Unlike upgrade-time private-store reads, this
// reader never creates parents, chmods a file or repairs an ACL. The permissions,
// identity and bytes all belong to the same opened regular file.
func readPrivateRuntimeSnapshot(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > maxPrivateStoreBytes {
		return nil, errors.New("invalid private runtime snapshot limit")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	return readPrivateRuntimeSnapshotFrom(path, info, limit)
}

func readPrivateRuntimeSnapshotFrom(path string, info os.FileInfo, limit int64) ([]byte, error) {
	if info == nil || limit <= 0 || limit > maxPrivateStoreBytes {
		return nil, errors.New("private runtime snapshot has no bounded captured identity")
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("private runtime snapshot is not a bounded regular file")
	}
	file, err := openPrivateRuntimeForRead(path, info)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := validatePrivateRuntimeOpenPermissions(file, info); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || int64(len(body)) != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("private runtime snapshot changed while being read")
	}
	if err := validatePrivateRuntimeOpenPermissions(file, info); err != nil {
		return nil, err
	}
	return body, nil
}
