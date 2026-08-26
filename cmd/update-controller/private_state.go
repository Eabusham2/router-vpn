package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxUpdaterPrivateBytes int64 = 4 << 20

func validateUpdaterPrivateParent(path string) error {
	parent := filepath.Clean(filepath.Dir(path))
	if parent == "." {
		return nil
	}
	validateAncestors := func() error {
		for current := parent; ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil {
				if !os.IsNotExist(err) {
					return err
				}
			} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("refusing non-directory/symlink private updater path component %s", current)
			}
			next := filepath.Dir(current)
			if next == current {
				break
			}
		}
		return nil
	}
	if err := validateAncestors(); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	return validateAncestors()
}

func validateUpdaterPrivateFile(path string, limit int64) error {
	if err := validateUpdaterPrivateParent(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular/symlink private updater file %s", path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("private updater file %s must be mode 0600, got %#o", path, info.Mode().Perm())
	}
	if limit <= 0 || limit > maxUpdaterPrivateBytes {
		limit = maxUpdaterPrivateBytes
	}
	if info.Size() < 0 || info.Size() > limit {
		return fmt.Errorf("private updater file %s exceeds safety limit", path)
	}
	return nil
}

func readUpdaterPrivate(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > maxUpdaterPrivateBytes {
		limit = maxUpdaterPrivateBytes
	}
	if err := validateUpdaterPrivateFile(path, limit); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("private updater file %s changed during open", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("private updater file %s exceeds safety limit", path)
	}
	return body, nil
}

func atomicWriteUpdaterPrivate(path string, body []byte) error {
	if int64(len(body)) > maxUpdaterPrivateBytes {
		return fmt.Errorf("private updater file %s exceeds safety limit", path)
	}
	if err := validateUpdaterPrivateParent(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if _, err := os.Lstat(path); err == nil {
		if err := validateUpdaterPrivateFile(path, maxUpdaterPrivateBytes); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(parent, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := validateUpdaterPrivateParent(path); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	// Rename is the commit point. Directory sync is best effort so callers do
	// not roll RAM back after the new durable bytes have already been adopted.
	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
