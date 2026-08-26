package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxPortablePrivateBytes int64 = 8 << 20

func validatePortablePrivateParent(path string) error {
	parent := filepath.Clean(filepath.Dir(path))
	if parent == "." {
		return nil
	}
	validate := func() error {
		for current := parent; ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil {
				if !os.IsNotExist(err) {
					return err
				}
			} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("refusing non-directory/symlink Portable private path component %s", current)
			}
			next := filepath.Dir(current)
			if next == current {
				break
			}
		}
		return nil
	}
	if err := validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	return validate()
}

func ensurePortablePrivateDir(path string) error {
	if err := validatePortablePrivateParent(filepath.Join(path, ".portable-private-check")); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("Portable private path is not a non-symlink directory: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return validatePortablePrivateParent(filepath.Join(path, ".portable-private-check"))
}

func hardenPortablePrivateFile(path string) error {
	if err := validatePortablePrivateParent(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular/symlink Portable private file %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func readPortablePrivate(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > maxPortablePrivateBytes {
		limit = maxPortablePrivateBytes
	}
	if err := hardenPortablePrivateFile(path); err != nil {
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
		return nil, fmt.Errorf("Portable private file %s changed during open", path)
	}
	if opened.Size() < 0 || opened.Size() > limit {
		return nil, fmt.Errorf("Portable private file %s exceeds safety limit", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("Portable private file %s exceeds safety limit", path)
	}
	return body, nil
}

func readPortablePackageFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > maxPortablePrivateBytes {
		limit = maxPortablePrivateBytes
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("refusing unsafe/oversized Portable package source %s", path)
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
	if !os.SameFile(opened, current) {
		return nil, fmt.Errorf("Portable package source %s changed during open", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("Portable package source %s exceeds safety limit", path)
	}
	return body, nil
}

func atomicWritePortablePrivate(path string, body []byte) error {
	if len(body) == 0 || int64(len(body)) > maxPortablePrivateBytes {
		return fmt.Errorf("Portable private output %s is empty or oversized", path)
	}
	if err := validatePortablePrivateParent(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := hardenPortablePrivateFile(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
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
	if err := validatePortablePrivateParent(path); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func copyPortablePrivate(src, dst string, overwrite bool) error {
	if !overwrite {
		if _, err := os.Lstat(dst); err == nil {
			return hardenPortablePrivateFile(dst)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	body, err := readPortablePackageFile(src, maxPortablePrivateBytes)
	if err != nil {
		return err
	}
	return atomicWritePortablePrivate(dst, body)
}
