package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxPrivateStoreBytes = 4 << 20

func validatePrivateParent(path string) error {
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
				return fmt.Errorf("refusing non-directory/symlink private store path component %s", current)
			}
			next := filepath.Dir(current)
			if next == current {
				break
			}
		}
		return nil
	}
	// Validate every existing lexical ancestor before MkdirAll so a symlink in
	// an earlier path component cannot redirect creation outside the intended
	// private state tree. Re-check afterwards to catch a concurrently changed
	// component before any private file is opened or renamed.
	if err := validateAncestors(); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	return validateAncestors()
}

// hardenPrivateRegular validates a private authoritative file before it is read
// or replaced. Existing group/world permission bits are removed before reading
// so upgrades from older packages converge to the private-store contract.
func hardenPrivateRegular(path string) error {
	if err := validatePrivateParent(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular/symlink private store %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("harden private store permissions %s: %w", path, err)
		}
	}
	return nil
}

func readPrivateRegular(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > maxPrivateStoreBytes {
		limit = maxPrivateStoreBytes
	}
	if err := hardenPrivateRegular(path); err != nil {
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
		return nil, fmt.Errorf("private store %s changed during open", path)
	}
	if !opened.Mode().IsRegular() || opened.Size() > limit {
		return nil, fmt.Errorf("private store %s is not a bounded regular file", path)
	}
	buf, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("private store %s exceeds safety limit", path)
	}
	return buf, nil
}

// atomicWritePrivate publishes one private file without an interval containing a
// truncated/partial authoritative value. All fallible permission/write/fsync
// work happens on the same-directory temporary file before rename. Once rename
// succeeds the new bytes are authoritative, so a best-effort directory fsync is
// deliberately not returned as a false post-commit failure to callers that may
// otherwise roll RAM back while disk already contains the new value.
func atomicWritePrivateTargetUnchanged(path string, before os.FileInfo) error {
	current, err := os.Lstat(path)
	if before == nil {
		if err == nil {
			return fmt.Errorf("private store %s appeared before adoption", path)
		}
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("private store %s disappeared before adoption", path)
		}
		return err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(before, current) {
		return fmt.Errorf("private store %s identity changed before adoption", path)
	}
	return nil
}

func atomicWritePrivate(path string, data []byte) error {
	if err := validatePrivateParent(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := hardenPrivateRegular(path); err != nil {
		return err
	}
	var targetBefore os.FileInfo
	if info, err := os.Lstat(path); err == nil {
		targetBefore = info
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
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := validatePrivateParent(path); err != nil {
		return err
	}
	if err := atomicWritePrivateTargetUnchanged(path, targetBefore); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	// Do not create a post-rename false failure edge. Directory fsync is useful
	// on filesystems that support it, but failure here cannot undo the rename.
	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
