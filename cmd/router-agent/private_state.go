package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxPrivilegedStateBytes int64 = 4 << 20

func validatePrivilegedStateFile(path string, limit int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular/symlink privileged state %s", path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("privileged state %s must be mode 0600, got %#o", path, info.Mode().Perm())
	}
	if limit <= 0 || limit > maxPrivilegedStateBytes {
		limit = maxPrivilegedStateBytes
	}
	if info.Size() < 0 || info.Size() > limit {
		return fmt.Errorf("privileged state %s exceeds safety limit", path)
	}
	return nil
}

func readPrivilegedState(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > maxPrivilegedStateBytes {
		limit = maxPrivilegedStateBytes
	}
	if err := validatePrivilegedStateFile(path, limit); err != nil {
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
		return nil, fmt.Errorf("privileged state %s changed during open", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("privileged state %s exceeds safety limit", path)
	}
	return body, nil
}

func atomicWritePrivilegedState(path string, body []byte) error {
	if int64(len(body)) > maxPrivilegedStateBytes {
		return fmt.Errorf("privileged state %s exceeds safety limit", path)
	}
	parent := filepath.Dir(path)
	if parent != "." {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validatePrivilegedStateFile(path, maxPrivilegedStateBytes); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	// The rename is the commit point. Directory sync is best effort so callers
	// never roll live/RAM state back after the new bytes are already authoritative.
	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
