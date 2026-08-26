package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var privateRuntimeLeafRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)

// ensurePrivateRuntimeDirectory creates/validates one directory inside the
// client's private state tree without following a symlink in the directory or
// any lexical ancestor. Runtime files can contain tunnel private keys, proxy
// passwords, imported exit credentials and selected-DNS state, so disposable
// does not mean safe to redirect.
func ensurePrivateRuntimeDirectory(path string) error {
	if path == "" {
		return errors.New("private runtime directory is empty")
	}
	// validatePrivateParent validates every lexical ancestor and creates the
	// requested directory because it is the parent of this sentinel leaf.
	if err := validatePrivateParent(filepath.Join(path, ".runtime-dir-check")); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("private runtime path is not a non-symlink directory: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return validatePrivateParent(filepath.Join(path, ".runtime-dir-check"))
}

func privateRuntimeBase(root, category string) (string, error) {
	if !privateRuntimeLeafRE.MatchString(category) {
		return "", errors.New("invalid private runtime category")
	}
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	if err := ensurePrivateRuntimeDirectory(rootAbs); err != nil {
		return "", fmt.Errorf("validate private client root: %w", err)
	}
	run := filepath.Join(rootAbs, "run")
	if err := ensurePrivateRuntimeDirectory(run); err != nil {
		return "", fmt.Errorf("validate private runtime root: %w", err)
	}
	base := filepath.Join(run, category)
	if err := ensurePrivateRuntimeDirectory(base); err != nil {
		return "", fmt.Errorf("validate private runtime category: %w", err)
	}
	return base, nil
}

func newPrivateRuntimeDir(root, category string) (string, error) {
	base, err := privateRuntimeBase(root, category)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(base, "session-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := ensurePrivateRuntimeDirectory(dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func writePrivateRuntimeFile(path string, body []byte) error {
	if len(body) == 0 || len(body) > maxPrivateStoreBytes {
		return fmt.Errorf("private runtime file %s is empty or oversized", filepath.Base(path))
	}
	if err := ensurePrivateRuntimeDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWritePrivate(path, body)
}
