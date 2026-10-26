//go:build !windows

package main

import (
	"errors"
	"os"
)

func openPrivateRuntimeForRead(path string, info os.FileInfo) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := privateRuntimeObjectUnchanged(file, info); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validatePrivateRuntimeOpenPermissions(file *os.File, info os.FileInfo) error {
	if err := privateRuntimeObjectUnchanged(file, info); err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	// Preserve the Unix runtime-file contract. Lexical directory containment is
	// checked separately; preparation creates each owned directory with 0700.
	if !opened.IsDir() && opened.Mode().Perm()&0o077 != 0 {
		return errors.New("private runtime file is not private")
	}
	return nil
}

func preparePrivateRuntimeDirectoryPermissions(path string, info os.FileInfo) error {
	file, err := openPrivateRuntimeForRead(path, info)
	if err != nil {
		return err
	}
	defer file.Close()
	if info.Mode().Perm()&0o077 != 0 {
		if err := file.Chmod(0o700); err != nil {
			return err
		}
	}
	return privateRuntimeObjectUnchanged(file, info)
}
