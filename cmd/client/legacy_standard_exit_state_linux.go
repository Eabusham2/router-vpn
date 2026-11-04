//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const legacyExitStateLimit = 256 << 10

// This is an original opened comparison file, never reconstructed ownership.
// Every named-state mutation is serialized with the Python helper's flock.
type legacyExitStateToken struct {
	file   *os.File
	info   os.FileInfo
	body   []byte
	absent bool
}

func (s *legacyExitStateToken) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	err := s.file.Close()
	if err == nil || errors.Is(err, os.ErrClosed) {
		s.file = nil
		return nil
	}
	return err
}
func legacyExitCaptureState(l *legacyExitMutationLease) (*legacyExitStateToken, error) {
	if err := l.Current(); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(l.run.Fd()), "kill-switch.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return &legacyExitStateToken{absent: true}, nil
	}
	if err != nil {
		return nil, err
	}
	s := &legacyExitStateToken{file: os.NewFile(uintptr(fd), "original-standard-protection-state")}
	failed := true
	defer func() {
		if failed {
			_ = s.Close()
		}
	}()
	s.info, err = s.file.Stat()
	if err != nil || !legacyExitPrivate(s.info, false) || s.info.Size() > legacyExitStateLimit {
		return nil, errors.New("standard protection state is not a bounded private original file")
	}
	s.body, err = io.ReadAll(io.LimitReader(s.file, legacyExitStateLimit+1))
	if err != nil || len(s.body) > legacyExitStateLimit {
		return nil, errors.Join(err, errors.New("standard protection state exceeded its bound"))
	}
	if err = s.Current(l); err != nil {
		return nil, err
	}
	failed = false
	return s, nil
}
func (s *legacyExitStateToken) Current(l *legacyExitMutationLease) error {
	if s == nil {
		return errors.New("standard protection has no captured saved-state comparison")
	}
	if err := l.Current(); err != nil {
		return err
	}
	named, err := os.Lstat(filepath.Join(l.rootPath, "run", "kill-switch.json"))
	if s.absent {
		if !errors.Is(err, os.ErrNotExist) {
			return errors.New("standard protection state appeared after captured absence")
		}
		return l.Current()
	}
	if err != nil || s.file == nil || !legacyExitPrivate(named, false) || !os.SameFile(named, s.info) {
		return errors.New("standard protection saved owner was replaced")
	}
	actual, err := s.file.Stat()
	if err != nil || !os.SameFile(actual, s.info) || actual.Size() != int64(len(s.body)) {
		return errors.New("standard protection original state inode changed")
	}
	current := make([]byte, len(s.body))
	n, err := s.file.ReadAt(current, 0)
	if err != nil && !errors.Is(err, io.EOF) || n != len(current) || !bytes.Equal(current, s.body) {
		return errors.New("standard protection original saved bytes changed")
	}
	return l.Current()
}
func legacyExitWriteState(ctx context.Context, l *legacyExitMutationLease, expected *legacyExitStateToken, body []byte) (*legacyExitStateToken, error) {
	if ctx == nil || ctx.Err() != nil || len(body) == 0 || len(body) > legacyExitStateLimit {
		return nil, errors.New("standard protection has no bounded live state commit")
	}
	if err := expected.Current(l); err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	leaf := ".standard-state-" + hex.EncodeToString(nonce[:])
	fd, err := syscall.Openat(int(l.run.Fd()), leaf, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), leaf)
	promoted := false
	defer func() {
		if !promoted {
			_ = file.Close()
			_ = syscall.Unlinkat(int(l.run.Fd()), leaf)
		}
	}()
	if n, err := file.Write(body); err != nil || n != len(body) {
		return nil, errors.Join(err, io.ErrShortWrite)
	}
	if err = file.Sync(); err != nil {
		return nil, err
	}
	if err = expected.Current(l); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = syscall.Renameat(int(l.run.Fd()), leaf, int(l.run.Fd()), "kill-switch.json"); err != nil {
		return nil, err
	}
	promoted = true
	info, err := file.Stat()
	result := &legacyExitStateToken{file: file, info: info, body: append([]byte(nil), body...)}
	if err != nil {
		return result, err
	}
	if err = result.Current(l); err != nil {
		return result, err
	}
	return result, l.run.Sync()
}
func legacyExitRemoveState(ctx context.Context, l *legacyExitMutationLease, expected *legacyExitStateToken) (bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return false, errors.New("standard protection removal exceeded original deadline")
	}
	if expected.absent {
		return false, expected.Current(l)
	}
	if err := expected.Current(l); err != nil {
		return false, err
	}
	if err := syscall.Unlinkat(int(l.run.Fd()), "kill-switch.json"); err != nil {
		return false, err
	}
	if err := l.run.Sync(); err != nil {
		return true, err
	}
	return true, legacyExitStateAbsent(l)
}
