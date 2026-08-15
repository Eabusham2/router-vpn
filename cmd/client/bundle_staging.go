package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxBundleModes      = 64
	maxBundleFiles      = 4096
	maxBundleFileBytes  = 16 << 20
	maxBundleTotalBytes = 96 << 20
	maxBundleNameBytes  = 128
)

func safeBundleToken(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > maxBundleNameBytes {
		return false
	}
	if strings.ContainsAny(value, "/\\:\x00") {
		return false
	}
	return true
}

func canonicalBundleRoot(root string) (string, error) {
	clean := filepath.Clean(root)
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("resolve client root: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", errors.New("client root is not a directory")
	}
	return resolved, nil
}

func ensurePrivateDirectoryNoSymlink(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		st, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private bundle directory must not be a symlink: %s", filepath.Base(path))
	}
	if !st.IsDir() {
		return fmt.Errorf("private bundle path is not a directory: %s", filepath.Base(path))
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return nil
}

type stagedBundle struct {
	root       string
	baseRoot   string
	profileDir string
	files      int
	bytes      int64
}

func newStagedBundle(root, profileID string) (*stagedBundle, error) {
	if !validProfileID(profileID) {
		return nil, errors.New("invalid router profile id")
	}
	baseRoot, err := canonicalBundleRoot(root)
	if err != nil {
		return nil, err
	}
	generated := filepath.Join(baseRoot, "generated")
	if err := ensurePrivateDirectoryNoSymlink(generated); err != nil {
		return nil, err
	}
	stagingRoot := filepath.Join(baseRoot, ".bundle-staging")
	if err := ensurePrivateDirectoryNoSymlink(stagingRoot); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(stagingRoot, "import-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp, 0o700); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	profileDir := filepath.Join(tmp, profileID)
	if err := os.Mkdir(profileDir, 0o700); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	return &stagedBundle{root: tmp, baseRoot: baseRoot, profileDir: profileDir}, nil
}

func (s *stagedBundle) cleanup() {
	if s != nil && s.root != "" {
		_ = os.RemoveAll(s.root)
	}
}

func (s *stagedBundle) writeProfiles(profiles map[string]map[string]string) error {
	if len(profiles) > maxBundleModes {
		return fmt.Errorf("router bundle has too many mode directories: %d", len(profiles))
	}
	for mode, files := range profiles {
		if !safeBundleToken(mode) {
			return fmt.Errorf("invalid mode filename token %q", mode)
		}
		if len(files) > maxBundleFiles {
			return fmt.Errorf("router bundle mode %q has too many files", mode)
		}
		dir := filepath.Join(s.profileDir, mode)
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		for name, encoded := range files {
			if !safeBundleToken(name) {
				return fmt.Errorf("invalid profile filename token %q", name)
			}
			s.files++
			if s.files > maxBundleFiles {
				return fmt.Errorf("router bundle exceeds %d files", maxBundleFiles)
			}
			if len(encoded) > ((maxBundleFileBytes+2)/3)*4+8 {
				return fmt.Errorf("profile %s/%s exceeds the file size limit", mode, name)
			}
			data, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return fmt.Errorf("invalid base64 for %s/%s", mode, name)
			}
			if len(data) > maxBundleFileBytes {
				return fmt.Errorf("profile %s/%s exceeds the file size limit", mode, name)
			}
			s.bytes += int64(len(data))
			if s.bytes > maxBundleTotalBytes {
				return fmt.Errorf("router bundle exceeds the staged-byte limit")
			}
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return err
			}
			if err := os.Chmod(path, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *stagedBundle) commit(root, profileID string) error {
	if !validProfileID(profileID) {
		return errors.New("invalid router profile id")
	}
	baseRoot, err := canonicalBundleRoot(root)
	if err != nil {
		return err
	}
	if s == nil || s.baseRoot == "" || baseRoot != s.baseRoot {
		return errors.New("client root changed during staged bundle import")
	}
	generated := filepath.Join(baseRoot, "generated")
	if err := ensurePrivateDirectoryNoSymlink(generated); err != nil {
		return err
	}
	final := filepath.Join(generated, profileID)
	rel, err := filepath.Rel(generated, final)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("unsafe generated profile destination")
	}
	if st, err := os.Lstat(final); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("generated router profile destination is a symlink")
		}
		return errors.New("generated router profile destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(s.profileDir, final); err != nil {
		return err
	}
	s.profileDir = ""
	return nil
}

type stagedProfileDeletion struct {
	baseRoot   string
	generated  string
	final      string
	holder     string
	tombstone  string
	moved      bool
}

func stageGeneratedProfileDeletion(root, profileID string) (*stagedProfileDeletion, error) {
	if !validProfileID(profileID) {
		return nil, errors.New("invalid router profile id")
	}
	baseRoot, err := canonicalBundleRoot(root)
	if err != nil {
		return nil, err
	}
	generated := filepath.Join(baseRoot, "generated")
	if err := ensurePrivateDirectoryNoSymlink(generated); err != nil {
		return nil, err
	}
	final := filepath.Join(generated, profileID)
	rel, err := filepath.Rel(generated, final)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil, errors.New("unsafe generated profile deletion path")
	}
	stage := &stagedProfileDeletion{baseRoot: baseRoot, generated: generated, final: final}
	st, err := os.Lstat(final)
	if errors.Is(err, os.ErrNotExist) {
		return stage, nil
	}
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("generated router profile deletion target is a symlink")
	}
	if !st.IsDir() {
		return nil, errors.New("generated router profile deletion target is not a directory")
	}
	trashRoot := filepath.Join(baseRoot, ".bundle-trash")
	if err := ensurePrivateDirectoryNoSymlink(trashRoot); err != nil {
		return nil, err
	}
	holder, err := os.MkdirTemp(trashRoot, "delete-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(holder, 0o700); err != nil {
		_ = os.RemoveAll(holder)
		return nil, err
	}
	tombstone := filepath.Join(holder, "profile")
	// Re-check the parent immediately before the atomic move so a symlink swap
	// does not silently redirect a deletion outside the canonical client root.
	if err := ensurePrivateDirectoryNoSymlink(generated); err != nil {
		_ = os.RemoveAll(holder)
		return nil, err
	}
	if err := os.Rename(final, tombstone); err != nil {
		_ = os.RemoveAll(holder)
		return nil, err
	}
	stage.holder, stage.tombstone, stage.moved = holder, tombstone, true
	return stage, nil
}

func (s *stagedProfileDeletion) rollback() error {
	if s == nil || !s.moved {
		return nil
	}
	baseRoot, err := canonicalBundleRoot(s.baseRoot)
	if err != nil || baseRoot != s.baseRoot {
		return errors.New("client root changed during profile deletion rollback")
	}
	if err := ensurePrivateDirectoryNoSymlink(s.generated); err != nil {
		return err
	}
	if _, err := os.Lstat(s.final); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("profile deletion rollback destination already exists")
		}
		return err
	}
	if err := os.Rename(s.tombstone, s.final); err != nil {
		return err
	}
	s.moved = false
	return os.RemoveAll(s.holder)
}

func (s *stagedProfileDeletion) commitCleanup() error {
	if s == nil || !s.moved {
		return nil
	}
	if err := os.RemoveAll(s.holder); err != nil {
		return err
	}
	s.moved = false
	return nil
}
