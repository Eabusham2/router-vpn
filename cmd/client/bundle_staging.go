package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	clean, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	// Bundle import/deletion shares the same private-state root as routers.json.
	// Preserve the lexical path and reject every symlinked ancestor instead of
	// EvalSymlinks-resolving the path and silently writing through a redirect.
	if err := validatePrivateParent(filepath.Join(clean, ".bundle-root-check")); err != nil {
		return "", fmt.Errorf("validate client root: %w", err)
	}
	st, err := os.Lstat(clean)
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return "", errors.New("client root must be a non-symlink directory")
	}
	return clean, nil
}

func ensurePrivateDirectoryNoSymlink(path string) error {
	if err := validatePrivateParent(filepath.Join(path, ".bundle-dir-check")); err != nil {
		return err
	}
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
	if err := validatePrivateParent(filepath.Join(path, ".bundle-dir-check")); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return nil
}

func writeStagedBundleFile(path string, data []byte) error {
	if len(data) > maxBundleFileBytes {
		return fmt.Errorf("staged bundle file exceeds safety limit: %s", filepath.Base(path))
	}
	if err := validatePrivateParent(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := validatePrivateParent(path); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncBundleDirectory(path string) error {
	// Windows does not expose POSIX directory fsync semantics. File contents are
	// still flushed before adoption there; Unix additionally flushes staging
	// directory entries before the authoritative directory rename.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func syncBundleDirectoryBestEffort(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	if dir, err := os.Open(path); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
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
			if err := writeStagedBundleFile(path, data); err != nil {
				return err
			}
		}
		if err := syncBundleDirectory(dir); err != nil {
			return fmt.Errorf("sync staged mode directory %s: %w", mode, err)
		}
	}
	if err := syncBundleDirectory(s.profileDir); err != nil {
		return fmt.Errorf("sync staged router profile: %w", err)
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
	if err := ensurePrivateDirectoryNoSymlink(generated); err != nil {
		return err
	}
	// Re-flush the fully staged profile immediately before the rename. All
	// fallible durability work therefore occurs before the commit point.
	if err := syncBundleDirectory(s.profileDir); err != nil {
		return fmt.Errorf("sync staged profile before adoption: %w", err)
	}
	if err := os.Rename(s.profileDir, final); err != nil {
		return err
	}
	s.profileDir = ""
	// Rename is the commit point. A directory fsync is useful durability
	// reinforcement, but cannot be reported as a false failure after the profile
	// has already become authoritative and visible to the controller.
	syncBundleDirectoryBestEffort(generated)
	return nil
}

type stagedProfileDeletion struct {
	baseRoot  string
	generated string
	final     string
	holder    string
	tombstone string
	moved     bool
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
	if err := ensurePrivateDirectoryNoSymlink(s.generated); err != nil {
		return err
	}
	if err := os.Rename(s.tombstone, s.final); err != nil {
		return err
	}
	s.moved = false
	syncBundleDirectoryBestEffort(s.generated)
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
