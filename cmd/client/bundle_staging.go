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

type stagedBundle struct {
	root       string
	profileDir string
	files      int
	bytes      int64
}

func newStagedBundle(root, profileID string) (*stagedBundle, error) {
	if !validProfileID(profileID) {
		return nil, errors.New("invalid router profile id")
	}
	generated := filepath.Join(filepath.Clean(root), "generated")
	if err := os.MkdirAll(generated, 0o700); err != nil {
		return nil, err
	}
	stagingRoot := filepath.Join(filepath.Clean(root), ".bundle-staging")
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
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
	return &stagedBundle{root: tmp, profileDir: profileDir}, nil
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
			// Encoded length gives a cheap pre-decode upper bound and avoids allocating
			// huge input that cannot possibly fit the individual decoded-file limit.
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
	generated := filepath.Join(filepath.Clean(root), "generated")
	final := filepath.Join(generated, profileID)
	rel, err := filepath.Rel(generated, final)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("unsafe generated profile destination")
	}
	if _, err := os.Stat(final); err == nil {
		return errors.New("generated router profile destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(s.profileDir, final); err != nil {
		return err
	}
	// The profile was atomically moved out. Cleanup may now remove only the empty
	// per-import staging directory.
	s.profileDir = ""
	return nil
}
