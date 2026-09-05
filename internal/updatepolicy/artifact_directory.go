package updatepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// EnsurePrivateArtifactDirectory creates or validates the one directory allowed
// to own staged update packages. Existing symlinks/non-directories and broad
// Unix permissions fail closed instead of redirecting verified packages into a
// foreign tree.
func EnsurePrivateArtifactDirectory(dir string) error {
	raw := strings.TrimSpace(dir)
	if raw == "" {
		return errors.New("update artifact directory is required")
	}
	dir = filepath.Clean(raw)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	before, err := os.Lstat(dir)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return errors.New("update artifact directory must be a real non-symlink directory")
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return errors.New("update artifact directory permissions must be private")
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	opened, statErr := f.Stat()
	_ = f.Close()
	if statErr != nil {
		return statErr
	}
	after, err := os.Lstat(dir)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return errors.New("update artifact directory identity changed during validation")
	}
	return nil
}

// ValidateOwnedArtifactPath binds durable update state back to the configured
// private staging directory and to DownloadArtifactDetailed's digest-prefixed
// filename convention. A corrupt state file therefore cannot make cleanup act
// on an unrelated same-digest file elsewhere on disk.
func ValidateOwnedArtifactPath(dir, path, digest string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := EnsurePrivateArtifactDirectory(dir); err != nil {
		return err
	}
	digest = strings.ToLower(strings.TrimSpace(digest))
	if !isHex(digest, 64) {
		return errors.New("owned update artifact requires a valid SHA-256 digest")
	}
	dirAbs, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(dirAbs, pathAbs)
	if err != nil || rel == "." || filepath.IsAbs(rel) || filepath.Dir(rel) != "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("staged update artifact is outside the configured private update directory")
	}
	prefix := digest[:16] + "-"
	if !strings.HasPrefix(strings.ToLower(filepath.Base(pathAbs)), prefix) {
		return errors.New("staged update artifact filename is not bound to its verified digest")
	}
	return nil
}
