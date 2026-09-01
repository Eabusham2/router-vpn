// SPDX-License-Identifier: MIT
package updatepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxStateBytes = 256 << 10

// State is the durable, non-secret update state shared by automatic checks and
// the native Settings surfaces. It never stores administrator credentials.
type State struct {
	Schema          int       `json:"schema"`
	Channel         string    `json:"channel"`
	LastSequence    uint64    `json:"last_sequence"`
	LastManifestSHA string    `json:"last_manifest_sha,omitempty"`
	InstalledSHA    string    `json:"installed_sha,omitempty"`
	AvailableSHA    string    `json:"available_sha,omitempty"`
	ArtifactPath    string    `json:"artifact_path,omitempty"`
	ArtifactSHA256  string    `json:"artifact_sha256,omitempty"`
	LastCheckedAt   time.Time `json:"last_checked_at,omitempty"`
	DownloadedAt    time.Time `json:"downloaded_at,omitempty"`
	InstallPending  bool      `json:"install_pending"`
	LastError       string    `json:"last_error,omitempty"`
}

func (s State) Validate() error {
	if s.Schema != SchemaV1 {
		return fmt.Errorf("unsupported state schema %d", s.Schema)
	}
	if !validChannel(s.Channel, nil) {
		return errors.New("invalid update channel")
	}
	for _, sha := range []string{s.LastManifestSHA, s.InstalledSHA, s.AvailableSHA} {
		if sha != "" && !isHex(sha, 40) {
			return errors.New("invalid exact commit SHA in state")
		}
	}
	if s.ArtifactSHA256 != "" && !isHex(s.ArtifactSHA256, 64) {
		return errors.New("invalid artifact SHA-256 in state")
	}
	if len(s.LastError) > 4096 {
		return errors.New("state error message is too large")
	}
	return nil
}

// LoadState rejects symlinks, non-regular files, oversized files, permissive
// Unix modes, corrupt JSON, and unknown schemas.
func LoadState(path string) (State, error) {
	var s State
	info, err := os.Lstat(path)
	if err != nil {
		return s, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return s, errors.New("update state must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return s, errors.New("update state permissions must be private")
	}
	if info.Size() <= 0 || info.Size() > maxStateBytes {
		return s, errors.New("invalid update state size")
	}
	parentBefore, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentBefore.IsDir() || parentBefore.Mode()&os.ModeSymlink != 0 {
		return s, errors.New("update state parent must be a regular directory")
	}
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return State{}, err
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return State{}, errors.New("update state identity changed during open")
	}
	dec := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return State{}, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return State{}, errors.New("update state contains trailing data")
	}
	parentAfter, err := os.Lstat(filepath.Dir(path))
	if err != nil || !os.SameFile(parentBefore, parentAfter) {
		return State{}, errors.New("update state parent identity changed during read")
	}
	current, err = os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return State{}, errors.New("update state identity changed during read")
	}
	if err := s.Validate(); err != nil {
		return State{}, err
	}
	return s, nil
}

// SaveState publishes one private same-directory file. A failure before rename
// leaves the previous state untouched; after rename the exact staged inode is
// re-proved before success is reported.
func SaveState(path string, s State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Lstat(dir); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("update state directory is not a trusted directory")
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".router-vpn-update-state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	stagedInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("refusing to replace unsafe update state path")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	adopted, err := os.Lstat(path)
	if err != nil || adopted.Mode()&os.ModeSymlink != 0 || !adopted.Mode().IsRegular() || !os.SameFile(stagedInfo, adopted) {
		return errors.New("update state adoption identity changed")
	}
	return syncDirectory(dir)
}

// DownloadArtifact downloads exactly the signed number of bytes, verifies the
// signed SHA-256, and atomically adopts the staged package. It never executes
// or installs a package.
type DownloadResult struct {
	Path    string
	Created bool
}

func DownloadArtifact(ctx context.Context, client *http.Client, artifact Artifact, dir string) (string, error) {
	result, err := DownloadArtifactDetailed(ctx, client, artifact, dir)
	return result.Path, err
}

func DownloadArtifactDetailed(ctx context.Context, client *http.Client, artifact Artifact, dir string) (DownloadResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Minute}
	}
	if err := artifact.Validate(VerifyOptions{}); err != nil {
		return DownloadResult{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return DownloadResult{}, err
	}
	base := filepath.Base(strings.TrimSpace(mustURLPath(artifact.URL)))
	if base == "." || base == string(filepath.Separator) || base == "" {
		base = "router-vpn-update.bin"
	}
	base = sanitizeFilename(base)
	finalPath := filepath.Join(dir, strings.ToLower(artifact.SHA256[:16])+"-"+base)
	if info, err := os.Lstat(finalPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return DownloadResult{}, errors.New("unsafe existing artifact path")
		}
		if info.Size() == artifact.Size {
			ok, hashErr := fileMatchesSHA256(finalPath, artifact.SHA256)
			if hashErr == nil && ok {
				return DownloadResult{Path: finalPath}, nil
			}
		}
		return DownloadResult{}, errors.New("existing artifact does not match signed metadata")
	} else if !os.IsNotExist(err) {
		return DownloadResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return DownloadResult{}, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return DownloadResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("artifact server returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != artifact.Size {
		return DownloadResult{}, errors.New("artifact Content-Length does not match signed size")
	}
	tmp, err := os.CreateTemp(dir, ".router-vpn-update-*")
	if err != nil {
		return DownloadResult{}, err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return DownloadResult{}, err
	}
	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, artifact.Size+1))
	if copyErr != nil {
		_ = tmp.Close()
		return DownloadResult{}, copyErr
	}
	if written != artifact.Size {
		_ = tmp.Close()
		return DownloadResult{}, fmt.Errorf("artifact size mismatch: got %d want %d", written, artifact.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, artifact.SHA256) {
		_ = tmp.Close()
		return DownloadResult{}, errors.New("artifact SHA-256 mismatch")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return DownloadResult{}, err
	}
	stagedInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return DownloadResult{}, err
	}
	if err := tmp.Close(); err != nil {
		return DownloadResult{}, err
	}
	if err := adoptNoClobber(tmpPath, finalPath, stagedInfo); err != nil {
		if errors.Is(err, os.ErrExist) {
			if info, statErr := os.Lstat(finalPath); statErr == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() && info.Size() == artifact.Size {
				if ok, hashErr := fileMatchesSHA256(finalPath, artifact.SHA256); hashErr == nil && ok {
					return DownloadResult{Path: finalPath}, nil
				}
			}
		}
		return DownloadResult{}, err
	}
	cleanup = false
	if err := syncDirectory(dir); err != nil {
		return DownloadResult{}, err
	}
	return DownloadResult{Path: finalPath, Created: true}, nil
}

// adoptNoClobber publishes a staged regular file without replacing a path
// created by another actor after the caller's preflight. Unix uses a hard link
// in the same directory so EEXIST is atomic; Windows os.Rename already refuses
// to replace an existing destination. The exact staged inode is re-proved
// before the temporary name is discarded.
func adoptNoClobber(tmpPath, finalPath string, stagedInfo os.FileInfo) error {
	if stagedInfo == nil || !stagedInfo.Mode().IsRegular() || stagedInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("artifact staging identity is unsafe")
	}
	if runtime.GOOS == "windows" {
		if err := os.Rename(tmpPath, finalPath); err != nil {
			return err
		}
	} else {
		if err := os.Link(tmpPath, finalPath); err != nil {
			return err
		}
	}
	adopted, err := os.Lstat(finalPath)
	if err != nil || adopted.Mode()&os.ModeSymlink != 0 || !adopted.Mode().IsRegular() || !os.SameFile(stagedInfo, adopted) {
		return errors.New("artifact adoption identity changed")
	}
	if runtime.GOOS != "windows" {
		// The exact final inode is already committed. Failure to remove the
		// private temporary hard-link must not make callers roll state back
		// after disk has committed the verified package.
		_ = os.Remove(tmpPath)
	}
	return nil
}

// RemoveVerifiedArtifact deletes only the exact regular staged package that
// still matches the signed digest. A same-directory tombstone binds deletion to
// the verified inode; a concurrent replacement is restored rather than removed.
func RemoveVerifiedArtifact(path, want string) error {
	return removeVerifiedArtifact(path, want, nil)
}

func removeVerifiedArtifact(path, want string, beforeRename func()) error {
	path = filepath.Clean(path)
	want = strings.ToLower(strings.TrimSpace(want))
	if !isHex(want, 64) {
		return errors.New("verified artifact cleanup requires one SHA-256 digest")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.New("verified artifact cleanup requires a regular non-symlink file")
	}
	ok, err := fileMatchesSHA256(path, want)
	if err != nil || !ok {
		return errors.New("artifact no longer matches its verified digest")
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, current) {
		return errors.New("artifact identity changed before cleanup")
	}
	tombDir, err := os.MkdirTemp(filepath.Dir(path), ".router-vpn-update-remove-*")
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tombDir, 0o700); err != nil {
			_ = os.Remove(tombDir)
			return err
		}
	}
	tomb := filepath.Join(tombDir, "artifact")
	if beforeRename != nil {
		beforeRename()
	}
	if err := os.Rename(path, tomb); err != nil {
		_ = os.Remove(tombDir)
		return err
	}
	moved, err := os.Lstat(tomb)
	if err != nil {
		return fmt.Errorf("read artifact tombstone: %w", err)
	}
	restore := func(cause error) error {
		if restoreErr := restoreArtifactNoClobber(tomb, path, moved); restoreErr != nil {
			return fmt.Errorf("%v; artifact preserved at %s because restore failed: %w", cause, tomb, restoreErr)
		}
		_ = os.Remove(tombDir)
		return cause
	}
	if moved.Mode()&os.ModeSymlink != 0 || !moved.Mode().IsRegular() || !os.SameFile(before, moved) {
		return restore(errors.New("artifact identity changed during cleanup"))
	}
	ok, err = fileMatchesSHA256(tomb, want)
	if err != nil || !ok {
		return restore(errors.New("artifact content changed during cleanup"))
	}
	if err := os.Remove(tomb); err != nil {
		return restore(fmt.Errorf("remove verified artifact tombstone: %w", err))
	}
	// Deletion already committed. Directory cleanup is best effort so a harmless
	// empty private directory cannot produce a post-commit false failure.
	_ = os.Remove(tombDir)
	return nil
}

func restoreArtifactNoClobber(tomb, path string, moved os.FileInfo) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("original artifact path was recreated")
	} else if !os.IsNotExist(err) {
		return err
	}
	if runtime.GOOS == "windows" {
		return os.Rename(tomb, path)
	}
	if err := os.Link(tomb, path); err != nil {
		return err
	}
	restored, err := os.Lstat(path)
	if err != nil || !os.SameFile(moved, restored) {
		return errors.New("restored artifact identity changed")
	}
	if err := os.Remove(tomb); err != nil {
		return err
	}
	return nil
}

func syncDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func fileMatchesSHA256(path, want string) (bool, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > MaxArtifactBytes {
		return false, errors.New("artifact path is not one bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return false, err
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return false, errors.New("artifact identity changed while opening")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxArtifactBytes+1))
	if err != nil || n != opened.Size() || n > MaxArtifactBytes {
		return false, errors.New("artifact changed or exceeded its bound while hashing")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || after.Size() != n {
		return false, errors.New("artifact identity changed while hashing")
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want), nil
}

func sanitizeFilename(v string) string {
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" {
		return "router-vpn-update.bin"
	}
	if len(out) > 128 {
		out = out[:128]
	}
	return out
}

func mustURLPath(raw string) string {
	// Artifact.Validate already parsed and validated this URL. Avoid carrying a
	// second externally visible URL interpretation into the destination path.
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] == '/' {
			return raw[i+1:]
		}
	}
	return raw
}
