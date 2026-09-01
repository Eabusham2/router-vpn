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
	for _, sha := range []string{s.InstalledSHA, s.AvailableSHA} {
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
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return State{}, err
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
func DownloadArtifact(ctx context.Context, client *http.Client, artifact Artifact, dir string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Minute}
	}
	if err := artifact.Validate(VerifyOptions{}); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	base := filepath.Base(strings.TrimSpace(mustURLPath(artifact.URL)))
	if base == "." || base == string(filepath.Separator) || base == "" {
		base = "router-vpn-update.bin"
	}
	base = sanitizeFilename(base)
	finalPath := filepath.Join(dir, strings.ToLower(artifact.SHA256[:16])+"-"+base)
	if info, err := os.Lstat(finalPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("unsafe existing artifact path")
		}
		if info.Size() == artifact.Size {
			ok, hashErr := fileMatchesSHA256(finalPath, artifact.SHA256)
			if hashErr == nil && ok {
				return finalPath, nil
			}
		}
		return "", errors.New("existing artifact does not match signed metadata")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifact server returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != artifact.Size {
		return "", errors.New("artifact Content-Length does not match signed size")
	}
	tmp, err := os.CreateTemp(dir, ".router-vpn-update-*")
	if err != nil {
		return "", err
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
		return "", err
	}
	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, artifact.Size+1))
	if copyErr != nil {
		_ = tmp.Close()
		return "", copyErr
	}
	if written != artifact.Size {
		_ = tmp.Close()
		return "", fmt.Errorf("artifact size mismatch: got %d want %d", written, artifact.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, artifact.SHA256) {
		_ = tmp.Close()
		return "", errors.New("artifact SHA-256 mismatch")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	stagedInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", err
	}
	cleanup = false
	adopted, err := os.Lstat(finalPath)
	if err != nil || adopted.Mode()&os.ModeSymlink != 0 || !adopted.Mode().IsRegular() || !os.SameFile(stagedInfo, adopted) {
		return "", errors.New("artifact adoption identity changed")
	}
	if err := syncDirectory(dir); err != nil {
		return "", err
	}
	return finalPath, nil
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
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
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
