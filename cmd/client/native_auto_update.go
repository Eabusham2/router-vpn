// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/updatepolicy"
)

const (
	rvNativeUpdateCheck    = "check"
	rvNativeUpdateDownload = "download"
)

type rvNativeUpdateConfig struct {
	Mode           string
	ManifestURL    string
	PublicKey      ed25519.PublicKey
	Channel        string
	Platform       string
	Arch           string
	Kind           string
	InstalledSHA   string
	StatePath      string
	DownloadDir    string
	RequestTimeout time.Duration
	AllowedHosts   []string
}

var rvNativeUpdateMu sync.Mutex

type rvNativeUpdateStatus struct {
	Configured          bool      `json:"configured"`
	Schema              int       `json:"schema"`
	Channel             string    `json:"channel"`
	Platform            string    `json:"platform"`
	Arch                string    `json:"arch"`
	Kind                string    `json:"kind"`
	InstalledSHA        string    `json:"installed_sha,omitempty"`
	AvailableSHA        string    `json:"available_sha,omitempty"`
	ArtifactPath        string    `json:"artifact_path,omitempty"`
	ArtifactSHA256      string    `json:"artifact_sha256,omitempty"`
	LastCheckedAt       time.Time `json:"last_checked_at,omitempty"`
	DownloadedAt        time.Time `json:"downloaded_at,omitempty"`
	InstallPending      bool      `json:"install_pending"`
	RequiresUserInstall bool      `json:"requires_user_install"`
	LastError           string    `json:"last_error,omitempty"`
}

func registerNativeUpdateRoutes(mux *http.ServeMux, a *app) {
	mux.HandleFunc("/api/update/native/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		if !rvNativeLoopbackRequest(r) {
			http.Error(w, "native update status is loopback-only", http.StatusForbidden)
			return
		}
		cfg, err := rvNativeUpdateConfigFromApp(a, rvNativeUpdateCheck)
		status := rvReadNativeUpdateStatus(cfg)
		if err != nil {
			status.Configured = false
			status.LastError = rvNativeErrorText(err)
		}
		rvNativeJSON(w, http.StatusOK, status)
	})
	register := func(path string, download bool) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST only", http.StatusMethodNotAllowed)
				return
			}
			if !rvNativeLoopbackMutation(r) {
				http.Error(w, "native update mutation requires the local native app", http.StatusForbidden)
				return
			}
			mode := rvNativeUpdateCheck
			if download {
				mode = rvNativeUpdateDownload
			}
			cfg, err := rvNativeUpdateConfigFromApp(a, mode)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			rvNativeUpdateMu.Lock()
			defer rvNativeUpdateMu.Unlock()
			ctx, cancel := context.WithTimeout(r.Context(), cfg.RequestTimeout)
			defer cancel()
			status, err := rvNativeUpdateOnce(ctx, cfg, download)
			if err != nil {
				rvPersistNativeUpdateError(cfg, err)
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			rvNativeJSON(w, http.StatusOK, status)
		})
	}
	register("/api/update/native/check", false)
	register("/api/update/native/download", true)
}

func rvNativeUpdateConfigFromApp(a *app, mode string) (rvNativeUpdateConfig, error) {
	base := "."
	if a != nil {
		if a.cfg.StateFile != "" {
			base = filepath.Dir(a.cfg.StateFile)
		} else if a.cfg.ProfilesFile != "" {
			base = filepath.Dir(a.cfg.ProfilesFile)
		}
	}
	cfg := rvNativeUpdateConfig{
		Mode:           mode,
		ManifestURL:    strings.TrimSpace(os.Getenv("ROUTER_VPN_UPDATE_MANIFEST_URL")),
		Channel:        strings.ToLower(rvEnv("ROUTER_VPN_UPDATE_CHANNEL", "stable")),
		Platform:       updatepolicy.NormalizePlatform(rvEnv("ROUTER_VPN_UPDATE_PLATFORM", runtime.GOOS)),
		Arch:           updatepolicy.NormalizeArch(rvEnv("ROUTER_VPN_UPDATE_ARCH", runtime.GOARCH)),
		Kind:           strings.ToLower(rvEnv("ROUTER_VPN_UPDATE_KIND", rvNativeDefaultKind())),
		InstalledSHA:   strings.ToLower(strings.TrimSpace(os.Getenv("ROUTER_VPN_SOURCE_SHA"))),
		StatePath:      rvEnv("ROUTER_VPN_NATIVE_UPDATE_STATE", filepath.Join(base, "native-update.json")),
		DownloadDir:    rvEnv("ROUTER_VPN_NATIVE_UPDATE_DIR", filepath.Join(base, "updates")),
		RequestTimeout: 2 * time.Minute,
		AllowedHosts:   rvCSV(os.Getenv("ROUTER_VPN_UPDATE_ALLOWED_HOSTS")),
	}
	if cfg.InstalledSHA == "" {
		cfg.InstalledSHA = rvPackagedSourceSHA(base)
	}
	key := strings.TrimSpace(os.Getenv("ROUTER_VPN_UPDATE_PUBLIC_KEY"))
	if key == "" {
		key = strings.TrimSpace(rvReadRegular(os.Getenv("ROUTER_VPN_UPDATE_PUBLIC_KEY_FILE"), 4096))
	}
	if key != "" {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return cfg, errors.New("a valid base64 Ed25519 update public key is required")
		}
		cfg.PublicKey = ed25519.PublicKey(decoded)
	}
	return cfg, rvValidateNativeUpdateConfig(cfg)
}

func rvValidateNativeUpdateConfig(cfg rvNativeUpdateConfig) error {
	if cfg.Mode != rvNativeUpdateCheck && cfg.Mode != rvNativeUpdateDownload {
		return errors.New("invalid native update mode")
	}
	if err := rvValidateManifestURL(cfg.ManifestURL); err != nil {
		return err
	}
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		return errors.New("signed update public key is not configured")
	}
	if cfg.Channel != "stable" && cfg.Channel != "beta" {
		return errors.New("native update channel must be stable or beta")
	}
	if !rvToken(cfg.Platform) || !rvToken(cfg.Arch) || !rvToken(cfg.Kind) {
		return errors.New("invalid native update platform, architecture, or kind")
	}
	if !rvExactSHA(cfg.InstalledSHA) {
		return errors.New("current package exact source SHA is unavailable")
	}
	if cfg.StatePath == "" || cfg.DownloadDir == "" {
		return errors.New("native update state and download paths are required")
	}
	if cfg.RequestTimeout < 5*time.Second || cfg.RequestTimeout > 15*time.Minute {
		return errors.New("native update request timeout is outside the safe range")
	}
	return nil
}

func rvClearNativeArtifact(state *updatepolicy.State) error {
	if state == nil {
		return errors.New("native update state is required")
	}
	path := strings.TrimSpace(state.ArtifactPath)
	digest := strings.ToLower(strings.TrimSpace(state.ArtifactSHA256))
	if path != "" {
		if digest == "" {
			return errors.New("staged native update is missing its verified digest")
		}
		if err := updatepolicy.RemoveVerifiedArtifact(path, digest); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	state.ArtifactPath, state.ArtifactSHA256 = "", ""
	state.DownloadedAt, state.InstallPending = time.Time{}, false
	return nil
}

func rvNativeUpdateOnce(ctx context.Context, cfg rvNativeUpdateConfig, download bool) (rvNativeUpdateStatus, error) {
	if err := rvValidateNativeUpdateConfig(cfg); err != nil {
		return rvStatus(cfg, updatepolicy.State{}), err
	}
	if download && rvNativeMobilePlatform(cfg.Platform) {
		return rvStatus(cfg, updatepolicy.State{}), errors.New("mobile updates remain under Android or Apple signed install control")
	}
	state := updatepolicy.State{Schema: updatepolicy.SchemaV1, Channel: cfg.Channel, InstalledSHA: strings.ToLower(cfg.InstalledSHA)}
	if old, err := updatepolicy.LoadState(cfg.StatePath); err == nil {
		state = old
		if !strings.EqualFold(state.Channel, cfg.Channel) {
			return rvStatus(cfg, state), errors.New("saved native update channel does not match configured channel")
		}
	} else if !os.IsNotExist(err) {
		return rvStatus(cfg, state), fmt.Errorf("load private native update state: %w", err)
	}
	manifestClient := rvNativeManifestClient(cfg.RequestTimeout)
	raw, err := rvFetchManifest(ctx, manifestClient, cfg.ManifestURL)
	if err != nil {
		return rvStatus(cfg, state), fmt.Errorf("fetch signed native update manifest: %w", err)
	}
	manifest, err := updatepolicy.ParseAndVerify(raw, cfg.PublicKey, updatepolicy.VerifyOptions{
		AllowedChannels: []string{cfg.Channel}, AllowedHosts: cfg.AllowedHosts,
	})
	if err != nil {
		return rvStatus(cfg, state), fmt.Errorf("verify signed native update manifest: %w", err)
	}
	if manifest.Sequence < state.LastSequence {
		return rvStatus(cfg, state), errors.New("signed native update manifest rolled back to an older sequence")
	}
	if manifest.Sequence == state.LastSequence {
		observed := state.LastManifestSHA
		if observed == "" {
			observed = state.AvailableSHA
		}
		if observed != "" && !strings.EqualFold(observed, manifest.CommitSHA) {
			return rvStatus(cfg, state), errors.New("signed native update sequence changed target identity")
		}
	}
	now := time.Now().UTC()
	state.Schema, state.Channel, state.InstalledSHA = updatepolicy.SchemaV1, cfg.Channel, strings.ToLower(cfg.InstalledSHA)
	state.LastCheckedAt, state.LastError = now, ""
	if manifest.Sequence > state.LastSequence {
		state.LastSequence = manifest.Sequence
	}
	state.LastManifestSHA = strings.ToLower(manifest.CommitSHA)
	if strings.EqualFold(manifest.CommitSHA, cfg.InstalledSHA) {
		if err := rvClearNativeArtifact(&state); err != nil {
			return rvStatus(cfg, state), fmt.Errorf("remove obsolete staged native update: %w", err)
		}
		state.AvailableSHA = ""
		return rvSaveNativeStatus(cfg, state, "persist current native update state")
	}
	artifact, err := manifest.SelectArtifact(cfg.Platform, cfg.Arch, cfg.Kind)
	if err != nil {
		return rvStatus(cfg, state), err
	}
	previousTarget := state.AvailableSHA
	state.AvailableSHA = strings.ToLower(manifest.CommitSHA)
	if !download {
		if state.ArtifactPath != "" && !strings.EqualFold(previousTarget, manifest.CommitSHA) {
			if err := rvClearNativeArtifact(&state); err != nil {
				return rvStatus(cfg, state), fmt.Errorf("remove superseded staged native update: %w", err)
			}
		}
		return rvSaveNativeStatus(cfg, state, "persist native update check")
	}
	artifactClient := rvNativeArtifactClient(cfg.RequestTimeout, cfg.AllowedHosts)
	downloaded, err := updatepolicy.DownloadArtifactDetailed(ctx, artifactClient, artifact, cfg.DownloadDir)
	if err != nil {
		return rvStatus(cfg, state), fmt.Errorf("stage verified native update: %w", err)
	}
	state.ArtifactPath, state.ArtifactSHA256 = downloaded.Path, strings.ToLower(artifact.SHA256)
	state.DownloadedAt, state.InstallPending = now, true
	status, saveErr := rvSaveNativeStatus(cfg, state, "persist staged native update")
	if saveErr == nil || !downloaded.Created {
		return status, saveErr
	}
	cleanupErr := updatepolicy.RemoveVerifiedArtifact(downloaded.Path, artifact.SHA256)
	if cleanupErr == nil || os.IsNotExist(cleanupErr) {
		state.ArtifactPath, state.ArtifactSHA256 = "", ""
		state.DownloadedAt, state.InstallPending = time.Time{}, false
		return rvStatus(cfg, state), saveErr
	}
	return status, fmt.Errorf("%v; cleanup newly staged native update: %w", saveErr, cleanupErr)
}

func rvSaveNativeStatus(cfg rvNativeUpdateConfig, state updatepolicy.State, label string) (rvNativeUpdateStatus, error) {
	if err := updatepolicy.SaveState(cfg.StatePath, state); err != nil {
		return rvStatus(cfg, state), fmt.Errorf("%s: %w", label, err)
	}
	return rvStatus(cfg, state), nil
}

func rvReadNativeUpdateStatus(cfg rvNativeUpdateConfig) rvNativeUpdateStatus {
	fallback := updatepolicy.State{Schema: updatepolicy.SchemaV1, Channel: cfg.Channel, InstalledSHA: strings.ToLower(cfg.InstalledSHA)}
	state, err := updatepolicy.LoadState(cfg.StatePath)
	if err == nil {
		return rvStatus(cfg, state)
	}
	status := rvStatus(cfg, fallback)
	if !os.IsNotExist(err) {
		status.LastError = rvNativeErrorText(fmt.Errorf("load private native update state: %w", err))
	}
	return status
}

func rvPersistNativeUpdateError(cfg rvNativeUpdateConfig, cause error) {
	if cause == nil || cfg.StatePath == "" {
		return
	}
	state := updatepolicy.State{Schema: updatepolicy.SchemaV1, Channel: cfg.Channel, InstalledSHA: strings.ToLower(cfg.InstalledSHA)}
	if old, err := updatepolicy.LoadState(cfg.StatePath); err == nil {
		state = old
	}
	state.Schema, state.InstalledSHA, state.LastCheckedAt = updatepolicy.SchemaV1, strings.ToLower(cfg.InstalledSHA), time.Now().UTC()
	if state.Channel == "" {
		state.Channel = cfg.Channel
	}
	state.LastError = rvNativeErrorText(cause)
	_ = updatepolicy.SaveState(cfg.StatePath, state)
}

func rvStatus(cfg rvNativeUpdateConfig, state updatepolicy.State) rvNativeUpdateStatus {
	return rvNativeUpdateStatus{
		Configured: len(cfg.PublicKey) == ed25519.PublicKeySize && cfg.ManifestURL != "" && rvExactSHA(cfg.InstalledSHA),
		Schema:     updatepolicy.SchemaV1, Channel: cfg.Channel, Platform: updatepolicy.NormalizePlatform(cfg.Platform),
		Arch: updatepolicy.NormalizeArch(cfg.Arch), Kind: cfg.Kind, InstalledSHA: state.InstalledSHA,
		AvailableSHA: state.AvailableSHA, ArtifactPath: state.ArtifactPath, ArtifactSHA256: state.ArtifactSHA256,
		LastCheckedAt: state.LastCheckedAt, DownloadedAt: state.DownloadedAt, InstallPending: state.InstallPending,
		RequiresUserInstall: state.InstallPending, LastError: state.LastError,
	}
}

func rvNativeMobilePlatform(platform string) bool {
	switch updatepolicy.NormalizePlatform(platform) {
	case "android", "ios", "ipados":
		return true
	default:
		return false
	}
}

func rvNativeLoopbackMutation(r *http.Request) bool {
	return r != nil && r.Header.Get("X-Router-VPN-Native-App") == "1" && rvNativeLoopbackRequest(r)
}

func rvNativeLoopbackRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
}

func rvFetchManifest(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	if err := rvValidateManifestURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "router-vpn-native-update/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest server returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > updatepolicy.MaxManifestBytes {
		return nil, errors.New("manifest exceeds maximum size")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, updatepolicy.MaxManifestBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > updatepolicy.MaxManifestBytes {
		return nil, errors.New("invalid manifest body")
	}
	return raw, nil
}

func rvNativeUpdateTransport() http.RoundTripper {
	transport := http.DefaultTransport
	if base, ok := transport.(*http.Transport); ok {
		clone := base.Clone()
		clone.Proxy = nil
		transport = clone
	}
	return transport
}

func rvNativeManifestClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout, Transport: rvNativeUpdateTransport(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("native update manifest redirects are forbidden")
		},
	}
}

func rvNativeArtifactClient(timeout time.Duration, allowedHosts []string) *http.Client {
	return &http.Client{
		Timeout: timeout, Transport: rvNativeUpdateTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 8 {
				return errors.New("too many native update artifact redirects")
			}
			if req.URL == nil || req.URL.User != nil || !strings.EqualFold(req.URL.Scheme, "https") {
				return errors.New("native update artifact redirect must remain authenticated HTTPS")
			}
			if len(allowedHosts) > 0 {
				allowed := false
				for _, host := range allowedHosts {
					if strings.EqualFold(strings.TrimSpace(host), req.URL.Hostname()) {
						allowed = true
						break
					}
				}
				if !allowed {
					return errors.New("native update artifact redirect host is not allowlisted")
				}
			}
			return nil
		},
	}
}

func rvValidateManifestURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return errors.New("native update manifest URL is malformed")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("native update manifest URL must use HTTPS")
	}
	path := strings.ToLower(u.EscapedPath())
	for _, moving := range []string{"/latest", "/refs/heads/main", "/archive/main", "latest.json", "latest.zip", "latest.tar"} {
		if strings.Contains(path, moving) {
			return errors.New("moving native update manifest URL is forbidden")
		}
	}
	return nil
}

func rvNativeDefaultKind() string {
	for _, name := range []string{"HOMEVPN_PORTABLE", "ROUTER_VPN_PORTABLE"} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "1", "true", "yes", "on", "enabled":
			return "portable"
		}
	}
	return "installed"
}

func rvPackagedSourceSHA(base string) string {
	var paths []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		paths = append(paths, filepath.Join(dir, "ROUTER-VPN-SOURCE.json"), filepath.Join(dir, "..", "ROUTER-VPN-SOURCE.json"), filepath.Join(dir, "..", "..", "ROUTER-VPN-SOURCE.json"))
	}
	paths = append(paths, filepath.Join(base, "ROUTER-VPN-SOURCE.json"))
	for _, path := range paths {
		raw := rvReadRegular(filepath.Clean(path), 512<<10)
		var source struct {
			Repository string `json:"repository"`
			SourceSHA  string `json:"source_sha"`
		}
		if raw != "" && json.Unmarshal([]byte(raw), &source) == nil && source.Repository == "Eabusham2/router-vpn" && rvExactSHA(source.SourceSHA) {
			return strings.ToLower(source.SourceSHA)
		}
	}
	return ""
}

func rvReadRegular(path string, limit int64) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || len(raw) == 0 || int64(len(raw)) > limit || !os.SameFile(opened, after) || after.Size() != int64(len(raw)) {
		return ""
	}
	return string(raw)
}

func rvExactSHA(v string) bool {
	if len(v) != 40 {
		return false
	}
	for _, r := range v {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func rvToken(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-_.", r) {
			continue
		}
		return false
	}
	return true
}

func rvEnv(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func rvCSV(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, value := range strings.Split(raw, ",") {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func rvNativeErrorText(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 4096 {
		value = value[:4096]
	}
	return value
}

func rvNativeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
