// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Eabusham2/router-vpn/internal/updatepolicy"
)

// Portainer automatic updates are opt-in. The existing updater remains the
// authority for exact-SHA release gates, environment preservation, Prune=false,
// core health checks, rollback, and updater-last deployment. This scheduler
// only selects a signed exact-SHA target and submits it to that authority.
type rvAutoUpdateConfig struct {
	Enabled       bool
	ManifestURL   string
	PublicKey     ed25519.PublicKey
	Channel       string
	ApplyURL      string
	BearerToken   string
	InstalledSHA  string
	StatePath     string
	Interval      time.Duration
	InitialDelay  time.Duration
	RequestTimeout time.Duration
	AllowedHosts  []string
}

var rvAutoUpdateStartOnce sync.Once

func init() {
	if !rvEnvBool("ROUTER_VPN_PORTAINER_AUTO_UPDATE", false) {
		return
	}
	rvAutoUpdateStartOnce.Do(func() {
		go rvRunPortainerAutoUpdateFromEnvironment()
	})
}

func rvRunPortainerAutoUpdateFromEnvironment() {
	cfg, err := rvAutoUpdateConfigFromEnv()
	if err != nil {
		rvPersistAutoUpdateError(os.Getenv("ROUTER_VPN_PORTAINER_AUTO_UPDATE_STATE"), err)
		return
	}
	if cfg.InitialDelay > 0 {
		timer := time.NewTimer(cfg.InitialDelay + rvSecureJitter(minDuration(cfg.InitialDelay/4, 5*time.Minute)))
		<-timer.C
	}
	client := &http.Client{Timeout: cfg.RequestTimeout}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
		err := rvPortainerAutoUpdateOnce(ctx, client, cfg)
		cancel()
		if err != nil {
			rvPersistAutoUpdateError(cfg.StatePath, err)
		}
		wait := cfg.Interval + rvSecureJitter(minDuration(cfg.Interval/10, 30*time.Minute))
		timer := time.NewTimer(wait)
		<-timer.C
	}
}

func rvAutoUpdateConfigFromEnv() (rvAutoUpdateConfig, error) {
	cfg := rvAutoUpdateConfig{
		Enabled:        true,
		ManifestURL:    strings.TrimSpace(os.Getenv("ROUTER_VPN_UPDATE_MANIFEST_URL")),
		Channel:        strings.ToLower(strings.TrimSpace(rvEnvDefault("ROUTER_VPN_UPDATE_CHANNEL", "stable"))),
		ApplyURL:       strings.TrimSpace(rvEnvDefault("ROUTER_VPN_PORTAINER_UPDATE_URL", "http://127.0.0.1:8793/api/update")),
		StatePath:      strings.TrimSpace(rvEnvDefault("ROUTER_VPN_PORTAINER_AUTO_UPDATE_STATE", "/var/lib/router-vpn/portainer-auto-update.json")),
		Interval:       rvEnvDuration("ROUTER_VPN_UPDATE_INTERVAL", 6*time.Hour),
		InitialDelay:   rvEnvDuration("ROUTER_VPN_UPDATE_INITIAL_DELAY", 90*time.Second),
		RequestTimeout: rvEnvDuration("ROUTER_VPN_UPDATE_REQUEST_TIMEOUT", 2*time.Minute),
		AllowedHosts:   rvSplitCSV(os.Getenv("ROUTER_VPN_UPDATE_ALLOWED_HOSTS")),
	}
	if cfg.ManifestURL == "" {
		return cfg, errors.New("ROUTER_VPN_UPDATE_MANIFEST_URL is required when Portainer auto-update is enabled")
	}
	pubRaw := strings.TrimSpace(os.Getenv("ROUTER_VPN_UPDATE_PUBLIC_KEY"))
	if pubRaw == "" {
		pubRaw = strings.TrimSpace(rvReadSmallFile(os.Getenv("ROUTER_VPN_UPDATE_PUBLIC_KEY_FILE"), 4096))
	}
	decoded, err := base64.StdEncoding.DecodeString(pubRaw)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return cfg, errors.New("a valid base64 Ed25519 update public key is required")
	}
	cfg.PublicKey = ed25519.PublicKey(decoded)
	cfg.BearerToken = strings.TrimSpace(os.Getenv("ROUTER_VPN_PORTAINER_UPDATE_TOKEN"))
	if cfg.BearerToken == "" {
		cfg.BearerToken = strings.TrimSpace(rvReadSmallFile(rvEnvDefault("ROUTER_VPN_PORTAINER_UPDATE_TOKEN_FILE", "/run/secrets/setup-center-token"), 64<<10))
	}
	if cfg.BearerToken == "" {
		return cfg, errors.New("Portainer updater bearer token is required")
	}
	cfg.InstalledSHA = strings.ToLower(strings.TrimSpace(os.Getenv("ROUTER_VPN_CURRENT_SHA")))
	if cfg.InstalledSHA == "" {
		cfg.InstalledSHA = strings.ToLower(strings.TrimSpace(rvReadSmallFile(os.Getenv("ROUTER_VPN_CURRENT_SHA_FILE"), 4096)))
	}
	if !rvExactSHA(cfg.InstalledSHA) {
		return cfg, errors.New("current deployed exact SHA is required")
	}
	if cfg.Interval < 15*time.Minute {
		return cfg, errors.New("automatic update interval must be at least 15 minutes")
	}
	if cfg.RequestTimeout < 10*time.Second || cfg.RequestTimeout > 15*time.Minute {
		return cfg, errors.New("automatic update request timeout is outside the safe range")
	}
	if err := rvValidateLoopbackApplyURL(cfg.ApplyURL); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func rvPortainerAutoUpdateOnce(ctx context.Context, client *http.Client, cfg rvAutoUpdateConfig) error {
	if !cfg.Enabled {
		return nil
	}
	manifestRaw, err := rvFetchBounded(ctx, client, cfg.ManifestURL, updatepolicy.MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("fetch signed update manifest: %w", err)
	}
	manifest, err := updatepolicy.ParseAndVerify(manifestRaw, cfg.PublicKey, updatepolicy.VerifyOptions{
		AllowedChannels: []string{cfg.Channel},
		AllowedHosts:    cfg.AllowedHosts,
	})
	if err != nil {
		return fmt.Errorf("verify signed update manifest: %w", err)
	}
	state := updatepolicy.State{Schema: updatepolicy.SchemaV1, Channel: cfg.Channel, InstalledSHA: cfg.InstalledSHA}
	if previous, loadErr := updatepolicy.LoadState(cfg.StatePath); loadErr == nil {
		state = previous
		if state.Channel != cfg.Channel {
			return errors.New("saved auto-update channel does not match configured channel")
		}
	} else if !os.IsNotExist(loadErr) {
		return fmt.Errorf("load private auto-update state: %w", loadErr)
	}
	state.LastCheckedAt = time.Now().UTC()
	state.LastError = ""
	state.InstalledSHA = cfg.InstalledSHA
	if manifest.Sequence <= state.LastSequence || strings.EqualFold(manifest.CommitSHA, cfg.InstalledSHA) {
		return updatepolicy.SaveState(cfg.StatePath, state)
	}

	body, err := json.Marshal(map[string]string{
		"sha":        strings.ToLower(manifest.CommitSHA),
		"target_sha": strings.ToLower(manifest.CommitSHA),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ApplyURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("submit exact-SHA update: %w", err)
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		return fmt.Errorf("read updater response: %w", readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("updater rejected exact SHA with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	// A successful response means the authoritative updater accepted ownership.
	// It still owns health proof and rollback; this scheduler must not perform a
	// competing Portainer mutation or claim the deployment completed.
	state.LastSequence = manifest.Sequence
	state.AvailableSHA = strings.ToLower(manifest.CommitSHA)
	state.InstallPending = true
	state.LastCheckedAt = time.Now().UTC()
	return updatepolicy.SaveState(cfg.StatePath, state)
}

func rvPersistAutoUpdateError(path string, cause error) {
	if cause == nil {
		return
	}
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/router-vpn/portainer-auto-update.json"
	}
	state := updatepolicy.State{Schema: updatepolicy.SchemaV1, Channel: strings.ToLower(rvEnvDefault("ROUTER_VPN_UPDATE_CHANNEL", "stable"))}
	if old, err := updatepolicy.LoadState(path); err == nil {
		state = old
	}
	state.LastCheckedAt = time.Now().UTC()
	state.LastError = cause.Error()
	if len(state.LastError) > 4096 {
		state.LastError = state.LastError[:4096]
	}
	_ = updatepolicy.SaveState(path, state)
}

func rvFetchBounded(ctx context.Context, client *http.Client, rawURL string, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid fetch limit")
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("manifest URL must be an authenticated HTTPS URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > int64(limit) {
		return nil, errors.New("response exceeds maximum size")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > limit {
		return nil, errors.New("invalid response size")
	}
	return data, nil
}

func rvValidateLoopbackApplyURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid Portainer updater URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("Portainer updater URL must use HTTP or HTTPS")
	}
	host := u.Hostname()
	loopback := strings.EqualFold(host, "localhost")
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if !loopback {
		return errors.New("Portainer auto-update may call only a loopback updater")
	}
	return nil
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

func rvReadSmallFile(path string, max int64) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > max {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) > max {
		return ""
	}
	return string(data)
}

func rvEnvBool(name string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func rvEnvDuration(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func rvEnvDefault(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func rvSplitCSV(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func rvSecureJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0
	}
	return time.Duration(binary.LittleEndian.Uint64(raw[:]) % uint64(max))
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
