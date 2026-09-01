package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultControllerURL = "http://127.0.0.1:8793"
	defaultTokenFile     = "/etc/router-vpn/setup-center.token"
	defaultInterval      = time.Hour
	defaultStartDelay    = 2 * time.Minute
	maxResponse          = 128 << 10
)

type updateState struct {
	Status    string `json:"status"`
	TargetSHA string `json:"target_sha"`
}

type statusResponse struct {
	OK         bool        `json:"ok"`
	Configured bool        `json:"configured"`
	CurrentSHA string      `json:"current_sha"`
	Busy       bool        `json:"busy"`
	State      updateState `json:"state"`
}

type checkResponse struct {
	OK  bool   `json:"ok"`
	SHA string `json:"sha"`
}

type autoUpdater struct {
	baseURL string
	token   string
	client  *http.Client
}

func envBool(name string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		// An invalid enable switch must never turn unattended production
		// updates on through the default-true fallback. Empty retains the
		// documented default; malformed explicit input fails closed.
		log.Printf("invalid %s=%q; automatic updates disabled", name, raw)
		return false
	}
}

func envDuration(name string, fallback, min, max time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < min || value > max {
		log.Printf("invalid %s=%q; using %s", name, raw, fallback)
		return fallback
	}
	return value
}

func validSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func readPrivateToken(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("update token is not a regular file")
	}
	if before.Mode().Perm()&0o077 != 0 {
		return "", errors.New("update token permissions are broader than 0600")
	}
	if before.Size() <= 0 || before.Size() > 64<<10 {
		return "", errors.New("update token size is unsafe")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !os.SameFile(before, opened) || !os.SameFile(opened, current) || current.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("update token changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil {
		return "", err
	}
	if len(body) > 64<<10 {
		return "", errors.New("update token is oversized")
	}
	after, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !os.SameFile(opened, after) || after.Size() != int64(len(body)) {
		return "", errors.New("update token changed while reading")
	}
	token := strings.TrimSpace(string(body))
	if len(token) < 32 {
		return "", errors.New("update token is too short")
	}
	return token, nil
}

func newUpdater() (*autoUpdater, error) {
	base := strings.TrimSpace(os.Getenv("ROUTER_VPN_UPDATE_CONTROLLER_URL"))
	if base == "" {
		base = defaultControllerURL
	}
	if base != defaultControllerURL {
		return nil, fmt.Errorf("automatic updater is restricted to %s", defaultControllerURL)
	}
	tokenFile := strings.TrimSpace(os.Getenv("ROUTER_VPN_ADMIN_TOKEN_FILE"))
	if tokenFile == "" {
		tokenFile = defaultTokenFile
	}
	token, err := readPrivateToken(tokenFile)
	if err != nil {
		return nil, err
	}
	return &autoUpdater{
		baseURL: base,
		token:   token,
		client: &http.Client{
			Timeout:   5 * time.Minute,
			Transport: &http.Transport{Proxy: nil},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("automatic updater redirects are forbidden")
			},
		},
	}, nil
}

func (u *autoUpdater) request(method, path string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, u.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+u.token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponse {
		return errors.New("update controller response is oversized")
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("update controller HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(out); err != nil {
			return err
		}
		var trailing json.RawMessage
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			return errors.New("update controller response contains trailing JSON")
		}
	}
	return nil
}

func (u *autoUpdater) status() (statusResponse, error) {
	var result statusResponse
	err := u.request(http.MethodGet, "/api/admin/update/status", nil, &result)
	return result, err
}

func (u *autoUpdater) latestVerified() (string, error) {
	var result checkResponse
	if err := u.request(http.MethodPost, "/api/admin/update/check", map[string]string{"sha": ""}, &result); err != nil {
		return "", err
	}
	sha := strings.ToLower(strings.TrimSpace(result.SHA))
	if !result.OK || !validSHA(sha) {
		return "", errors.New("update controller returned an invalid verified SHA")
	}
	return sha, nil
}

func (u *autoUpdater) apply(sha string) error {
	if !validSHA(sha) {
		return errors.New("automatic update target is not one exact SHA")
	}
	var result map[string]any
	return u.request(http.MethodPost, "/api/admin/update/apply", map[string]string{"sha": sha}, &result)
}

func (u *autoUpdater) cycle() {
	status, err := u.status()
	if err != nil {
		log.Printf("automatic update status: %v", err)
		return
	}
	if !status.OK || !status.Configured || status.Busy {
		return
	}
	current := strings.ToLower(strings.TrimSpace(status.CurrentSHA))
	if !validSHA(current) {
		log.Printf("automatic update skipped: current Portainer stack is not one exact verified SHA")
		return
	}
	latest, err := u.latestVerified()
	if err != nil {
		log.Printf("automatic update check: %v", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(current), []byte(latest)) == 1 {
		return
	}
	if status.State.Status == "failed" && status.State.TargetSHA == latest {
		log.Printf("automatic update skipped: exact target %s previously failed; waiting for a newer verified release", latest)
		return
	}
	log.Printf("automatic update: verified %s -> %s", current, latest)
	if err := u.apply(latest); err != nil {
		// The update-controller container is intentionally replaced last. A local
		// connection can therefore disappear after the durable finalizing state is
		// already committed. Restart reconciliation owns that boundary.
		log.Printf("automatic update apply returned: %v", err)
	}
}

func main() {
	if !envBool("ROUTER_VPN_AUTO_UPDATE", true) {
		log.Printf("Router VPN automatic exact-SHA updates are disabled")
		select {}
	}
	interval := envDuration("ROUTER_VPN_AUTO_UPDATE_INTERVAL", defaultInterval, 5*time.Minute, 24*time.Hour)
	startDelay := envDuration("ROUTER_VPN_AUTO_UPDATE_START_DELAY", defaultStartDelay, 15*time.Second, 30*time.Minute)
	updater, err := newUpdater()
	if err != nil {
		log.Fatalf("automatic updater configuration: %v", err)
	}
	log.Printf("Router VPN automatic exact-SHA updater enabled; first check in %s, interval %s", startDelay, interval)
	time.Sleep(startDelay)
	updater.cycle()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		updater.cycle()
	}
}
