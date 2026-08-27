package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultListen          = "127.0.0.1:8793"
	defaultPortainerURL    = "https://127.0.0.1:9443"
	defaultStackName       = "router-vpn"
	defaultRepo            = "Eabusham2/router-vpn"
	defaultBranch          = "main"
	defaultSetupTokenFile  = "/etc/router-vpn/setup-center.token"
	defaultPortainerKey    = "/etc/router-vpn/portainer-api.key"
	defaultPortainerPin    = "/etc/router-vpn/portainer-tls.sha256"
	defaultStatePath       = "/var/lib/router-vpn/update-controller.json"
	maxJSON                = 4 << 20
	maxCompose             = 2 << 20
)

var (
	shaRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	customImageRE = regexp.MustCompile(`(ghcr\.io/eabusham2/router-vpn-(?:init|agent|wireguard|awg2|rosenpass|naive|ss-v2ray|aux|updater):)([0-9a-f]{40})`)
	brokerSHARe = regexp.MustCompile(`(?m)^(\s*ROUTER_VPN_GITHUB_SHA:\s*)([0-9a-f]{40})(\s*)$`)
	requiredReleaseWorkflows = []string{
		"release-candidate.yml",
		"arm64-portainer-preflight.yml",
		"publish-arm64-images.yml",
		"production-release-compose.yml",
	}
	ownedImageRE = regexp.MustCompile(`ghcr\.io/eabusham2/(router-vpn-[a-z0-9-]+):([^\s]+)`)
	requiredCustomImageRepos = []string{
		"router-vpn-init",
		"router-vpn-agent",
		"router-vpn-wireguard",
		"router-vpn-awg2",
		"router-vpn-rosenpass",
		"router-vpn-naive",
		"router-vpn-ss-v2ray",
		"router-vpn-aux",
		"router-vpn-updater",
	}
)

type updateState struct {
	Version       int    `json:"version"`
	Status        string `json:"status"`
	FromSHA       string `json:"from_sha,omitempty"`
	TargetSHA     string `json:"target_sha,omitempty"`
	Message       string `json:"message,omitempty"`
	UpdatedAt     int64  `json:"updated_at"`
}

type controller struct {
	setupToken       string
	listen           string
	portainerURL     *url.URL
	portainerKeyFile string
	portainerPinFile string
	stackName        string
	repo             string
	branch           string
	statePath        string
	mu               sync.Mutex
	state            updateState
}

type stackInfo struct {
	ID         int             `json:"Id"`
	EndpointID int             `json:"EndpointId"`
	Name       string          `json:"Name"`
	Status     int             `json:"Status"`
	Env        json.RawMessage `json:"Env"`
}

type workflowRuns struct {
	Runs []struct {
		ID         int64  `json:"id"`
		HeadSHA    string `json:"head_sha"`
		HeadBranch string `json:"head_branch"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		CreatedAt  string `json:"created_at"`
	} `json:"workflow_runs"`
}

func env(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

func readSecret(path string, min int) (string, error) {
	b, err := readUpdaterPrivate(path, 64<<10)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if len(v) < min {
		return "", fmt.Errorf("%s is empty or too short", path)
	}
	return v, nil
}

func loadController() (*controller, error) {
	setupToken, err := readSecret(env("ROUTER_VPN_ADMIN_TOKEN_FILE", defaultSetupTokenFile), 32)
	if err != nil {
		return nil, fmt.Errorf("setup token: %w", err)
	}
	listen := env("ROUTER_VPN_UPDATE_LISTEN", defaultListen)
	host, _, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("update controller listen must be a literal loopback address")
	}
	purl, err := url.Parse(env("ROUTER_VPN_PORTAINER_URL", defaultPortainerURL))
	if err != nil || purl.Scheme != "https" || purl.Hostname() == "" || purl.Path != "" || purl.RawQuery != "" || purl.Fragment != "" {
		return nil, errors.New("Portainer URL must be an HTTPS origin")
	}
	pip := net.ParseIP(purl.Hostname())
	if pip == nil || !pip.IsLoopback() {
		return nil, errors.New("Portainer Update is restricted to a loopback Portainer origin")
	}
	c := &controller{
		setupToken:       setupToken,
		listen:           listen,
		portainerURL:     purl,
		portainerKeyFile: env("ROUTER_VPN_PORTAINER_API_KEY_FILE", defaultPortainerKey),
		portainerPinFile: env("ROUTER_VPN_PORTAINER_TLS_PIN_FILE", defaultPortainerPin),
		stackName:        env("ROUTER_VPN_PORTAINER_STACK", defaultStackName),
		repo:             env("ROUTER_VPN_GITHUB_REPO", defaultRepo),
		branch:           env("ROUTER_VPN_GITHUB_BRANCH", defaultBranch),
		statePath:        env("ROUTER_VPN_UPDATE_STATE", defaultStatePath),
		state:            updateState{Version: 1, Status: "idle"},
	}
	if strings.Count(c.repo, "/") != 1 || strings.ContainsAny(c.repo, " \\?#") {
		return nil, errors.New("invalid GitHub repository")
	}
	if err := c.loadState(); err != nil {
		return nil, fmt.Errorf("load update recovery state: %w", err)
	}
	return c, nil
}

func validUpdateStatus(status string) bool {
	switch status {
	case "idle", "applying", "finalizing", "rolling-back", "failed", "complete":
		return true
	default:
		return false
	}
}

func validateUpdateState(s updateState) error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported update state version %d", s.Version)
	}
	if !validUpdateStatus(s.Status) {
		return fmt.Errorf("unsupported update state status %q", s.Status)
	}
	if s.FromSHA != "" && !shaRE.MatchString(s.FromSHA) {
		return errors.New("update state contains invalid from_sha")
	}
	if s.TargetSHA != "" && !shaRE.MatchString(s.TargetSHA) {
		return errors.New("update state contains invalid target_sha")
	}

	// Status is part of the durable recovery protocol, not presentation metadata.
	// Reject impossible status/SHA combinations so a truncated/manual/corrupt
	// state file cannot make restart reconciliation guess which mutation boundary
	// had been crossed.
	switch s.Status {
	case "idle":
		if s.FromSHA != "" || s.TargetSHA != "" {
			return errors.New("idle update state may not retain release SHAs")
		}
	case "applying":
		if s.TargetSHA == "" {
			return errors.New("applying update state requires target_sha")
		}
		// from_sha is intentionally optional only for the first pre-deployment
		// applying checkpoint, before the current exact stack is discovered.
	case "finalizing", "rolling-back", "complete":
		if s.FromSHA == "" || s.TargetSHA == "" {
			return fmt.Errorf("%s update state requires exact from_sha and target_sha", s.Status)
		}
	case "failed":
		// A failure before stack discovery legitimately has no from_sha, but the
		// requested exact target must always remain attributable.
		if s.TargetSHA == "" {
			return errors.New("failed update state requires target_sha")
		}
	}
	return nil
}

func (c *controller) loadState() error {
	b, err := readUpdaterPrivate(c.statePath, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state updateState
	if err := json.Unmarshal(b, &state); err != nil {
		return err
	}
	if err := validateUpdateState(state); err != nil {
		return err
	}
	c.state = state
	return nil
}

func (c *controller) persistStateLocked(status, from, target, message string) error {
	next := updateState{Version: 1, Status: status, FromSHA: from, TargetSHA: target, Message: message, UpdatedAt: time.Now().Unix()}
	if err := validateUpdateState(next); err != nil {
		return err
	}
	body, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteUpdaterPrivate(c.statePath, append(body, '\n')); err != nil {
		return err
	}
	c.state = next
	return nil
}

func (c *controller) authorized(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.setupToken)) == 1
}

func (c *controller) require(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !c.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (c *controller) configured() (bool, string) {
	if _, err := readSecret(c.portainerKeyFile, 16); err != nil {
		return false, "Portainer API key is not configured server-side"
	}
	pin, err := readSecret(c.portainerPinFile, 64)
	if err != nil || len(pin) != 64 {
		return false, "Portainer TLS certificate fingerprint is not configured server-side"
	}
	if _, err := hex.DecodeString(strings.ToLower(pin)); err != nil {
		return false, "Portainer TLS certificate fingerprint is invalid"
	}
	return true, ""
}

func (c *controller) portainerClient() (*http.Client, string, error) {
	key, err := readSecret(c.portainerKeyFile, 16)
	if err != nil {
		return nil, "", err
	}
	pin, err := readSecret(c.portainerPinFile, 64)
	if err != nil {
		return nil, "", err
	}
	pin = strings.ToLower(pin)
	if len(pin) != 64 {
		return nil, "", errors.New("invalid Portainer TLS fingerprint length")
	}
	if _, err := hex.DecodeString(pin); err != nil {
		return nil, "", errors.New("invalid Portainer TLS fingerprint")
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("Portainer returned no TLS certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
				return errors.New("Portainer TLS certificate fingerprint changed")
			}
			return nil
		},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	return &http.Client{Transport: transport, Timeout: 90 * time.Second}, key, nil
}

func (c *controller) portainer(method, path string, body any, out any) error {
	client, key, err := c.portainerClient()
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(b) > maxCompose+maxJSON {
			return errors.New("Portainer request exceeds safety limit")
		}
		reader = bytes.NewReader(b)
	}
	endpoint := strings.TrimRight(c.portainerURL.String(), "/") + path
	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCompose+maxJSON+1))
	if err != nil {
		return err
	}
	if len(raw) > maxCompose+maxJSON {
		return errors.New("Portainer response exceeds safety limit")
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Portainer %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode Portainer response: %w", err)
		}
	}
	return nil
}

func githubHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "router-vpn-update-controller/1")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func githubJSON(endpoint string, out any) error {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	githubHeaders(req)
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJSON+1))
	if err != nil {
		return err
	}
	if len(raw) > maxJSON {
		return errors.New("GitHub response exceeds safety limit")
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GitHub HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(raw, out)
}

func githubText(endpoint string, limit int64) (string, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	githubHeaders(req)
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > limit {
		return "", errors.New("GitHub file exceeds safety limit")
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("GitHub file HTTP %d", resp.StatusCode)
	}
	return string(raw), nil
}

func (c *controller) workflowSuccess(file, sha string) (bool, error) {
	if !shaRE.MatchString(sha) {
		return false, errors.New("invalid SHA")
	}
	q := url.Values{"branch": {c.branch}, "status": {"success"}, "head_sha": {sha}, "per_page": {"20"}}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/actions/workflows/%s/runs?%s", c.repo, url.PathEscape(file), q.Encode())
	var runs workflowRuns
	if err := githubJSON(endpoint, &runs); err != nil {
		return false, err
	}
	for _, run := range runs.Runs {
		if strings.ToLower(run.HeadSHA) == sha && run.HeadBranch == c.branch && run.Status == "completed" && run.Conclusion == "success" {
			return true, nil
		}
	}
	return false, nil
}

func (c *controller) verifiedTarget(sha string) error {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !shaRE.MatchString(sha) {
		return errors.New("target must be a lowercase full 40-character commit SHA")
	}
	for _, workflow := range requiredReleaseWorkflows {
		ok, err := c.workflowSuccess(workflow, sha)
		if err != nil {
			return fmt.Errorf("verify %s: %w", workflow, err)
		}
		if !ok {
			return fmt.Errorf("%s has no successful exact-SHA %s run", sha, workflow)
		}
	}
	return nil
}

func (c *controller) latestVerified() (string, error) {
	q := url.Values{"branch": {c.branch}, "status": {"success"}, "per_page": {"30"}}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/actions/workflows/release-candidate.yml/runs?%s", c.repo, q.Encode())
	var runs workflowRuns
	if err := githubJSON(endpoint, &runs); err != nil {
		return "", err
	}
	seen := map[string]bool{}
	for _, run := range runs.Runs {
		sha := strings.ToLower(run.HeadSHA)
		if seen[sha] || !shaRE.MatchString(sha) || run.HeadBranch != c.branch || run.Status != "completed" || run.Conclusion != "success" {
			continue
		}
		seen[sha] = true
		if err := c.verifiedTarget(sha); err == nil {
			return sha, nil
		}
	}
	return "", errors.New("no recent exact-SHA release has all required green workflows")
}

func ownedImageSHAs(content string) (map[string]string, error) {
	seen := map[string]string{}
	allowed := map[string]bool{}
	for _, repo := range requiredCustomImageRepos {
		allowed[repo] = true
	}
	for _, match := range ownedImageRE.FindAllStringSubmatch(content, -1) {
		repo, tag := match[1], match[2]
		if !allowed[repo] {
			return nil, fmt.Errorf("production compose contains unrecognized Router VPN image %s", repo)
		}
		if !shaRE.MatchString(tag) {
			return nil, fmt.Errorf("production compose Router VPN image %s is not pinned to a full SHA", repo)
		}
		if prior, ok := seen[repo]; ok && prior != tag {
			return nil, fmt.Errorf("production compose image %s has mixed SHAs", repo)
		}
		seen[repo] = tag
	}
	for _, repo := range requiredCustomImageRepos {
		if seen[repo] == "" {
			return nil, fmt.Errorf("production compose is missing required Router VPN image %s", repo)
		}
	}
	return seen, nil
}

func validateAndMaterializeTemplate(text, target string) (string, error) {
	if !shaRE.MatchString(target) {
		return "", errors.New("invalid target SHA")
	}
	if len(text) == 0 || len(text) > maxCompose {
		return "", errors.New("production compose baseline size is invalid")
	}
	for _, forbidden := range []string{"\nbuild:\n", "\n    build:", ":latest", "- /var/run/docker.sock"} {
		if strings.Contains(text, forbidden) {
			return "", fmt.Errorf("production compose contains forbidden marker %q", forbidden)
		}
	}
	if _, err := ownedImageSHAs(text); err != nil {
		return "", err
	}
	if !strings.Contains(text, "router-vpn-updater:") {
		return "", errors.New("target release does not contain the rollback-safe update controller service")
	}
	out := customImageRE.ReplaceAllString(text, `${1}`+target)
	if brokerSHARe.MatchString(out) {
		out = brokerSHARe.ReplaceAllString(out, `${1}`+target+`${3}`)
	} else {
		return "", errors.New("production compose broker provenance SHA is missing")
	}
	images, err := ownedImageSHAs(out)
	if err != nil {
		return "", err
	}
	for repo, imageSHA := range images {
		if imageSHA != target {
			return "", fmt.Errorf("materialized compose image %s contains non-target SHA", repo)
		}
	}
	if !strings.Contains(out, "ROUTER_VPN_GITHUB_SHA: "+target) {
		return "", errors.New("materialized compose broker SHA mismatch")
	}
	header := "# GENERATED exact-SHA Router VPN production compose: " + target + "\n# Update controller verified RC + ARM64 Portainer preflight + ARM64 image publication + production compose before materialization.\n"
	return header + out, nil
}

func (c *controller) targetCompose(sha string) (string, error) {
	if err := c.verifiedTarget(sha); err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/server/portainer-current.yaml", c.repo, sha)
	baseline, err := githubText(endpoint, maxCompose)
	if err != nil {
		return "", err
	}
	return validateAndMaterializeTemplate(baseline, sha)
}

func stackEnvironment(raw json.RawMessage) ([]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("Portainer did not return stack environment; refusing to replace it with an empty environment")
	}
	if len(trimmed) > maxJSON {
		return nil, errors.New("Portainer stack environment exceeds safety limit")
	}
	var values []any
	if err := json.Unmarshal(trimmed, &values); err != nil {
		return nil, fmt.Errorf("decode Portainer stack environment: %w", err)
	}
	if values == nil {
		return nil, errors.New("Portainer stack environment is null")
	}
	return values, nil
}

func (c *controller) findStack() (stackInfo, error) {
	var stacks []stackInfo
	if err := c.portainer(http.MethodGet, "/api/stacks", nil, &stacks); err != nil {
		return stackInfo{}, err
	}
	var matches []stackInfo
	for _, stack := range stacks {
		if stack.Name == c.stackName {
			matches = append(matches, stack)
		}
	}
	if len(matches) != 1 {
		return stackInfo{}, fmt.Errorf("expected one Portainer stack named %q, found %d", c.stackName, len(matches))
	}
	selected := matches[0]
	if selected.ID <= 0 || selected.EndpointID <= 0 {
		return stackInfo{}, errors.New("Portainer stack has invalid ID/environment")
	}
	var detail stackInfo
	if err := c.portainer(http.MethodGet, fmt.Sprintf("/api/stacks/%d", selected.ID), nil, &detail); err != nil {
		return stackInfo{}, fmt.Errorf("read Portainer stack details: %w", err)
	}
	if detail.ID != 0 && detail.ID != selected.ID {
		return stackInfo{}, errors.New("Portainer stack detail ID changed during lookup")
	}
	if detail.Name != "" && detail.Name != c.stackName {
		return stackInfo{}, errors.New("Portainer stack detail name changed during lookup")
	}
	if len(bytes.TrimSpace(detail.Env)) > 0 {
		selected.Env = detail.Env
	}
	if _, err := stackEnvironment(selected.Env); err != nil {
		return stackInfo{}, err
	}
	return selected, nil
}

func (c *controller) stackFile(stack stackInfo) (string, error) {
	var payload struct {
		StackFileContent string `json:"StackFileContent"`
	}
	if err := c.portainer(http.MethodGet, fmt.Sprintf("/api/stacks/%d/file", stack.ID), nil, &payload); err != nil {
		return "", err
	}
	if payload.StackFileContent == "" || len(payload.StackFileContent) > maxCompose {
		return "", errors.New("Portainer returned an empty/oversized stack file")
	}
	return payload.StackFileContent, nil
}

func (c *controller) putStack(stack stackInfo, content string) error {
	if len(content) == 0 || len(content) > maxCompose {
		return errors.New("refusing invalid stack content")
	}
	environment, err := stackEnvironment(stack.Env)
	if err != nil {
		return err
	}
	payload := map[string]any{"StackFileContent": content, "Env": environment, "PullImage": true, "Prune": false}
	path := fmt.Sprintf("/api/stacks/%d?endpointId=%d", stack.ID, stack.EndpointID)
	return c.portainer(http.MethodPut, path, payload, nil)
}

func extractUpdaterImage(content string) (string, error) {
	re := regexp.MustCompile(`ghcr\.io/eabusham2/router-vpn-updater:[0-9a-f]{40}`)
	matches := re.FindAllString(content, -1)
	if len(matches) != 1 {
		return "", fmt.Errorf("expected one updater image in current stack, found %d", len(matches))
	}
	return matches[0], nil
}

func preserveUpdater(target, current string) (string, error) {
	oldImage, err := extractUpdaterImage(current)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`ghcr\.io/eabusham2/router-vpn-updater:[0-9a-f]{40}`)
	if len(re.FindAllString(target, -1)) != 1 {
		return "", errors.New("target compose has invalid updater image count")
	}
	return re.ReplaceAllString(target, oldImage), nil
}

func composeSHA(content string) string {
	images, err := ownedImageSHAs(content)
	if err != nil {
		return "unknown"
	}
	values := map[string]bool{}
	for _, imageSHA := range images {
		values[imageSHA] = true
	}
	if len(values) != 1 {
		return "unknown"
	}
	var imageSHA string
	for sha := range values {
		imageSHA = sha
	}
	header := regexp.MustCompile(`(?m)^# GENERATED exact-SHA Router VPN production compose: ([0-9a-f]{40})$`).FindStringSubmatch(content)
	if len(header) == 2 && header[1] != imageSHA {
		return "unknown"
	}
	broker := brokerSHARe.FindStringSubmatch(content)
	if len(broker) == 4 && broker[2] != imageSHA {
		return "unknown"
	}
	return imageSHA
}

func (c *controller) containerState(stack stackInfo, name string) (bool, int, error) {
	var payload struct {
		State struct {
			Running  bool   `json:"Running"`
			ExitCode int    `json:"ExitCode"`
			Status   string `json:"Status"`
		} `json:"State"`
	}
	path := fmt.Sprintf("/api/endpoints/%d/docker/containers/%s/json", stack.EndpointID, url.PathEscape(name))
	if err := c.portainer(http.MethodGet, path, nil, &payload); err != nil {
		return false, -1, err
	}
	return payload.State.Running, payload.State.ExitCode, nil
}

func localHealth(endpoint string) bool {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(endpoint)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode/100 == 2
}

func (c *controller) waitCoreHealthy(stack stackInfo, timeout time.Duration) error {
	longRunning := []string{"router-vpn-agent", "router-vpn-wireguard", "router-vpn-awg2", "router-vpn-rosenpass", "router-vpn-transports", "router-vpn-xray", "router-vpn-naive", "router-vpn-ss-v2ray", "router-vpn-aux", "router-vpn-bundle-web", "router-vpn-socks5", "router-vpn-updater"}
	oneShot := []string{"router-vpn-init", "router-vpn-finalize"}
	deadline := time.Now().Add(timeout)
	var problems []string
	for time.Now().Before(deadline) {
		problems = problems[:0]
		for _, name := range longRunning {
			running, exit, err := c.containerState(stack, name)
			if err != nil || !running {
				problems = append(problems, fmt.Sprintf("%s not running (exit=%d)", name, exit))
			}
		}
		for _, name := range oneShot {
			running, exit, err := c.containerState(stack, name)
			if err != nil || running || exit != 0 {
				problems = append(problems, fmt.Sprintf("%s not completed successfully (running=%t exit=%d)", name, running, exit))
			}
		}
		if len(problems) == 0 && localHealth("http://127.0.0.1:8786/healthz") && localHealth("http://127.0.0.1:8787/health") {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	sort.Strings(problems)
	return fmt.Errorf("updated stack failed health verification: %s", strings.Join(problems, "; "))
}

func (c *controller) status(w http.ResponseWriter, r *http.Request) {
	if !c.require(w, r, http.MethodGet) {
		return
	}
	configured, reason := c.configured()
	c.mu.Lock()
	state := c.state
	busy := state.Status == "applying" || state.Status == "finalizing" || state.Status == "rolling-back"
	c.mu.Unlock()
	current := "unknown"
	if configured {
		if stack, err := c.findStack(); err == nil {
			if file, err := c.stackFile(stack); err == nil {
				current = composeSHA(file)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "configured": configured, "configuration_reason": reason, "current_sha": current, "busy": busy, "state": state, "semantics": "Exact-SHA update requires green release-candidate, ARM64 image publication and production-compose workflows; Portainer owns deployment; prune is always false; stack environment and previous exact compose are preserved; terminal failed is written only after exact prior-stack rollback is health-verified."})
}

func decodeSHARequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	var q struct {
		SHA string `json:"sha"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	if err := dec.Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(q.SHA)), true
}

func (c *controller) check(w http.ResponseWriter, r *http.Request) {
	if !c.require(w, r, http.MethodPost) {
		return
	}
	sha, ok := decodeSHARequest(w, r)
	if !ok {
		return
	}
	var err error
	if sha == "" {
		sha, err = c.latestVerified()
	} else {
		err = c.verifiedTarget(sha)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	compose, err := c.targetCompose(sha)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sha": sha, "compose_bytes": len(compose), "verified": true})
}

func (c *controller) applyUpdate(w http.ResponseWriter, r *http.Request) {
	if !c.require(w, r, http.MethodPost) {
		return
	}
	sha, ok := decodeSHARequest(w, r)
	if !ok {
		return
	}
	if sha == "" {
		http.Error(w, "exact target sha is required; use Check latest first", http.StatusBadRequest)
		return
	}
	if configured, reason := c.configured(); !configured {
		http.Error(w, reason, http.StatusServiceUnavailable)
		return
	}

	c.mu.Lock()
	if c.state.Status == "applying" || c.state.Status == "finalizing" || c.state.Status == "rolling-back" {
		c.mu.Unlock()
		http.Error(w, "an update is already in progress", http.StatusConflict)
		return
	}
	// A stale rollback snapshot may remain only after a prior terminal update's
	// cleanup failed. Clear only a validated private snapshot while holding the
	// update-state lock, before this new transaction enters applying. Any unsafe
	// leftover therefore blocks before durable state changes or Portainer writes.
	if err := c.clearRollbackCompose(); err != nil {
		c.mu.Unlock()
		http.Error(w, "cannot safely clear stale rollback snapshot before update: "+err.Error(), http.StatusConflict)
		return
	}
	if err := c.persistStateLocked("applying", "", sha, "verifying exact release"); err != nil {
		c.mu.Unlock()
		http.Error(w, "cannot persist update recovery state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	c.mu.Unlock()

	stack, err := c.findStack()
	if err != nil {
		err = c.failState(sha, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	previous, err := c.stackFile(stack)
	if err != nil {
		err = c.failState(sha, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	from := composeSHA(previous)
	if !shaRE.MatchString(from) {
		err = c.failState(sha, fmt.Errorf("current Portainer stack is not one exact rollback-safe SHA: %s", from))
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	target, err := c.targetCompose(sha)
	if err != nil {
		err = c.failState(sha, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	phaseOne, err := preserveUpdater(target, previous)
	if err != nil {
		err = c.failState(sha, err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err := c.saveRollbackCompose(previous, from); err != nil {
		err = c.failState(sha, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	c.mu.Lock()
	if err := c.persistStateLocked("applying", from, sha, "Portainer is applying target services while preserving the current update controller"); err != nil {
		c.mu.Unlock()
		_ = c.clearRollbackCompose()
		err = c.failState(sha, fmt.Errorf("cannot persist pre-deployment recovery state: %w", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.mu.Unlock()

	if err := c.putStack(stack, phaseOne); err != nil {
		err = c.rollbackAfterDeploymentFailure(stack, from, sha, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := c.waitCoreHealthy(stack, 120*time.Second); err != nil {
		err = c.rollbackAfterDeploymentFailure(stack, from, sha, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	c.mu.Lock()
	if err := c.persistStateLocked("finalizing", from, sha, "core services verified; updating the update controller last"); err != nil {
		c.mu.Unlock()
		err = c.rollbackAfterDeploymentFailure(stack, from, sha, fmt.Errorf("cannot persist finalizing recovery state: %w", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.mu.Unlock()

	if err := c.putStack(stack, target); err != nil {
		err = c.rollbackAfterDeploymentFailure(stack, from, sha, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := c.waitCoreHealthy(stack, 120*time.Second); err != nil {
		err = c.rollbackAfterDeploymentFailure(stack, from, sha, fmt.Errorf("full exact target failed final health verification: %w", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	current, err := c.stackFile(stack)
	if err != nil {
		err = c.rollbackAfterDeploymentFailure(stack, from, sha, fmt.Errorf("cannot prove final Portainer compose identity: %w", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if actual := composeSHA(current); actual != sha {
		err = c.rollbackAfterDeploymentFailure(stack, from, sha, fmt.Errorf("final Portainer compose identity is %s, expected %s", actual, sha))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state := updateState{FromSHA: from, TargetSHA: sha}
	if err := c.completeRecoveredUpdate(state, "exact-SHA Portainer stack update completed and health-verified"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "from_sha": from, "sha": sha, "rolled_back": false, "core_health_verified": true, "exact_compose_verified": true})
}

func (c *controller) failState(target string, cause error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	from := c.state.FromSHA
	if err := c.persistStateLocked("failed", from, target, cause.Error()); err != nil {
		return fmt.Errorf("%v; failed to persist terminal update state: %w", cause, err)
	}
	return cause
}

func (c *controller) reconcileFinalizing() {
	if err := c.reconcileRecovery(); err != nil {
		log.Printf("update recovery reconciliation: %v", err)
	}
}

func main() {
	c, err := loadController()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/update/status", c.status)
	mux.HandleFunc("/api/admin/update/check", c.check)
	mux.HandleFunc("/api/admin/update/apply", c.applyUpdate)
	go c.reconcileFinalizing()
	server := &http.Server{Addr: c.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	log.Printf("Router VPN exact-SHA update controller listening on %s", c.listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
