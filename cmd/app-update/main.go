package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"router-vpn/internal/updatepolicy"
)

const (
	repository        = "Eabusham2/router-vpn"
	releaseTagPrefix  = "router-vpn-sha-"
	maxMetadata       = 512 << 10
	maxReleaseAsset   = int64(768 << 20)
	defaultCheckEvery = 6 * time.Hour
)

type releaseAsset struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type release struct {
	ID              int64          `json:"id"`
	TagName         string         `json:"tag_name"`
	TargetCommitish string         `json:"target_commitish"`
	Draft           bool           `json:"draft"`
	Prerelease      bool           `json:"prerelease"`
	PublishedAt     time.Time      `json:"published_at"`
	Assets          []releaseAsset `json:"assets"`
}

type releaseManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Repository    string `json:"repository"`
	SourceSHA     string `json:"source_sha"`
	Tag           string `json:"tag"`
	Producer      string `json:"producer_workflow"`
	Assets        []struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"assets"`
}

type sourceManifest struct {
	Repository string `json:"repository"`
	SourceSHA  string `json:"source_sha"`
}

type result struct {
	OK          bool   `json:"ok"`
	CurrentSHA  string `json:"current_sha"`
	Available   bool   `json:"available"`
	TargetSHA   string `json:"target_sha,omitempty"`
	Asset       string `json:"asset,omitempty"`
	StagedPath  string `json:"staged_path,omitempty"`
	InstallMode string `json:"install_mode"`
	Message     string `json:"message"`
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

func platformAsset(goos, goarch string, portable bool) (string, string, error) {
	switch goos {
	case "windows":
		if goarch != "amd64" && goarch != "arm64" {
			return "", "", fmt.Errorf("unsupported Windows architecture %s", goarch)
		}
		if portable {
			return "RouterVPN-Portable-Windows-" + goarch + ".zip", "stage-and-restart-helper", nil
		}
		return "RouterVPN-Windows-" + goarch + ".zip", "stage-and-restart-helper", nil
	case "darwin":
		if goarch != "amd64" && goarch != "arm64" {
			return "", "", fmt.Errorf("unsupported macOS architecture %s", goarch)
		}
		return "RouterVPN-darwin-" + goarch + ".tar.gz", "stage-signed-package; notarized production build required", nil
	case "linux":
		if goarch != "amd64" && goarch != "arm64" {
			return "", "", fmt.Errorf("unsupported Linux architecture %s", goarch)
		}
		return "RouterVPN-linux-" + goarch + ".tar.gz", "stage-package; package-manager installs remain package-manager-owned", nil
	default:
		return "", "", fmt.Errorf("desktop self-update helper is unavailable on %s", goos)
	}
}

func apiClient() *http.Client {
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" || req.URL.Hostname() != "api.github.com" {
				return errors.New("GitHub API redirect left api.github.com")
			}
			return nil
		},
	}
}

func assetClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Minute,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 8 {
				return errors.New("too many release-asset redirects")
			}
			host := strings.ToLower(req.URL.Hostname())
			allowed := host == "github.com" || host == "release-assets.githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
			if req.URL.Scheme != "https" || !allowed || req.URL.User != nil {
				return fmt.Errorf("release asset redirect left trusted GitHub HTTPS hosts: %s", req.URL.String())
			}
			return nil
		},
	}
}

func githubJSON(endpoint string, out any) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() != "api.github.com" || u.User != nil {
		return errors.New("invalid GitHub API endpoint")
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "router-vpn-app-update/1")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := apiClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadata+1))
	if err != nil {
		return err
	}
	if len(body) > maxMetadata {
		return errors.New("GitHub metadata response is oversized")
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func exactReleaseIdentity(rel release) (string, bool) {
	if rel.Draft || !strings.HasPrefix(rel.TagName, releaseTagPrefix) {
		return "", false
	}
	sha := strings.TrimPrefix(rel.TagName, releaseTagPrefix)
	if !validSHA(sha) || strings.ToLower(strings.TrimSpace(rel.TargetCommitish)) != sha {
		return "", false
	}
	// Build-all publishes exact-SHA native packages as prereleases only after
	// every authoritative release gate passes. Prerelease status is therefore
	// not a trust downgrade; exact tag/target identity plus the verified
	// RouterVPN-RELEASE.json digest manifest remain the acceptance boundary.
	return sha, true
}

func exactRelease() (release, string, error) {
	var releases []release
	endpoint := "https://api.github.com/repos/" + repository + "/releases?per_page=50"
	if err := githubJSON(endpoint, &releases); err != nil {
		return release{}, "", err
	}
	sort.SliceStable(releases, func(i, j int) bool { return releases[i].PublishedAt.After(releases[j].PublishedAt) })
	for _, rel := range releases {
		if sha, ok := exactReleaseIdentity(rel); ok {
			return rel, sha, nil
		}
	}
	return release{}, "", errors.New("no immutable exact-SHA Router VPN release is available")
}

func findAsset(rel release, name string) (releaseAsset, error) {
	var found []releaseAsset
	for _, asset := range rel.Assets {
		if asset.Name == name {
			found = append(found, asset)
		}
	}
	if len(found) != 1 || found[0].ID <= 0 || found[0].Size <= 0 || found[0].Size > maxReleaseAsset {
		return releaseAsset{}, fmt.Errorf("release must contain exactly one safe %s asset", name)
	}
	return found[0], nil
}

func downloadBytes(asset releaseAsset, maximum int64) ([]byte, error) {
	if asset.Size <= 0 || asset.Size > maximum {
		return nil, errors.New("release metadata asset size is unsafe")
	}
	u, err := url.Parse(asset.BrowserDownloadURL)
	if err != nil || u.Scheme != "https" || u.Hostname() != "github.com" || u.User != nil {
		return nil, errors.New("release metadata asset URL is not trusted GitHub HTTPS")
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "router-vpn-app-update/1")
	resp, err := assetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("release asset HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum || len(body) == 0 {
		return nil, errors.New("release metadata asset is empty or oversized")
	}
	return body, nil
}

func decodeReleaseManifest(raw []byte) (releaseManifest, error) {
	var manifest releaseManifest
	if len(raw) == 0 || len(raw) > maxMetadata {
		return manifest, errors.New("release manifest is empty or oversized")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return releaseManifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return releaseManifest{}, errors.New("release manifest contains trailing JSON")
		}
		return releaseManifest{}, fmt.Errorf("release manifest trailing data: %w", err)
	}
	return manifest, nil
}

func verifiedManifest(rel release, target string) (releaseManifest, error) {
	asset, err := findAsset(rel, "RouterVPN-RELEASE.json")
	if err != nil {
		return releaseManifest{}, err
	}
	body, err := downloadBytes(asset, maxMetadata)
	if err != nil {
		return releaseManifest{}, err
	}
	manifest, err := decodeReleaseManifest(body)
	if err != nil {
		return releaseManifest{}, err
	}
	if manifest.SchemaVersion != 1 || manifest.Repository != repository || manifest.SourceSHA != target || manifest.Tag != releaseTagPrefix+target || manifest.Producer != "build-all.yml" {
		return releaseManifest{}, errors.New("release manifest identity does not match the exact release")
	}
	return manifest, nil
}

func expectedAsset(manifest releaseManifest, name string) (int64, string, error) {
	count := 0
	var size int64
	var digest string
	for _, item := range manifest.Assets {
		if item.Name != name {
			continue
		}
		count++
		size, digest = item.Size, strings.ToLower(item.SHA256)
	}
	if count != 1 || size <= 0 || size > maxReleaseAsset || len(digest) != 64 {
		return 0, "", fmt.Errorf("release manifest has invalid %s metadata", name)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return 0, "", errors.New("release manifest asset digest is invalid")
	}
	return size, digest, nil
}

func readSourceManifest(path string) (sourceManifest, error) {
	var manifest sourceManifest
	before, err := os.Lstat(path)
	if err != nil {
		return manifest, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxMetadata {
		return manifest, errors.New("package provenance must be one bounded regular non-symlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return manifest, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return manifest, err
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return sourceManifest{}, errors.New("package provenance changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxMetadata+1))
	if err != nil || len(raw) == 0 || len(raw) > maxMetadata {
		return sourceManifest{}, errors.New("package provenance is unreadable or oversized")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(raw)) {
		return sourceManifest{}, errors.New("package provenance changed while reading")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return sourceManifest{}, fmt.Errorf("decode package provenance: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return sourceManifest{}, errors.New("package provenance contains trailing data")
	}
	if manifest.Repository != repository || !validSHA(strings.ToLower(manifest.SourceSHA)) {
		return sourceManifest{}, errors.New("package provenance identity is invalid")
	}
	manifest.SourceSHA = strings.ToLower(manifest.SourceSHA)
	return manifest, nil
}

func sourceSHA(explicit string) (string, error) {
	if sha := strings.ToLower(strings.TrimSpace(explicit)); sha != "" {
		if validSHA(sha) {
			return sha, nil
		}
		return "", errors.New("--current-sha is invalid")
	}
	if sha := strings.ToLower(strings.TrimSpace(os.Getenv("ROUTER_VPN_SOURCE_SHA"))); validSHA(sha) {
		return sha, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "ROUTER-VPN-SOURCE.json"),
		filepath.Join(filepath.Dir(exe), "..", "ROUTER-VPN-SOURCE.json"),
		filepath.Join(filepath.Dir(exe), "..", "..", "ROUTER-VPN-SOURCE.json"),
	}
	for _, path := range candidates {
		clean := filepath.Clean(path)
		manifest, err := readSourceManifest(clean)
		if err == nil {
			return manifest.SourceSHA, nil
		}
		if os.IsNotExist(err) {
			continue
		}
		return "", fmt.Errorf("read package provenance %s: %w", clean, err)
	}
	return "", errors.New("current exact source SHA is unavailable; package provenance is required")
}

func updateCacheDir(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "RouterVPN", "updates"), nil
}

func stageAsset(rel release, manifest releaseManifest, name, target, directory string) (string, error) {
	asset, err := findAsset(rel, name)
	if err != nil {
		return "", err
	}
	expectedSize, expectedDigest, err := expectedAsset(manifest, name)
	if err != nil {
		return "", err
	}
	if asset.Size != expectedSize {
		return "", errors.New("release API and manifest asset sizes disagree")
	}
	if target != manifest.SourceSHA {
		return "", errors.New("release target and verified manifest identity disagree")
	}
	verified := updatepolicy.Artifact{
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
		Kind:     "package",
		URL:      asset.BrowserDownloadURL,
		SHA256:   expectedDigest,
		Size:     expectedSize,
	}
	return updatepolicy.DownloadArtifact(context.Background(), assetClient(), verified, directory)
}

func checkOnce(current string, portable, download bool, directory string) (result, error) {
	assetName, installMode, err := platformAsset(runtime.GOOS, runtime.GOARCH, portable)
	if err != nil {
		return result{}, err
	}
	rel, target, err := exactRelease()
	if err != nil {
		return result{}, err
	}
	manifest, err := verifiedManifest(rel, target)
	if err != nil {
		return result{}, err
	}
	if _, _, err := expectedAsset(manifest, assetName); err != nil {
		return result{}, err
	}
	out := result{OK: true, CurrentSHA: current, TargetSHA: target, Asset: assetName, InstallMode: installMode}
	if current == target {
		out.Message = "Router VPN is already on the newest verified exact-SHA release"
		return out, nil
	}
	out.Available = true
	out.Message = "A newer verified exact-SHA Router VPN package is available"
	if download {
		path, err := stageAsset(rel, manifest, assetName, target, directory)
		if err != nil {
			return result{}, err
		}
		out.StagedPath = path
		out.Message = "A newer verified exact-SHA Router VPN package was downloaded and staged"
	}
	return out, nil
}

func emit(out result, asJSON bool) {
	if asJSON {
		body, _ := json.Marshal(out)
		fmt.Println(string(body))
		return
	}
	fmt.Println(out.Message)
	fmt.Printf("current=%s target=%s asset=%s\n", out.CurrentSHA, out.TargetSHA, out.Asset)
	if out.StagedPath != "" {
		fmt.Printf("staged=%s\n", out.StagedPath)
	}
	fmt.Printf("install=%s\n", out.InstallMode)
}

func main() {
	var current, cache string
	var portable, download, background, jsonOutput bool
	var interval time.Duration
	flag.StringVar(&current, "current-sha", "", "current exact source SHA; normally read from package provenance")
	flag.StringVar(&cache, "cache", "", "verified update staging directory")
	flag.BoolVar(&portable, "portable", false, "use the Windows Portable asset")
	flag.BoolVar(&download, "download", false, "download and hash-verify a newer exact-SHA package")
	flag.BoolVar(&background, "background", false, "periodically check and stage verified updates")
	flag.BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	flag.DurationVar(&interval, "interval", defaultCheckEvery, "background check interval")
	flag.Parse()
	sha, err := sourceSHA(current)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	dir, err := updateCacheDir(cache)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !background {
		out, err := checkOnce(sha, portable, download, dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(out, jsonOutput)
		return
	}
	if interval < 30*time.Minute || interval > 24*time.Hour {
		fmt.Fprintln(os.Stderr, "background interval must be between 30m and 24h")
		os.Exit(2)
	}
	for {
		out, err := checkOnce(sha, portable, true, dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Router VPN automatic update check:", err)
		} else if out.Available {
			emit(out, jsonOutput)
		}
		time.Sleep(interval)
	}
}
