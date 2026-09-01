// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/updatepolicy"
)

func rvNativeSignedManifest(t *testing.T, target, artifactURL string, artifact []byte) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return rvNativeSignedManifestWithKey(t, privateKey, 11, target, artifactURL, artifact), pub
}

func rvNativeSignedManifestWithKey(t *testing.T, privateKey ed25519.PrivateKey, sequence uint64, target, artifactURL string, artifact []byte) []byte {
	t.Helper()
	h := sha256.Sum256(artifact)
	now := time.Now().UTC()
	manifest := updatepolicy.Manifest{
		Schema:      updatepolicy.SchemaV1,
		Channel:     "stable",
		Sequence:    sequence,
		CommitSHA:   target,
		PublishedAt: now.Add(-time.Minute),
		ExpiresAt:   now.Add(time.Hour),
		ReleaseURL:  "https://github.com/Eabusham2/router-vpn/releases/tag/sha-" + target,
		Artifacts: []updatepolicy.Artifact{{
			Platform: "linux",
			Arch:     "amd64",
			Kind:     "installed",
			URL:      artifactURL,
			SHA256:   hex.EncodeToString(h[:]),
			Size:     int64(len(artifact)),
		}},
	}
	if err := manifest.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeUpdateCheckAndDownloadRemainSeparate(t *testing.T) {
	current := strings.Repeat("a", 40)
	target := strings.Repeat("c", 40)
	packageBytes := []byte("signed exact native package")

	var manifestRaw []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(manifestRaw)
		case "/sha-" + target + "/router-vpn.tar.gz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(packageBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	var publicKey ed25519.PublicKey
	manifestRaw, publicKey = rvNativeSignedManifest(t, target, server.URL+"/sha-"+target+"/router-vpn.tar.gz", packageBytes)

	cfg := rvNativeUpdateConfig{
		Mode:           rvNativeUpdateDownload,
		ManifestURL:    server.URL + "/manifest.json",
		PublicKey:      publicKey,
		Channel:        "stable",
		Platform:       "linux",
		Arch:           "amd64",
		Kind:           "installed",
		InstalledSHA:   current,
		StatePath:      filepath.Join(t.TempDir(), "state.json"),
		DownloadDir:    filepath.Join(t.TempDir(), "updates"),
		RequestTimeout: 5 * time.Second,
	}
	// Use the TLS test client's trusted transport through a temporary default
	// transport because rvNativeUpdateOnce intentionally creates its own client.
	oldTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()

	checked, err := rvNativeUpdateOnce(context.Background(), cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if checked.AvailableSHA != target || checked.ArtifactPath != "" || checked.InstallPending {
		t.Fatalf("check unexpectedly staged an update: %#v", checked)
	}
	downloaded, err := rvNativeUpdateOnce(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if downloaded.ArtifactPath == "" || !downloaded.InstallPending || !downloaded.RequiresUserInstall {
		t.Fatalf("download did not stage for user-confirmed install: %#v", downloaded)
	}
	got, err := os.ReadFile(downloaded.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(packageBytes) {
		t.Fatalf("staged package mismatch: %q", got)
	}
}

func TestNativeMobileDownloadFailsClosed(t *testing.T) {
	for _, platform := range []string{"android", "ios", "ipados"} {
		if !rvNativeMobilePlatform(platform) {
			t.Fatalf("%s was not recognized as a mobile platform", platform)
		}
	}
	if rvNativeMobilePlatform("macos") {
		t.Fatal("macOS was incorrectly treated as a mobile distribution target")
	}
}

func TestNativeUpdateMutationRequiresLoopbackAppHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/update/native/check", nil)
	request.RemoteAddr = "127.0.0.1:49321"
	if rvNativeLoopbackMutation(request) {
		t.Fatal("missing native-app header was accepted")
	}
	request.Header.Set("X-Router-VPN-Native-App", "1")
	if !rvNativeLoopbackMutation(request) {
		t.Fatal("valid loopback native-app request was rejected")
	}
	request.RemoteAddr = "192.0.2.10:49321"
	if rvNativeLoopbackMutation(request) {
		t.Fatal("non-loopback mutation was accepted")
	}
}

func TestNativeUpdateStateRejectsStaleOrCorruptState(t *testing.T) {
	dir := t.TempDir()
	cfg := rvNativeUpdateConfig{
		Mode:         rvNativeUpdateCheck,
		Channel:      "stable",
		Platform:     "linux",
		Arch:         "amd64",
		Kind:         "installed",
		InstalledSHA: strings.Repeat("a", 40),
		StatePath:    filepath.Join(dir, "state.json"),
	}
	if err := os.WriteFile(cfg.StatePath, []byte(`{"schema":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	status := rvReadNativeUpdateStatus(cfg)
	if status.LastError == "" {
		t.Fatal("corrupt/unsupported state did not fail closed")
	}
}

func TestPackagedSourceSHAReadsCanonicalProvenance(t *testing.T) {
	dir := t.TempDir()
	want := strings.Repeat("d", 40)
	raw := []byte(`{"repository":"Eabusham2/router-vpn","source_sha":"` + want + `"}`)
	if err := os.WriteFile(filepath.Join(dir, "ROUTER-VPN-SOURCE.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := rvPackagedSourceSHA(dir); got != want {
		t.Fatalf("packaged source SHA = %q, want %q", got, want)
	}
	if err := os.WriteFile(filepath.Join(dir, "ROUTER-VPN-SOURCE.json"), []byte(`{"repository":"other/repo","source_sha":"`+want+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := rvPackagedSourceSHA(dir); got != "" {
		t.Fatalf("foreign package provenance was accepted: %q", got)
	}
}

func TestNativeMobileDownloadOperationFailsClosed(t *testing.T) {
	cfg := rvNativeUpdateConfig{
		Mode:           rvNativeUpdateDownload,
		ManifestURL:    "https://updates.example/sha-" + strings.Repeat("c", 40) + "/manifest.json",
		PublicKey:      make(ed25519.PublicKey, ed25519.PublicKeySize),
		Channel:        "stable",
		Platform:       "android",
		Arch:           "arm64",
		Kind:           "installed",
		InstalledSHA:   strings.Repeat("a", 40),
		StatePath:      filepath.Join(t.TempDir(), "state.json"),
		DownloadDir:    filepath.Join(t.TempDir(), "updates"),
		RequestTimeout: 5 * time.Second,
	}
	if _, err := rvNativeUpdateOnce(context.Background(), cfg, true); err == nil || !strings.Contains(err.Error(), "signed install control") {
		t.Fatalf("mobile staging did not fail closed: %v", err)
	}
}

func TestNativeUpdateRejectsSequenceRollbackAndReuse(t *testing.T) {
	current := strings.Repeat("a", 40)
	firstTarget := strings.Repeat("b", 40)
	secondTarget := strings.Repeat("c", 40)
	payload := []byte("exact package")
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var manifestRaw []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(manifestRaw)
	}))
	defer server.Close()
	cfg := rvNativeUpdateConfig{
		Mode:           rvNativeUpdateCheck,
		ManifestURL:    server.URL + "/manifest.json",
		PublicKey:      pub,
		Channel:        "stable",
		Platform:       "linux",
		Arch:           "amd64",
		Kind:           "installed",
		InstalledSHA:   current,
		StatePath:      filepath.Join(t.TempDir(), "state.json"),
		DownloadDir:    filepath.Join(t.TempDir(), "updates"),
		RequestTimeout: 5 * time.Second,
	}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()
	manifestFor := func(sequence uint64, target string) []byte {
		return rvNativeSignedManifestWithKey(t, privateKey, sequence, target, server.URL+"/sha-"+target+"/router-vpn.tar.gz", payload)
	}
	manifestRaw = manifestFor(20, firstTarget)
	if _, err := rvNativeUpdateOnce(context.Background(), cfg, false); err != nil {
		t.Fatal(err)
	}
	manifestRaw = manifestFor(19, secondTarget)
	if _, err := rvNativeUpdateOnce(context.Background(), cfg, false); err == nil || !strings.Contains(err.Error(), "older sequence") {
		t.Fatalf("sequence rollback was accepted: %v", err)
	}
	manifestRaw = manifestFor(20, secondTarget)
	if _, err := rvNativeUpdateOnce(context.Background(), cfg, false); err == nil || !strings.Contains(err.Error(), "target identity") {
		t.Fatalf("sequence reuse was accepted: %v", err)
	}
}

func TestNativeManifestRedirectFailsClosed(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"unexpected":true}`))
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/manifest.json", http.StatusFound)
	}))
	defer redirector.Close()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = redirector.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()
	if _, err := rvFetchManifest(context.Background(), rvNativeManifestClient(5*time.Second), redirector.URL+"/manifest.json"); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("manifest redirect was accepted: %v", err)
	}
}

func TestClearNativeArtifactRemovesOnlyVerifiedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.bin")
	payload := []byte("verified native package")
	digest := sha256.Sum256(payload)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	state := updatepolicy.State{ArtifactPath: path, ArtifactSHA256: hex.EncodeToString(digest[:]), InstallPending: true, DownloadedAt: time.Now().UTC()}
	if err := rvClearNativeArtifact(&state); err != nil {
		t.Fatal(err)
	}
	if state.ArtifactPath != "" || state.ArtifactSHA256 != "" || state.InstallPending || !state.DownloadedAt.IsZero() {
		t.Fatalf("artifact state was not cleared: %#v", state)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("verified staged file remains: %v", err)
	}
}

func TestClearNativeArtifactPreservesDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.bin")
	if err := os.WriteFile(path, []byte("foreign replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := updatepolicy.State{ArtifactPath: path, ArtifactSHA256: strings.Repeat("0", 64), InstallPending: true}
	if err := rvClearNativeArtifact(&state); err == nil {
		t.Fatal("digest-mismatched staged file was accepted for cleanup")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "foreign replacement" {
		t.Fatalf("foreign replacement was removed or changed: %q err=%v", got, err)
	}
	if state.ArtifactPath != path || !state.InstallPending {
		t.Fatalf("failed cleanup discarded durable ownership state: %#v", state)
	}
}
