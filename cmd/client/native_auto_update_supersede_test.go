package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/updatepolicy"
)

func TestNativeUpdateDirectDownloadRemovesSupersededArtifact(t *testing.T) {
	current := strings.Repeat("a", 40)
	firstTarget := strings.Repeat("b", 40)
	secondTarget := strings.Repeat("c", 40)
	firstPayload := []byte("first exact native package")
	secondPayload := []byte("second exact native package")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var manifestRaw []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(manifestRaw)
		case "/sha-" + firstTarget + "/router-vpn.tar.gz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(firstPayload)
		case "/sha-" + secondTarget + "/router-vpn.tar.gz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(secondPayload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	cfg := rvNativeUpdateConfig{
		Mode:           rvNativeUpdateDownload,
		ManifestURL:    server.URL + "/manifest.json",
		PublicKey:      publicKey,
		Channel:        "stable",
		Platform:       "linux",
		Arch:           "amd64",
		Kind:           "installed",
		InstalledSHA:   current,
		StatePath:      filepath.Join(root, "state.json"),
		DownloadDir:    filepath.Join(root, "updates"),
		RequestTimeout: 5 * time.Second,
	}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()

	manifestRaw = rvNativeSignedManifestWithKey(
		t, privateKey, 30, firstTarget,
		server.URL+"/sha-"+firstTarget+"/router-vpn.tar.gz", firstPayload,
	)
	first, err := rvNativeUpdateOnce(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if first.ArtifactPath == "" || first.AvailableSHA != firstTarget || !first.InstallPending {
		t.Fatalf("first target was not staged: %#v", first)
	}
	oldPath := first.ArtifactPath
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("first staged artifact is missing: %v", err)
	}

	// Skip a separate Check call on purpose. Download must itself retire the old
	// target instead of relying on UI call ordering to prevent orphaned packages.
	manifestRaw = rvNativeSignedManifestWithKey(
		t, privateKey, 31, secondTarget,
		server.URL+"/sha-"+secondTarget+"/router-vpn.tar.gz", secondPayload,
	)
	second, err := rvNativeUpdateOnce(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if second.ArtifactPath == "" || second.ArtifactPath == oldPath || second.AvailableSHA != secondTarget || !second.InstallPending {
		t.Fatalf("replacement target was not staged independently: %#v", second)
	}
	if _, err := os.Lstat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("superseded verified artifact remains on disk: %v", err)
	}
	got, err := os.ReadFile(second.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secondPayload) {
		t.Fatalf("replacement artifact payload mismatch: %q", got)
	}
	state, err := updatepolicy.LoadState(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.AvailableSHA != secondTarget || state.ArtifactPath != second.ArtifactPath || !state.InstallPending {
		t.Fatalf("durable state does not own only the replacement artifact: %#v", state)
	}
}
