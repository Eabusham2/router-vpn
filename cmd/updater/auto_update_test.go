// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Eabusham2/router-vpn/internal/updatepolicy"
)

func rvSignedManifestForTest(t *testing.T, sequence uint64, sha, artifactURL string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	m := updatepolicy.Manifest{
		Schema:      updatepolicy.SchemaV1,
		Channel:     "stable",
		Sequence:    sequence,
		CommitSHA:   sha,
		PublishedAt: now.Add(-time.Minute),
		ExpiresAt:   now.Add(time.Hour),
		ReleaseURL:  "https://github.com/Eabusham2/router-vpn/releases/tag/sha-" + sha,
		Artifacts: []updatepolicy.Artifact{{
			Platform: "linux",
			Arch:     "arm64",
			Kind:     "server",
			URL:      artifactURL,
			SHA256:   strings.Repeat("b", 64),
			Size:     123,
		}},
	}
	if err := m.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, pub
}

func TestPortainerAutoUpdateSubmitsOnlySignedExactSHA(t *testing.T) {
	current := strings.Repeat("a", 40)
	target := strings.Repeat("c", 40)
	var applyCount atomic.Int32
	apply := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["sha"] != target || body["target_sha"] != target {
			t.Fatalf("unexpected target body: %#v", body)
		}
		applyCount.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer apply.Close()

	var manifest []byte
	var publicKey ed25519.PublicKey
	manifestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(manifest)
	}))
	defer manifestServer.Close()
	artifactURL := "https://github.com/Eabusham2/router-vpn/releases/download/sha-" + target + "/router-vpn-server-arm64.tar.gz"
	manifest, publicKey = rvSignedManifestForTest(t, 2, target, artifactURL)

	client := manifestServer.Client()
	// Route the loopback HTTP apply request through the normal transport.
	client.Timeout = 5 * time.Second
	cfg := rvAutoUpdateConfig{
		Enabled:        true,
		ManifestURL:    manifestServer.URL,
		PublicKey:      publicKey,
		Channel:        "stable",
		ApplyURL:       apply.URL,
		BearerToken:    "test-token",
		InstalledSHA:   current,
		StatePath:      filepath.Join(t.TempDir(), "state.json"),
		RequestTimeout: 5 * time.Second,
	}
	if err := rvPortainerAutoUpdateOnce(context.Background(), client, cfg); err != nil {
		t.Fatal(err)
	}
	if got := applyCount.Load(); got != 1 {
		t.Fatalf("apply count = %d, want 1", got)
	}
	state, err := updatepolicy.LoadState(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastSequence != 2 || state.AvailableSHA != target || !state.InstallPending {
		t.Fatalf("unexpected state: %#v", state)
	}
	if err := rvPortainerAutoUpdateOnce(context.Background(), client, cfg); err != nil {
		t.Fatal(err)
	}
	if got := applyCount.Load(); got != 1 {
		t.Fatalf("same sequence was submitted again: %d", got)
	}
}

func TestPortainerAutoUpdateRejectsTamperedManifest(t *testing.T) {
	current := strings.Repeat("a", 40)
	target := strings.Repeat("c", 40)
	artifactURL := "https://github.com/Eabusham2/router-vpn/releases/download/sha-" + target + "/router-vpn-server-arm64.tar.gz"
	raw, publicKey := rvSignedManifestForTest(t, 2, target, artifactURL)
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["commit_sha"] = strings.Repeat("d", 40)
	tampered, _ := json.Marshal(manifest)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tampered)
	}))
	defer server.Close()
	cfg := rvAutoUpdateConfig{
		Enabled:        true,
		ManifestURL:    server.URL,
		PublicKey:      publicKey,
		Channel:        "stable",
		ApplyURL:       "http://127.0.0.1:8793/api/update",
		BearerToken:    "test-token",
		InstalledSHA:   current,
		StatePath:      filepath.Join(t.TempDir(), "state.json"),
		RequestTimeout: 5 * time.Second,
	}
	if err := rvPortainerAutoUpdateOnce(context.Background(), server.Client(), cfg); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
}

func TestPortainerApplyURLMustRemainLoopback(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/api/update",
		"http://192.168.50.133:8793/api/update",
		"file:///var/run/updater",
		"https://user:password@127.0.0.1:8793/api/update",
	} {
		if err := rvValidateLoopbackApplyURL(raw); err == nil {
			t.Fatalf("accepted unsafe updater URL %q", raw)
		}
	}
	if err := rvValidateLoopbackApplyURL("http://127.0.0.1:8793/api/update"); err != nil {
		t.Fatal(err)
	}
}
