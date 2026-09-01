// SPDX-License-Identifier: MIT
package updatepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStateRoundTripUsesPrivateRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "native-update.json")
	want := State{
		Schema:          SchemaV1,
		Channel:         "stable",
		LastSequence:    7,
		LastManifestSHA: strings.Repeat("c", 40),
		InstalledSHA:    strings.Repeat("a", 40),
		AvailableSHA:    strings.Repeat("b", 40),
		LastCheckedAt:   time.Now().UTC().Truncate(time.Second),
		InstallPending:  true,
	}
	if err := SaveState(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("unsafe state mode: %v", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.AvailableSHA != want.AvailableSHA || got.LastManifestSHA != want.LastManifestSHA || got.LastSequence != want.LastSequence || !got.InstallPending {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestStateSymlinkAndPermissiveModeFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission and symlink contract")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(`{"schema":1,"channel":"stable"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(link); err == nil {
		t.Fatal("symlink state was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte(`{"schema":1,"channel":"stable"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(link); err == nil {
		t.Fatal("world-readable state was accepted")
	}
}

func TestDownloadArtifactVerifiesSizeAndHash(t *testing.T) {
	payload := []byte("exact immutable Router VPN package")
	h := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "34")
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	artifact := Artifact{
		Platform: "linux",
		Arch:     "amd64",
		Kind:     "installed",
		URL:      server.URL + "/sha-" + strings.Repeat("a", 40) + "/router-vpn.tar.gz",
		SHA256:   hex.EncodeToString(h[:]),
		Size:     int64(len(payload)),
	}
	// The normal artifact validator requires HTTPS. The httptest server is
	// intentionally HTTP, so validate the private download primitive through
	// a loopback-aware copy of the signed metadata.
	if err := artifact.Validate(VerifyOptions{AllowLoopbackHTTP: true}); err != nil {
		t.Fatal(err)
	}
	// DownloadArtifact independently uses the production validator. Replace
	// its transport with TLS so the complete production path is exercised.
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "34")
		_, _ = w.Write(payload)
	}))
	defer tlsServer.Close()
	artifact.URL = tlsServer.URL + "/sha-" + strings.Repeat("a", 40) + "/router-vpn.tar.gz"
	path, err := DownloadArtifact(context.Background(), tlsServer.Client(), artifact, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("download mismatch: %q", got)
	}
}

func TestDownloadArtifactRejectsWrongHashAndCleansTemporaryFile(t *testing.T) {
	payload := []byte("tampered package")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	dir := t.TempDir()
	artifact := Artifact{
		Platform: "macos",
		Arch:     "arm64",
		Kind:     "installed",
		URL:      server.URL + "/sha-" + strings.Repeat("a", 40) + "/router-vpn.pkg",
		SHA256:   strings.Repeat("0", 64),
		Size:     int64(len(payload)),
	}
	if _, err := DownloadArtifact(context.Background(), server.Client(), artifact, dir); err == nil {
		t.Fatal("wrong hash was accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary artifact was not cleaned: %v", entries)
	}
}

func TestLoadStateRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"schema":1,"channel":"stable"} {"schema":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}
