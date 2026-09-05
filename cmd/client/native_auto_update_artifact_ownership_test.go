package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/updatepolicy"
)

func TestNativeUpdateRejectsForeignDurableArtifactPath(t *testing.T) {
	root := t.TempDir()
	updates := filepath.Join(root, "updates")
	foreignDir := t.TempDir()
	foreign := filepath.Join(foreignDir, "foreign-package.bin")
	payload := []byte("unrelated file that updater state must never own")
	if err := os.WriteFile(foreign, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	cfg := rvNativeUpdateConfig{
		Mode:           rvNativeUpdateCheck,
		ManifestURL:    "https://updates.example.invalid/sha-manifest.json",
		PublicKey:      publicKey,
		Channel:        "stable",
		Platform:       "linux",
		Arch:           "amd64",
		Kind:           "installed",
		InstalledSHA:   strings.Repeat("a", 40),
		StatePath:      filepath.Join(root, "native-update.json"),
		DownloadDir:    updates,
		RequestTimeout: 5 * time.Second,
	}
	state := updatepolicy.State{
		Schema:         updatepolicy.SchemaV1,
		Channel:        "stable",
		InstalledSHA:   cfg.InstalledSHA,
		AvailableSHA:   strings.Repeat("b", 40),
		ArtifactPath:   foreign,
		ArtifactSHA256: digest,
		InstallPending: true,
		DownloadedAt:   time.Now().UTC(),
	}
	if err := updatepolicy.SaveState(cfg.StatePath, state); err != nil {
		t.Fatal(err)
	}

	if _, err := rvNativeUpdateOnce(context.Background(), cfg, false); err == nil || !strings.Contains(err.Error(), "outside the configured private update directory") {
		t.Fatalf("foreign durable artifact was not rejected before update work: %v", err)
	}
	if got, err := os.ReadFile(foreign); err != nil || string(got) != string(payload) {
		t.Fatalf("foreign artifact was touched: %q %v", got, err)
	}

	status := rvReadNativeUpdateStatus(cfg)
	if status.ArtifactPath != "" || status.ArtifactSHA256 != "" || status.InstallPending || status.RequiresUserInstall {
		t.Fatalf("status exposed foreign artifact ownership: %#v", status)
	}
	if !strings.Contains(status.LastError, "ownership is invalid") {
		t.Fatalf("status did not explain invalid artifact ownership: %#v", status)
	}

	rvPersistNativeUpdateError(cfg, errors.New("test update failure"))
	persisted, err := updatepolicy.LoadState(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ArtifactPath != "" || persisted.ArtifactSHA256 != "" || persisted.InstallPending {
		t.Fatalf("error persistence retained foreign artifact pointer: %#v", persisted)
	}
	if got, err := os.ReadFile(foreign); err != nil || string(got) != string(payload) {
		t.Fatalf("foreign file changed while state pointer was repaired: %q %v", got, err)
	}
}
