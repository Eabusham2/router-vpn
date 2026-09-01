// SPDX-License-Identifier: MIT
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/updatepolicy"
)

func TestRunWritesVerifiableManifest(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROUTER_VPN_UPDATE_SIGNING_KEY", base64.StdEncoding.EncodeToString(privateKey))
	dir := t.TempDir()
	inventory := filepath.Join(dir, "artifacts.json")
	output := filepath.Join(dir, "manifest.json")
	sha := strings.Repeat("a", 40)
	artifact := updatepolicy.Artifact{
		Platform: "windows",
		Arch:     "amd64",
		Kind:     "installed",
		URL:      "https://github.com/Eabusham2/router-vpn/releases/download/sha-" + sha + "/router-vpn-windows-amd64.zip",
		SHA256:   strings.Repeat("b", 64),
		Size:     999,
	}
	encoded, _ := json.Marshal(artifactInventory{Artifacts: []updatepolicy.Artifact{artifact}})
	if err := os.WriteFile(inventory, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	published := "2026-08-31T12:00:00Z"
	args := []string{
		"-artifacts", inventory,
		"-output", output,
		"-channel", "stable",
		"-sequence", "42",
		"-commit", sha,
		"-release-url", "https://github.com/Eabusham2/router-vpn/releases/tag/sha-" + sha,
		"-published-at", published,
		"-valid-for", "168h",
	}
	var stdout, stderr strings.Builder
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr.String())
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := updatepolicy.ParseAndVerify(raw, pub, updatepolicy.VerifyOptions{Now: time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Sequence != 42 || manifest.CommitSHA != sha || len(manifest.Artifacts) != 1 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

func TestRunFailsWithoutSigningKeyOrExactSHA(t *testing.T) {
	t.Setenv("ROUTER_VPN_UPDATE_SIGNING_KEY", "")
	dir := t.TempDir()
	inventory := filepath.Join(dir, "artifacts.json")
	if err := os.WriteFile(inventory, []byte(`{"artifacts":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-artifacts", inventory, "-sequence", "1", "-commit", "main"},
		{"-artifacts", inventory, "-sequence", "1", "-commit", strings.Repeat("a", 40)},
	} {
		var stdout, stderr strings.Builder
		if err := run(args, &stdout, &stderr); err == nil {
			t.Fatalf("unsafe manifest generation succeeded for args %v", args)
		}
	}
}
