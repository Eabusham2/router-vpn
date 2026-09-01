// SPDX-License-Identifier: MIT
package updatepolicy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signedFixture(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	m := Manifest{
		Schema:      SchemaV1,
		Channel:     "stable",
		Sequence:    41,
		CommitSHA:   strings.Repeat("a", 40),
		PublishedAt: now.Add(-time.Hour),
		ExpiresAt:   now.Add(24 * time.Hour),
		ReleaseURL:  "https://github.com/Eabusham2/router-vpn/releases/tag/sha-" + strings.Repeat("a", 40),
		Artifacts: []Artifact{{
			Platform: "windows",
			Arch:     "amd64",
			Kind:     "installed",
			URL:      "https://github.com/Eabusham2/router-vpn/releases/download/sha-" + strings.Repeat("a", 40) + "/router-vpn-windows-amd64.zip",
			SHA256:   strings.Repeat("b", 64),
			Size:     12345,
		}},
	}
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, pub
}

func TestParseAndVerifySignedManifest(t *testing.T) {
	raw, pub := signedFixture(t)
	m, err := ParseAndVerify(raw, pub, VerifyOptions{Now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if m.Sequence != 41 || m.CommitSHA != strings.Repeat("a", 40) {
		t.Fatalf("unexpected manifest: %#v", m)
	}
}

func TestManifestSignatureCoversArtifacts(t *testing.T) {
	raw, pub := signedFixture(t)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.Artifacts[0].Size++
	tampered, _ := json.Marshal(m)
	if _, err := ParseAndVerify(tampered, pub, VerifyOptions{Now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
}

func TestMovingAndInsecureArtifactURLsFailClosed(t *testing.T) {
	raw, pub := signedFixture(t)
	var base Manifest
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"http://example.com/router-vpn.zip",
		"https://github.com/Eabusham2/router-vpn/releases/latest/download/router-vpn.zip",
		"https://github.com/Eabusham2/router-vpn/archive/refs/heads/main.zip",
		"https://user:password@example.com/router-vpn.zip",
	} {
		m := base
		m.Artifacts = append([]Artifact(nil), base.Artifacts...)
		m.Artifacts[0].URL = bad
		// Keep the old signature: validation must reject before signature is even
		// relevant, and no caller can opt into a moving URL.
		candidate, _ := json.Marshal(m)
		if _, err := ParseAndVerify(candidate, pub, VerifyOptions{Now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}); err == nil {
			t.Fatalf("accepted forbidden URL %q", bad)
		}
	}
}

func TestUnknownFieldsAndUnknownSchemaFailClosed(t *testing.T) {
	raw, pub := signedFixture(t)
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["future_field"] = true
	unknown, _ := json.Marshal(obj)
	if _, err := ParseAndVerify(unknown, pub, VerifyOptions{Now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("unknown field was accepted")
	}
	delete(obj, "future_field")
	obj["schema"] = float64(99)
	future, _ := json.Marshal(obj)
	if _, err := ParseAndVerify(future, pub, VerifyOptions{Now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("unknown schema was accepted")
	}
}

func TestTrailingJSONFailsClosed(t *testing.T) {
	raw, pub := signedFixture(t)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	for _, suffix := range [][]byte{[]byte(` {}`), []byte(` true`), []byte(` null`)} {
		candidate := append(append([]byte(nil), raw...), suffix...)
		if _, err := ParseAndVerify(candidate, pub, VerifyOptions{Now: now}); err == nil {
			t.Fatalf("trailing JSON %q was accepted", suffix)
		}
	}
}

func TestSelectArtifactNormalizesPlatformAndArchitecture(t *testing.T) {
	raw, pub := signedFixture(t)
	m, err := ParseAndVerify(raw, pub, VerifyOptions{Now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SelectArtifact("win", "x86_64", "installed"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SelectArtifact("windows", "arm64", "installed"); err == nil {
		t.Fatal("missing architecture was accepted")
	}
}
