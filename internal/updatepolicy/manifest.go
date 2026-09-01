// SPDX-License-Identifier: MIT
package updatepolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	// SchemaV1 is the first signed native/server update manifest schema.
	SchemaV1 = 1
	// MaxManifestBytes bounds untrusted manifest input before JSON parsing.
	MaxManifestBytes = 1 << 20
	// MaxArtifactBytes is a defensive upper bound; individual artifacts carry a
	// tighter signed size and downloads are bounded to that exact value.
	MaxArtifactBytes int64 = 8 << 30
)

var (
	errInvalidManifest = errors.New("invalid update manifest")
	errInvalidArtifact = errors.New("invalid update artifact")
)

// Manifest is the signed, immutable update decision supplied to both native
// clients and the Portainer updater. Signature covers every field except
// Signature itself through SignedPayload.
type Manifest struct {
	Schema      int        `json:"schema"`
	Channel     string     `json:"channel"`
	Sequence    uint64     `json:"sequence"`
	CommitSHA   string     `json:"commit_sha"`
	PublishedAt time.Time  `json:"published_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	ReleaseURL  string     `json:"release_url,omitempty"`
	Artifacts   []Artifact `json:"artifacts"`
	Signature   string     `json:"signature"`
}

// Artifact identifies one exact platform package or server release input.
type Artifact struct {
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// SignedPayload is deliberately a struct rather than a map so json.Marshal
// emits one deterministic field order across the generator and verifier.
type SignedPayload struct {
	Schema      int        `json:"schema"`
	Channel     string     `json:"channel"`
	Sequence    uint64     `json:"sequence"`
	CommitSHA   string     `json:"commit_sha"`
	PublishedAt time.Time  `json:"published_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	ReleaseURL  string     `json:"release_url,omitempty"`
	Artifacts   []Artifact `json:"artifacts"`
}

// VerifyOptions controls the few environment-specific trust decisions. An
// empty AllowedHosts list means any HTTPS host is acceptable after signature
// verification. Loopback HTTP is allowed only when explicitly enabled.
type VerifyOptions struct {
	Now               time.Time
	AllowedChannels   []string
	AllowedHosts      []string
	AllowLoopbackHTTP bool
	MaxClockSkew      time.Duration
}

func (m Manifest) Payload() SignedPayload {
	artifacts := append([]Artifact(nil), m.Artifacts...)
	sort.Slice(artifacts, func(i, j int) bool {
		if artifacts[i].Platform != artifacts[j].Platform {
			return artifacts[i].Platform < artifacts[j].Platform
		}
		if artifacts[i].Arch != artifacts[j].Arch {
			return artifacts[i].Arch < artifacts[j].Arch
		}
		if artifacts[i].Kind != artifacts[j].Kind {
			return artifacts[i].Kind < artifacts[j].Kind
		}
		return artifacts[i].URL < artifacts[j].URL
	})
	return SignedPayload{
		Schema:      m.Schema,
		Channel:     m.Channel,
		Sequence:    m.Sequence,
		CommitSHA:   strings.ToLower(m.CommitSHA),
		PublishedAt: m.PublishedAt.UTC(),
		ExpiresAt:   m.ExpiresAt.UTC(),
		ReleaseURL:  m.ReleaseURL,
		Artifacts:   artifacts,
	}
}

func (m Manifest) CanonicalPayload() ([]byte, error) {
	return json.Marshal(m.Payload())
}

// Sign applies an Ed25519 signature. Ed25519 is intentionally used instead of
// an invented packet/update cipher; the private key belongs in CI secrets and
// only the public key ships with clients.
func (m *Manifest) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: invalid Ed25519 private key", errInvalidManifest)
	}
	payload, err := m.CanonicalPayload()
	if err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

// ParseAndVerify parses one bounded manifest, validates every decision field,
// and verifies the Ed25519 signature before returning it.
func ParseAndVerify(raw []byte, publicKey ed25519.PublicKey, opts VerifyOptions) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return m, fmt.Errorf("%w: manifest size", errInvalidManifest)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: decode: %v", errInvalidManifest, err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, fmt.Errorf("%w: trailing JSON", errInvalidManifest)
		}
		return Manifest{}, fmt.Errorf("%w: trailing JSON: %v", errInvalidManifest, err)
	}
	if err := m.Validate(opts); err != nil {
		return Manifest{}, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Manifest{}, fmt.Errorf("%w: invalid Ed25519 public key", errInvalidManifest)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Manifest{}, fmt.Errorf("%w: malformed signature", errInvalidManifest)
	}
	payload, err := m.CanonicalPayload()
	if err != nil {
		return Manifest{}, err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return Manifest{}, fmt.Errorf("%w: signature verification failed", errInvalidManifest)
	}
	return m, nil
}

func (m Manifest) Validate(opts VerifyOptions) error {
	if m.Schema != SchemaV1 {
		return fmt.Errorf("%w: unsupported schema %d", errInvalidManifest, m.Schema)
	}
	if !validChannel(m.Channel, opts.AllowedChannels) {
		return fmt.Errorf("%w: channel", errInvalidManifest)
	}
	if m.Sequence == 0 {
		return fmt.Errorf("%w: zero sequence", errInvalidManifest)
	}
	if !isHex(m.CommitSHA, 40) {
		return fmt.Errorf("%w: commit SHA must be exact 40-hex", errInvalidManifest)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := opts.MaxClockSkew
	if skew <= 0 {
		skew = 10 * time.Minute
	}
	published := m.PublishedAt.UTC()
	expires := m.ExpiresAt.UTC()
	if published.IsZero() || expires.IsZero() || !expires.After(published) {
		return fmt.Errorf("%w: invalid validity window", errInvalidManifest)
	}
	if published.After(now.Add(skew)) {
		return fmt.Errorf("%w: published in the future", errInvalidManifest)
	}
	if !expires.After(now.Add(-skew)) {
		return fmt.Errorf("%w: expired", errInvalidManifest)
	}
	if expires.Sub(published) > 31*24*time.Hour {
		return fmt.Errorf("%w: validity window too large", errInvalidManifest)
	}
	if m.ReleaseURL != "" {
		if err := validateImmutableURL(m.ReleaseURL, opts); err != nil {
			return fmt.Errorf("%w: release URL: %v", errInvalidManifest, err)
		}
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > 128 {
		return fmt.Errorf("%w: artifact count", errInvalidManifest)
	}
	seen := make(map[string]struct{}, len(m.Artifacts))
	for i, a := range m.Artifacts {
		if err := a.Validate(opts); err != nil {
			return fmt.Errorf("%w at index %d: %v", errInvalidArtifact, i, err)
		}
		key := strings.ToLower(a.Platform + "\x00" + a.Arch + "\x00" + a.Kind)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate %s/%s/%s", errInvalidArtifact, a.Platform, a.Arch, a.Kind)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (a Artifact) Validate(opts VerifyOptions) error {
	if !validToken(a.Platform) || !validToken(a.Arch) || !validToken(a.Kind) {
		return fmt.Errorf("%w: invalid identity", errInvalidArtifact)
	}
	if a.Size <= 0 || a.Size > MaxArtifactBytes {
		return fmt.Errorf("%w: invalid size", errInvalidArtifact)
	}
	if !isHex(a.SHA256, 64) {
		return fmt.Errorf("%w: SHA-256", errInvalidArtifact)
	}
	if err := validateImmutableURL(a.URL, opts); err != nil {
		return fmt.Errorf("%w: URL: %v", errInvalidArtifact, err)
	}
	return nil
}

// SelectArtifact returns exactly one matching artifact or fails closed.
func (m Manifest) SelectArtifact(platform, arch, kind string) (Artifact, error) {
	platform = NormalizePlatform(platform)
	arch = NormalizeArch(arch)
	var match *Artifact
	for i := range m.Artifacts {
		a := m.Artifacts[i]
		if NormalizePlatform(a.Platform) == platform && NormalizeArch(a.Arch) == arch && strings.EqualFold(a.Kind, kind) {
			if match != nil {
				return Artifact{}, fmt.Errorf("%w: ambiguous match", errInvalidArtifact)
			}
			copy := a
			match = &copy
		}
	}
	if match == nil {
		return Artifact{}, fmt.Errorf("%w: no artifact for %s/%s/%s", errInvalidArtifact, platform, arch, kind)
	}
	return *match, nil
}

func NormalizePlatform(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "darwin", "osx":
		return "macos"
	case "win", "win32":
		return "windows"
	default:
		return v
	}
}

func NormalizeArch(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "x86_64", "x64":
		return "amd64"
	case "aarch64":
		return "arm64"
	case "":
		return NormalizeArch(runtime.GOARCH)
	default:
		return v
	}
}

func validChannel(channel string, allowed []string) bool {
	channel = strings.ToLower(strings.TrimSpace(channel))
	if !validToken(channel) {
		return false
	}
	if len(allowed) == 0 {
		return channel == "stable" || channel == "beta"
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), channel) {
			return true
		}
	}
	return false
}

func validToken(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func isHex(v string, length int) bool {
	if len(v) != length {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func validateImmutableURL(raw string, opts VerifyOptions) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("malformed URL")
	}
	if u.RawQuery != "" {
		return errors.New("query strings are not allowed")
	}
	host := strings.ToLower(u.Hostname())
	isLoopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil {
		isLoopback = ip.IsLoopback()
	}
	if !strings.EqualFold(u.Scheme, "https") {
		if !(opts.AllowLoopbackHTTP && strings.EqualFold(u.Scheme, "http") && isLoopback) {
			return errors.New("HTTPS required")
		}
	}
	if len(opts.AllowedHosts) > 0 {
		allowed := false
		for _, h := range opts.AllowedHosts {
			if strings.EqualFold(strings.TrimSpace(h), u.Hostname()) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("host is not allowlisted")
		}
	}
	clean := strings.ToLower(path.Clean(u.EscapedPath()))
	for _, forbidden := range []string{"/latest", "/refs/heads/main", "/archive/main", "/heads/main", "latest.zip", "latest.tar"} {
		if strings.Contains(clean, forbidden) {
			return errors.New("moving release URL is forbidden")
		}
	}
	return nil
}
