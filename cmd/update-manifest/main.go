// SPDX-License-Identifier: MIT
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/updatepolicy"
)

type artifactInventory struct {
	Artifacts []updatepolicy.Artifact `json:"artifacts"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "update-manifest:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("update-manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		inventoryPath = fs.String("artifacts", "", "JSON artifact inventory")
		outputPath    = fs.String("output", "router-vpn-update-v1.json", "output manifest path")
		channel       = fs.String("channel", "stable", "stable or beta")
		sequence      = fs.Uint64("sequence", 0, "monotonic release sequence")
		commitSHA     = fs.String("commit", "", "exact 40-hex source SHA")
		releaseURL    = fs.String("release-url", "", "immutable exact-SHA release URL")
		validFor      = fs.Duration("valid-for", 7*24*time.Hour, "manifest validity period")
		publishedAt   = fs.String("published-at", "", "RFC3339 publication time; defaults to now")
		privateKeyFile = fs.String("private-key-file", "", "private key file; environment is preferred in CI")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inventoryPath == "" || *outputPath == "" || *sequence == 0 || !exactSHA(*commitSHA) {
		return errors.New("artifacts, output, non-zero sequence, and exact commit SHA are required")
	}
	if *validFor <= 0 || *validFor > 31*24*time.Hour {
		return errors.New("valid-for must be within 31 days")
	}
	published := time.Now().UTC().Truncate(time.Second)
	if strings.TrimSpace(*publishedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*publishedAt))
		if err != nil {
			return fmt.Errorf("parse published-at: %w", err)
		}
		published = parsed.UTC()
	}
	artifacts, err := readArtifacts(*inventoryPath)
	if err != nil {
		return err
	}
	privateKey, err := readPrivateKey(*privateKeyFile)
	if err != nil {
		return err
	}
	manifest := updatepolicy.Manifest{
		Schema:      updatepolicy.SchemaV1,
		Channel:     strings.ToLower(strings.TrimSpace(*channel)),
		Sequence:    *sequence,
		CommitSHA:   strings.ToLower(*commitSHA),
		PublishedAt: published,
		ExpiresAt:   published.Add(*validFor),
		ReleaseURL:  strings.TrimSpace(*releaseURL),
		Artifacts:   artifacts,
	}
	if err := manifest.Validate(updatepolicy.VerifyOptions{Now: published}); err != nil {
		return err
	}
	if err := manifest.Sign(privateKey); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := atomicPublicWrite(*outputPath, encoded); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote signed update manifest for %s sequence %d to %s\n", manifest.CommitSHA, manifest.Sequence, *outputPath)
	return nil
}

func readArtifacts(path string) ([]updatepolicy.Artifact, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > updatepolicy.MaxManifestBytes {
		return nil, errors.New("artifact inventory must be a bounded regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	dec := json.NewDecoder(io.LimitReader(file, updatepolicy.MaxManifestBytes+1))
	dec.DisallowUnknownFields()
	var wrapped artifactInventory
	if err := dec.Decode(&wrapped); err == nil && len(wrapped.Artifacts) > 0 {
		return wrapped.Artifacts, nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	dec = json.NewDecoder(io.LimitReader(file, updatepolicy.MaxManifestBytes+1))
	dec.DisallowUnknownFields()
	var bare []updatepolicy.Artifact
	if err := dec.Decode(&bare); err != nil {
		return nil, fmt.Errorf("decode artifact inventory: %w", err)
	}
	if len(bare) == 0 {
		return nil, errors.New("artifact inventory is empty")
	}
	return bare, nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv("ROUTER_VPN_UPDATE_SIGNING_KEY"))
	if raw == "" && strings.TrimSpace(path) != "" {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
			return nil, errors.New("private key must be a bounded regular non-symlink file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("private key file permissions must be 0600 or stricter")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = strings.TrimSpace(string(data))
	}
	if raw == "" {
		return nil, errors.New("ROUTER_VPN_UPDATE_SIGNING_KEY or private-key-file is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("private key must be base64")
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, errors.New("private key must be an Ed25519 seed or private key")
	}
}

func atomicPublicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".router-vpn-update-manifest-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("refusing to replace unsafe manifest path")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func exactSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := strconv.ParseUint(value[:16], 16, 64)
	if err != nil {
		return false
	}
	for _, r := range value[16:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
