package main

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"

	"router-vpn/internal/multihoprelay"
)

func (r *relayNodeChainExecRunner) originalCandidateSource(ctx context.Context, c multihoprelay.NodeChainCandidateCapture) (string, func() bool, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || c.Validate() != nil || (c.Request.Schema != 2 && c.Request.Schema != 3) {
		return "", nil, multihoprelay.ErrUnavailable
	}
	knownID := false
	for _, d := range r.registered {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		if d.EntryNodeID != c.Lease.Source.EntryNodeID {
			continue
		}
		if c.Request.Schema == 3 && !d.SameExternalFinalEntry(c.Lease.Source) {
			continue
		}
		for _, member := range d.Members {
			if member.ProfileID != c.Request.CandidateID {
				continue
			}
			knownID = true
			if member.Mode != "shadowsocks" || member.StartLayer != "off" ||
				c.Request.Schema == 2 && member.NodeKind != "" ||
				c.Request.Schema == 3 && (member.NodeKind != "external" || member.ProofKind != "public-path" || member.SourceSHA256 != c.Request.CandidateSourceSHA256) {
				continue
			}
			path := filepath.Join(r.sources, d.SourceSHA256+".json")
			raw, original, err := readNodeChainRegistration(path, nil)
			if err != nil {
				return "", nil, multihoprelay.ErrUnavailable
			}
			policy, err := parsePrivateNodeChainServerSource(raw)
			fingerprint := sha256.Sum256(raw)
			clear(raw)
			if err != nil {
				return "", nil, multihoprelay.ErrUnavailable
			}
			actual, err := policy.Descriptor().Digest()
			expected, e := d.Digest()
			if err != nil || e != nil || actual != expected {
				return "", nil, multihoprelay.ErrUnavailable
			}
			var input string
			if c.Request.Schema == 3 {
				input, err = policy.PublicCandidateResponseInput(c)
			} else {
				input, err = policy.CandidateResponseInput(c)
			}
			if err != nil {
				continue
			}
			current := func() bool {
				raw, _, err := readNodeChainRegistration(path, original)
				defer clear(raw)
				return err == nil && sha256.Sum256(raw) == fingerprint
			}
			if ctx.Err() != nil || !current() {
				return "", nil, multihoprelay.ErrUnavailable
			}
			return input, current, nil
		}
	}
	if !knownID && ctx.Err() == nil {
		return "", nil, multihoprelay.ErrCandidateNotRegistered
	}
	return "", nil, multihoprelay.ErrUnavailable
}

func readNodeChainRegistration(path string, previous os.FileInfo) ([]byte, os.FileInfo, error) {
	if err := validatePrivilegedStateFile(path, maxPrivilegedStateBytes); err != nil {
		return nil, nil, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 1 || before.Size() > maxPrivilegedStateBytes || previous != nil && (!os.SameFile(previous, before) || before.Size() != previous.Size() || !before.ModTime().Equal(previous.ModTime())) {
		return nil, nil, multihoprelay.ErrOwnership
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return nil, nil, multihoprelay.ErrOwnership
	}
	raw, err := io.ReadAll(io.LimitReader(file, before.Size()+1))
	after, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || int64(len(raw)) != before.Size() || !os.SameFile(before, after) || before.Mode() != after.Mode() || after.Size() != before.Size() || !before.ModTime().Equal(after.ModTime()) {
		clear(raw)
		return nil, nil, multihoprelay.ErrOwnership
	}
	return raw, before, nil
}
