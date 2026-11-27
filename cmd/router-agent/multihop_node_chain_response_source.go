package main

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sync"

	"router-vpn/internal/multihoprelay"
)

func (r *relayNodeChainExecRunner) originalCandidateSource(ctx context.Context, c multihoprelay.NodeChainCandidateCapture) (string, func() bool, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || c.Validate() != nil || (c.Request.Schema != 2 && c.Request.Schema != 3 && !c.Request.IsPacketResponse()) {
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
			if c.Request.IsPacketResponse() {
				if member.Mode != c.Request.CandidateMode || member.StartLayer != "off" || member.NodeKind != "" {
					continue
				}
			} else if member.Mode != "shadowsocks" || member.StartLayer != "off" ||
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
			if c.Request.IsPacketResponse() {
				input, err = policy.CandidatePacketResponseInput(c)
			} else if c.Request.Schema == 3 {
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

// The original runner owns every live worker and candidate reservation. A failed
// native close cannot free peer identities for another worker or operation.
type relayNodeChainPacketKeyReservation struct {
	self      *relayNodeChainPacketKeyReservation
	ledger    *relayNodeChainPacketKeyLedger
	process   *relayNodeChainProcess
	operation *relayNodeChainCandidateOperation
	keys      []string
}
type relayNodeChainPacketKeyLedger struct {
	mu     sync.Mutex
	owners map[*relayNodeChainPacketKeyReservation]bool
}

func (r *relayNodeChainPacketKeyLedger) reserve(p *relayNodeChainProcess, op *relayNodeChainCandidateOperation, keys []string) (*relayNodeChainPacketKeyReservation, error) {
	if r == nil || p == nil || p.candidateOwnerSelf != p || p.packetKeys != r || op != nil && (op.self != op || op.process != p) {
		return nil, multihoprelay.ErrOwnership
	}
	unique := make(map[string]bool, len(keys))
	for _, key := range keys {
		if key == "" || unique[key] {
			return nil, multihoprelay.ErrOwnership
		}
		unique[key] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owners == nil {
		r.owners = make(map[*relayNodeChainPacketKeyReservation]bool)
	}
	if op != nil && (p.packetBase == nil || !r.owners[p.packetBase] || p.packetBase.process != p || p.packetBase.operation != nil) {
		return nil, multihoprelay.ErrOwnership
	}
	for original := range r.owners {
		if original.process == p && original.operation == op {
			return nil, multihoprelay.ErrBusy
		}
		if original.operation == nil && op == nil {
			continue
		} // Existing full-worker sharing is unchanged.
		for _, key := range original.keys {
			if unique[key] {
				return nil, multihoprelay.ErrBusy
			}
		}
	}
	owner := &relayNodeChainPacketKeyReservation{ledger: r, process: p, operation: op, keys: append([]string(nil), keys...)}
	owner.self = owner
	r.owners[owner] = true
	return owner, nil
}
func (r *relayNodeChainPacketKeyLedger) release(owner *relayNodeChainPacketKeyReservation, p *relayNodeChainProcess, op *relayNodeChainCandidateOperation) error {
	if r == nil || owner == nil || owner.self != owner || owner.ledger != r || owner.process != p || owner.operation != op {
		return multihoprelay.ErrOwnership
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.owners[owner] {
		return multihoprelay.ErrOwnership
	}
	delete(r.owners, owner)
	return nil
}
