package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

type relayNodeChainPrefixCandidateOperation struct {
	self                                                      *relayNodeChainPrefixCandidateOperation
	process                                                   *relayNodeChainPrefixProcess
	capture                                                   multihoprelay.NodeChainPrefixCandidateCapture
	digest                                                    string
	mu                                                        sync.Mutex
	attempted, prepared, drained, retired, publicationStarted bool
}

func (p *relayNodeChainPrefixProcess) NewPrefixCandidateOperation(ctx context.Context, c multihoprelay.NodeChainPrefixCandidateCapture) (multihoprelay.NodeChainPrefixCandidateOperation, error) {
	if p == nil || p.self != p || ctx == nil || ctx.Err() != nil || c.Validate() != nil || !p.Alive() || p.current == nil || !p.current() {
		return nil, multihoprelay.ErrOwnership
	}
	parent, err := c.Lease.Digest()
	if err != nil || parent != p.digest || !time.Now().Before(c.Deadline) {
		return nil, multihoprelay.ErrOwnership
	}
	digest, err := c.Digest()
	if err != nil {
		return nil, err
	}
	p.candidateMu.Lock()
	defer p.candidateMu.Unlock()
	if p.candidate != nil {
		return nil, multihoprelay.ErrBusy
	}
	op := &relayNodeChainPrefixCandidateOperation{process: p, capture: c.Clone(), digest: digest}
	op.self = op
	p.candidate = op
	if ctx.Err() != nil {
		return op, ctx.Err()
	}
	return op, nil
}

func (op *relayNodeChainPrefixCandidateOperation) original() bool {
	if op == nil || op.self != op || op.process == nil || op.process.self != op.process {
		return false
	}
	digest, err := op.capture.Digest()
	if err != nil || digest != op.digest {
		return false
	}
	op.process.candidateMu.Lock()
	defer op.process.candidateMu.Unlock()
	return op.process.candidate == op
}

// The original process gate is held through this admission and the stdin Write.
// Once admitted, even a short or failed write remains ambiguous until an actual
// candidate-close receipt or the original whole-worker joined proof is obtained.
func (p *relayNodeChainPrefixProcess) beginCandidatePreparePublication(c *multihoprelay.NodeChainPrefixCandidateCapture) error {
	if p == nil || p.self != p || c == nil {
		return multihoprelay.ErrOwnership
	}
	digest, err := c.Digest()
	if err != nil {
		return err
	}
	p.candidateMu.Lock()
	defer p.candidateMu.Unlock()
	op := p.candidate
	if op == nil || op.self != op || op.process != p || digest != op.digest {
		return multihoprelay.ErrOwnership
	}
	original, err := op.capture.Digest()
	if err != nil || original != digest {
		return multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if !op.attempted || op.retired || op.drained || op.publicationStarted {
		return multihoprelay.ErrOwnership
	}
	op.publicationStarted = true
	return nil
}

func (op *relayNodeChainPrefixCandidateOperation) exchange(ctx context.Context, operation, challenge string) (multihoprelay.NodeChainPrefixCandidateReceipt, error) {
	if !op.original() || ctx == nil || ctx.Err() != nil {
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, multihoprelay.ErrOwnership
	}
	p := op.process
	if err := p.lock(ctx); err != nil {
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, err
	}
	defer func() { <-p.gate }()
	return op.exchangeLocked(ctx, operation, challenge)
}

// exchangeLocked retains the same original process gate as Close and Write.
func (op *relayNodeChainPrefixCandidateOperation) exchangeLocked(ctx context.Context, operation, challenge string) (multihoprelay.NodeChainPrefixCandidateReceipt, error) {
	bad := multihoprelay.ErrOwnership
	if !op.original() || ctx == nil || ctx.Err() != nil {
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, bad
	}
	p := op.process
	op.mu.Lock()
	retired := op.retired || op.drained
	op.mu.Unlock()
	if operation != "candidate-close" && (retired || !p.Alive() || p.current == nil || !p.current() || !time.Now().Before(op.capture.Deadline)) {
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, bad
	}
	nonce := challenge
	var err error
	if nonce == "" {
		nonce, err = torIPCNonce()
		if err != nil {
			return multihoprelay.NodeChainPrefixCandidateReceipt{}, err
		}
	}
	began := time.Now()
	capture := op.capture.Clone()
	reply, err := p.request(ctx, operation, nonce, &capture)
	expected := nonce
	if operation == "candidate-prepare" {
		expected = ""
	}
	if err != nil || reply.CandidateReceipt == nil || reply.CandidateReceipt.Validate(op.capture, expected, began, time.Now()) != nil || ctx.Err() != nil || !op.original() {
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, errors.Join(err, bad)
	}
	if operation != "candidate-close" && (p.current == nil || !p.current() || !p.Alive()) {
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, bad
	}
	if operation == "candidate-prepare" {
		op.mu.Lock()
		if op.retired || op.drained {
			op.mu.Unlock()
			return multihoprelay.NodeChainPrefixCandidateReceipt{}, bad
		}
		op.prepared = reply.CandidateReceipt.Prepared && !reply.CandidateReceipt.Drained
		op.mu.Unlock()
	}
	return *reply.CandidateReceipt, nil
}

func (op *relayNodeChainPrefixCandidateOperation) Prepare(ctx context.Context) (multihoprelay.NodeChainPrefixCandidateReceipt, error) {
	if !op.original() {
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	if op.attempted || op.drained || op.retired {
		op.mu.Unlock()
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, multihoprelay.ErrOwnership
	}
	op.attempted = true
	op.mu.Unlock()
	receipt, err := op.exchange(ctx, "candidate-prepare", "")
	if err != nil || !receipt.Prepared || receipt.Drained {
		return receipt, errors.Join(err, multihoprelay.ErrUnavailable)
	}
	return receipt, nil
}

func (op *relayNodeChainPrefixCandidateOperation) Snapshot(ctx context.Context, nonce string) (multihoprelay.NodeChainPrefixCandidateReceipt, error) {
	if nonce == "" {
		return multihoprelay.NodeChainPrefixCandidateReceipt{}, multihoprelay.ErrOwnership
	}
	return op.exchange(ctx, "candidate-status", nonce)
}

func (op *relayNodeChainPrefixCandidateOperation) Close(ctx context.Context) error {
	if op == nil || op.self != op || ctx == nil {
		return multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	if op.drained {
		op.mu.Unlock()
		return nil
	}
	// Seal retirement before waiting: a queued Prepare cannot publish afterward.
	op.retired = true
	op.mu.Unlock()
	if !op.original() {
		return multihoprelay.ErrOwnership
	}
	p := op.process
	if err := p.lock(ctx); err != nil {
		return err
	}
	defer func() { <-p.gate }()
	op.mu.Lock()
	done, published := op.drained, op.publicationStarted
	op.mu.Unlock()
	if done {
		return nil
	}
	if !op.original() || ctx.Err() != nil {
		return errors.Join(ctx.Err(), multihoprelay.ErrOwnership)
	}
	if published {
		receipt, err := op.exchangeLocked(ctx, "candidate-close", "")
		if err != nil || !receipt.Drained || receipt.Prepared {
			if p.Alive() {
				return errors.Join(err, multihoprelay.ErrUnavailable)
			}
			// Whole-owner Close drains its original candidate before closed.
			// Only its authenticated terminal record and both original joins
			// can replace an impossible candidate-close reply.
			if joinErr := p.joinedCleanupProof(ctx); joinErr != nil {
				return joinErr
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.candidateMu.Lock()
	defer p.candidateMu.Unlock()
	if p.candidate != op {
		return multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	op.drained = true
	op.prepared = false
	op.mu.Unlock()
	p.candidate = nil
	return nil
}
