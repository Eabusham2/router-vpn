package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"router-vpn/internal/mobilemultihop"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

// Every native candidate allocation is returned as this original handle before
// Prepare writes the inherited authenticated pipe. No owner/key cleanup lookup.
type relayNodeChainCandidateOperation struct {
	self                        *relayNodeChainCandidateOperation
	process                     *relayNodeChainProcess
	capture                     multihoprelay.NodeChainCandidateCapture
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	attempted, retired, drained bool
	prepareDone                 chan struct{}
	closeGate                   chan struct{}
	responseFile                string
	responseFileOwner           os.FileInfo
	responseCurrent             func() bool
}

func (p *relayNodeChainProcess) NewCandidateOperation(ctx context.Context, c multihoprelay.NodeChainCandidateCapture) (multihoprelay.NodeChainCandidateOperation, error) {
	digest, err := c.Lease.Digest()
	if p == nil || p.candidateOwnerSelf != p || ctx == nil || ctx.Err() != nil || c.Validate() != nil || err != nil || digest != p.digest || !p.Alive() || time.Now().UnixMilli() >= c.Request.DeadlineAt {
		return nil, multihoprelay.ErrUnavailable
	}
	p.candidateMu.Lock()
	defer p.candidateMu.Unlock()
	if p.candidate != nil {
		return nil, multihoprelay.ErrBusy
	}
	owned, cancel := context.WithDeadline(ctx, time.UnixMilli(c.Request.DeadlineAt))
	op := &relayNodeChainCandidateOperation{process: p, capture: c.Clone(), ctx: owned, cancel: cancel, closeGate: make(chan struct{}, 1)}
	op.self = op
	p.candidate = op
	return op, nil
}
func (op *relayNodeChainCandidateOperation) original() bool {
	if op == nil || op.self != op || op.process == nil || op.process.candidateOwnerSelf != op.process {
		return false
	}
	op.process.candidateMu.Lock()
	defer op.process.candidateMu.Unlock()
	return op.process.candidate == op
}
func (op *relayNodeChainCandidateOperation) Prepare(ctx context.Context) (multihoprelay.NodeChainCandidateReceipt, error) {
	if !op.original() || ctx == nil || ctx.Err() != nil {
		return multihoprelay.NodeChainCandidateReceipt{}, multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	if op.attempted || op.retired || op.ctx.Err() != nil {
		op.mu.Unlock()
		return multihoprelay.NodeChainCandidateReceipt{}, multihoprelay.ErrUnavailable
	}
	op.attempted = true
	op.prepareDone = make(chan struct{})
	done := op.prepareDone
	op.mu.Unlock()
	defer close(done)
	bounded, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(op.ctx, cancel)
	defer func() { stop(); cancel() }()
	if op.capture.Request.Schema == 2 || op.capture.Request.Schema == 3 {
		if err := op.prepareResponseSource(bounded); err != nil {
			return multihoprelay.NodeChainCandidateReceipt{}, err
		}
	}
	response, err := op.process.candidateRequest(bounded, "candidate-prepare", op.capture)
	if err != nil || response.Receipt == nil || !op.original() || op.ctx.Err() != nil || op.responseCurrent != nil && !op.responseCurrent() {
		return multihoprelay.NodeChainCandidateReceipt{}, multihoprelay.ErrUnavailable
	}
	return *response.Receipt, nil
}
func (op *relayNodeChainCandidateOperation) Snapshot(ctx context.Context) (multihoprelay.NodeChainCandidateReceipt, error) {
	if !op.original() || ctx == nil || ctx.Err() != nil {
		return multihoprelay.NodeChainCandidateReceipt{}, multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	ready := op.attempted && !op.retired && op.ctx.Err() == nil
	done := op.prepareDone
	op.mu.Unlock()
	if !ready {
		return multihoprelay.NodeChainCandidateReceipt{}, multihoprelay.ErrUnavailable
	}
	select {
	case <-done:
	default:
		return multihoprelay.NodeChainCandidateReceipt{}, multihoprelay.ErrBusy
	}
	bounded, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(op.ctx, cancel)
	defer func() { stop(); cancel() }()
	if op.responseCurrent != nil && !op.responseCurrent() {
		return multihoprelay.NodeChainCandidateReceipt{}, multihoprelay.ErrOwnership
	}
	response, err := op.process.candidateRequest(bounded, "candidate-status", op.capture)
	if err != nil || response.Receipt == nil || !op.original() || op.ctx.Err() != nil || op.responseCurrent != nil && !op.responseCurrent() {
		return multihoprelay.NodeChainCandidateReceipt{}, multihoprelay.ErrUnavailable
	}
	return *response.Receipt, nil
}
func (op *relayNodeChainCandidateOperation) Close(ctx context.Context) error {
	if op == nil || op.self != op || ctx == nil {
		return multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	if op.drained {
		op.mu.Unlock()
		return nil
	}
	op.mu.Unlock()
	if !op.original() {
		return multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	op.retired = true
	op.cancel()
	done := op.prepareDone
	op.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case op.closeGate <- struct{}{}:
		defer func() { <-op.closeGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	op.mu.Lock()
	drained := op.drained
	op.mu.Unlock()
	if drained {
		return nil
	}
	if !op.original() {
		return multihoprelay.ErrOwnership
	}
	if _, err := op.process.candidateRequest(ctx, "candidate-close", op.capture); err != nil {
		// Whole-owner Close drains its original candidate before emitting closed.
		// Once that owner terminates, no further candidate IPC can succeed. Only
		// its exact clean joined proof may replace the impossible per-op reply.
		p := op.process
		if p.Alive() {
			return err
		}
		if joinErr := p.lock(ctx); joinErr != nil {
			return joinErr
		}
		joinErr := p.joinedCleanupProof(ctx)
		<-p.gate
		if joinErr != nil {
			return joinErr
		}
	}
	if op.responseFile != "" {
		if err := op.process.lock(ctx); err != nil {
			return err
		}
		var removal error
		if root := op.process.root; root != nil {
			info, e := root.Lstat(op.responseFile)
			switch {
			case errors.Is(e, os.ErrNotExist):
			case e != nil:
				removal = e
			case op.responseFileOwner == nil || !os.SameFile(op.responseFileOwner, info):
				removal = multihoprelay.ErrOwnership
			default:
				removal = root.Remove(op.responseFile)
			}
		} else if !op.process.cleaned {
			removal = multihoprelay.ErrOwnership
		}
		<-op.process.gate
		if removal != nil {
			return removal
		}
		op.responseFile = ""
	}
	op.process.candidateMu.Lock()
	defer op.process.candidateMu.Unlock()
	if op.process.candidate != op {
		return multihoprelay.ErrOwnership
	}
	op.mu.Lock()
	op.drained = true
	op.mu.Unlock()
	op.process.candidate = nil
	return nil
}

// p.gate serializes candidate and legacy frames on the same original pipe.
func (p *relayNodeChainProcess) candidateRequest(ctx context.Context, operation string, c multihoprelay.NodeChainCandidateCapture) (multihoprelay.NodeChainCandidateIPCResponse, error) {
	bad := errors.New("original candidate worker did not answer")
	nonce, err := torIPCNonce()
	if err != nil {
		return multihoprelay.NodeChainCandidateIPCResponse{}, err
	}
	request := multihoprelay.NodeChainCandidateIPCRequest{Schema: 1, Operation: operation, Nonce: nonce, Capture: c.Clone()}
	if request.Validate() != nil || p.candidateOwnerSelf != p || !p.Alive() {
		return multihoprelay.NodeChainCandidateIPCResponse{}, bad
	}
	if err := p.lock(ctx); err != nil {
		return multihoprelay.NodeChainCandidateIPCResponse{}, err
	}
	defer func() { <-p.gate }()
	if operation != "candidate-close" && p.current != nil && !p.current() {
		return multihoprelay.NodeChainCandidateIPCResponse{}, bad
	}
	p.responseMu.Lock()
	select {
	case <-p.candidateResponses:
	default:
	}
	p.pendingCandidate = &request
	p.responded = false
	p.responseMu.Unlock()
	defer func() { p.responseMu.Lock(); p.pendingCandidate = nil; p.responseMu.Unlock() }()
	if file, ok := p.input.(*os.File); ok {
		deadline := time.Now().Add(time.Second)
		if limit, yes := ctx.Deadline(); yes && limit.Before(deadline) {
			deadline = limit
		}
		if file.SetWriteDeadline(deadline) != nil {
			return multihoprelay.NodeChainCandidateIPCResponse{}, bad
		}
		defer file.SetWriteDeadline(time.Time{})
	}
	frame, err := multihoprelay.MarshalNodeChainCandidateWorkerRequest(request)
	if err != nil {
		return multihoprelay.NodeChainCandidateIPCResponse{}, bad
	}
	defer clear(frame)
	if json.NewEncoder(p.input).Encode(json.RawMessage(frame)) != nil {
		return multihoprelay.NodeChainCandidateIPCResponse{}, bad
	}
	select {
	case response := <-p.candidateResponses:
		if response.Validate(request) == nil && ctx.Err() == nil && p.Alive() && (operation == "candidate-close" || p.current == nil || p.current()) {
			return response, nil
		}
	case <-p.readerDone:
	case <-ctx.Done():
	}
	return multihoprelay.NodeChainCandidateIPCResponse{}, bad
}
func (p *relayNodeChainProcess) candidateResponse(raw []byte) bool {
	var hint struct {
		Operation string `json:"operation"`
		Nonce     string `json:"nonce"`
	}
	if json.Unmarshal(raw, &hint) != nil || (hint.Operation != "candidate-prepare" && hint.Operation != "candidate-status" && hint.Operation != "candidate-close") {
		return false
	}
	p.responseMu.Lock()
	defer p.responseMu.Unlock()
	// Consuming a response clears pendingCandidate and a later request resets
	// responded. Neither event makes a second copy of that original response
	// legitimate. Keep its nonce independently of the replaceable mailbox.
	if p.candidateResponseNonce != "" && hint.Nonce == p.candidateResponseNonce {
		p.bad.Store(true)
		return true
	}
	request := p.pendingCandidate
	// Late replies have no authority and never enter a replacement's mailbox.
	if request == nil || request.Nonce != hint.Nonce {
		return true
	}
	if p.responded {
		p.bad.Store(true)
		return true
	}
	p.responded = true
	p.candidateResponseNonce = hint.Nonce
	response, err := multihoprelay.DecodeNodeChainCandidateIPCResponse(raw, *request)
	if err != nil {
		response = multihoprelay.NodeChainCandidateIPCResponse{}
	}
	select {
	case p.candidateResponses <- response:
	default:
		p.bad.Store(true)
	}
	return true
}

func (op *relayNodeChainCandidateOperation) prepareResponseSource(ctx context.Context) error {
	p := op.process
	if p.responseSource == nil || !op.original() {
		return multihoprelay.ErrUnavailable
	}
	input, current, err := p.responseSource(ctx, op.capture)
	if err == multihoprelay.ErrCandidateNotRegistered && ctx.Err() == nil && op.original() {
		return multihoprelay.ErrCandidateNotRegistered
	}
	if err != nil || current == nil || !current() {
		return multihoprelay.ErrUnavailable
	}
	if op.capture.Request.Schema == 3 {
		_, err = mobilemultihop.NewNodeChainServerPublicCandidateResponder(op.capture, input)
	} else {
		_, err = mobilemultihop.NewNodeChainServerCandidateResponder(op.capture, input)
	}
	if err != nil {
		return multihoprelay.ErrUnavailable
	}
	if err := p.lock(ctx); err != nil {
		return err
	}
	defer func() { <-p.gate }()
	if p.root == nil || !p.Alive() {
		return multihoprelay.ErrUnavailable
	}
	name := op.capture.ResponseSourceFile()
	file, err := p.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	op.responseFile = name
	op.responseFileOwner, err = file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	n, writeErr := io.WriteString(file, input)
	if n != len(input) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	if err = errors.Join(writeErr, file.Close(), ctx.Err()); err != nil {
		return err
	}
	op.responseCurrent = current
	if !current() {
		return multihoprelay.ErrOwnership
	}
	return nil
}
