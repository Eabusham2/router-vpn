package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

const nodeChainAppendPrefixLeasePath = "/api/multihop/chain/prefix/lease"
const nodeChainAppendPrefixCandidatePath = "/api/multihop/chain/prefix/candidate"

func (s *nodeChainExecutionIO) exchangePrefix(ctx context.Context, method string, payload []byte) ([]byte, error) {
	if method == "GET" {
		if len(payload) != 0 {
			return nil, errNodeChainAppendExecution
		}
		return s.exchangeCaptured(ctx, method, nodeChainAppendPrefixLeasePath, nil, multihoprelay.MaxNodeChainPrefixCapabilitiesBytes)
	}
	if method != "PUT" && method != "POST" && method != "DELETE" {
		return nil, errNodeChainAppendExecution
	}
	if _, _, err := multihoprelay.DecodeNodeChainPrefixRequest(payload, method == "POST"); err != nil {
		return nil, err
	}
	return s.exchangeCaptured(ctx, method, nodeChainAppendPrefixLeasePath, payload, multihoprelay.NodeChainPrefixIPCMaximumBytes)
}
func (s *nodeChainExecutionIO) exchangePrefixCandidate(ctx context.Context, method string, payload []byte) ([]byte, error) {
	if method != "PUT" && method != "POST" && method != "DELETE" {
		return nil, errNodeChainAppendExecution
	}
	if _, _, err := multihoprelay.DecodeNodeChainPrefixCandidateRequest(payload, method == "POST"); err != nil {
		return nil, err
	}
	return s.exchangeCaptured(ctx, method, nodeChainAppendPrefixCandidatePath, payload, 16<<10)
}

type nodeChainAppendExecutionLease struct {
	self                     *nodeChainAppendExecutionLease
	runtime                  *NodeChainCandidateAppendExecutionRuntime
	request                  multihoprelay.NodeChainPrefixRequest
	descriptor               multihoprelay.NodeChainPrefixDescriptor
	lease                    multihoprelay.NodeChainPrefixLease
	capture                  multihoprelay.NodeChainPrefixCapture
	control                  *nodeChainExecutionIO
	stop                     *nodeChainAppendExecutionRetirement
	front                    string
	ctx                      context.Context
	cancel                   context.CancelFunc
	ready                    chan struct{}
	gate                     chan struct{}
	mu                       sync.Mutex
	issued, prepared, closed bool
	sequence                 uint64
	candidate                *nodeChainAppendExecutionRemoteCandidate
}

func (r *NodeChainCandidateAppendExecutionRuntime) newLease(parent context.Context) (*nodeChainAppendExecutionLease, error) {
	if parent == nil || r.HealthyContext(parent) != nil {
		return nil, errNodeChainAppendExecution
	}
	r.mu.Lock()
	if len(r.pending) != 0 {
		r.mu.Unlock()
		return nil, errNodeChainAppendExecution
	}
	ctx, cancel := context.WithCancel(r.lifetime)
	lease := &nodeChainAppendExecutionLease{runtime: r, ctx: ctx, cancel: cancel, ready: make(chan struct{}), gate: make(chan struct{}, 1)}
	lease.self = lease
	r.pending[lease] = true
	r.mu.Unlock()
	err := lease.initialize(parent)
	return lease, err
}
func (l *nodeChainAppendExecutionLease) initialize(ctx context.Context) (failure error) {
	defer close(l.ready)
	r := l.runtime
	discovery, descriptor, err := r.fetchDiscovery(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	original, originalDescriptor, port := r.discovery, r.descriptor, r.captured.Proposal.Port
	r.mu.Unlock()
	oldDigest, _ := originalDescriptor.Digest()
	digest, _ := descriptor.Digest()
	if digest != oldDigest || discovery.Challenge.Epoch != original.Challenge.Epoch || discovery.Challenge.Peer != original.Challenge.Peer || discovery.FirstPort != original.FirstPort || discovery.LastPort != original.LastPort || port < discovery.FirstPort || port > discovery.LastPort {
		return errNodeChainAppendExecution
	}
	session, err := randomHex(16)
	if err != nil {
		return err
	}
	seed, err := randomHex(32)
	if err != nil {
		return err
	}
	p := r.preparation.policy
	keys := make([]string, 0, len(p.localMembers))
	for _, member := range p.localMembers {
		if NodeChainPrefixMode(member.Mode) {
			keys = append(keys, member.ClientPublicKey)
		}
	}
	prefixCount := 0
	if descriptor.Schema == 2 {
		prefixCount = len(p.localMembers)
	}
	q := multihoprelay.NodeChainPrefixRequest{Schema: descriptor.Schema, Purpose: multihoprelay.NodeChainPrefixPurpose, SessionID: session, EntryNodeID: descriptor.EntryNodeID, SourceSHA256: descriptor.SourceSHA256, DescriptorSHA256: digest, LocalSourceSHA256: p.OriginalSourceSHA256(), InventorySHA256: p.inventorySHA, Epoch: discovery.Challenge.Epoch, Peer: discovery.Challenge.Peer, AcquireExpiresAt: discovery.Challenge.ExpiresAt, LocalPacketPublicKeys: keys, PrefixCount: prefixCount, Port: port, FrontSeed: seed}
	if q.Validate(descriptor) != nil {
		return errNodeChainAppendExecution
	}
	l.request, l.descriptor = q, descriptor
	l.control, err = r.newControl()
	if err != nil {
		return err
	}
	l.stop, err = r.newRetirement(l, nil)
	if err != nil {
		return err
	}
	body, err := json.Marshal(q)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.issued = true
	l.mu.Unlock()
	raw, err := l.control.exchangePrefix(ctx, "PUT", body)
	if err != nil {
		return err
	}
	lease, err := multihoprelay.DecodeNodeChainPrefixLease(raw, q, descriptor)
	if err != nil {
		return err
	}
	capture, err := lease.Capture(descriptor)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.lease, l.capture, l.front = lease, capture, net.JoinHostPort(lease.Host, strconv.Itoa(lease.Port))
	l.mu.Unlock()
	for {
		if err = l.verifyPrefix(ctx, true); err != nil {
			return err
		}
		l.mu.Lock()
		prepared := l.prepared
		l.mu.Unlock()
		if prepared {
			return r.HealthyContext(ctx)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-l.ctx.Done():
			timer.Stop()
			return l.ctx.Err()
		case <-timer.C:
		}
	}
}
func (l *nodeChainAppendExecutionLease) lock(ctx context.Context) error {
	if ctx == nil {
		return errNodeChainAppendExecution
	}
	select {
	case l.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (l *nodeChainAppendExecutionLease) frontCurrent() bool {
	if l == nil || l.self != l {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prepared && !l.closed && l.ctx.Err() == nil && l.capture.Validate() == nil && l.front != "" && time.Now().Before(l.lease.ExpiresAt)
}
func (l *nodeChainAppendExecutionLease) verifyPrefix(ctx context.Context, pending bool) error {
	if err := l.lock(ctx); err != nil {
		return err
	}
	defer func() { <-l.gate }()
	if err := l.runtime.HealthyContext(ctx); err != nil {
		return err
	}
	l.mu.Lock()
	capture, closed, prepared, sequence := l.capture, l.closed, l.prepared, l.sequence
	l.mu.Unlock()
	if closed || l.ctx.Err() != nil || capture.Validate() != nil || !pending && !prepared {
		return errNodeChainAppendExecution
	}
	nonce, err := randomHex(32)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Request multihoprelay.NodeChainPrefixRequest `json:"request"`
		Nonce   string                               `json:"nonce"`
	}{l.request, nonce})
	if err != nil {
		return err
	}
	started := time.Now()
	raw, err := l.control.exchangePrefix(ctx, "POST", body)
	if err != nil {
		return err
	}
	status, err := multihoprelay.DecodeNodeChainPrefixLeaseStatus(raw, capture, nonce, started, time.Now())
	if err != nil || status.Receipt.Sequence <= sequence || !time.Now().Before(status.Lease.ExpiresAt) || status.Receipt.Phase != multihoprelay.NodeChainPrefixPrepared && (!pending || status.Receipt.Phase != multihoprelay.NodeChainPrefixPending) {
		return errors.Join(err, errNodeChainAppendExecution)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.sequence != sequence {
		return errNodeChainAppendExecution
	}
	l.lease = status.Lease
	l.sequence = status.Receipt.Sequence
	l.prepared = status.Receipt.Phase == multihoprelay.NodeChainPrefixPrepared
	return ctx.Err()
}
func (l *nodeChainAppendExecutionLease) close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		return errNodeChainAppendExecution
	}
	l.cancel()
	select {
	case <-l.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := l.lock(ctx); err != nil {
		return err
	}
	defer func() { <-l.gate }()
	l.mu.Lock()
	closed, candidate, issued := l.closed, l.candidate, l.issued
	l.mu.Unlock()
	if closed {
		return nil
	}
	if candidate != nil {
		if err := candidate.close(ctx); err != nil {
			return err
		}
	}
	if issued {
		if l.stop == nil {
			return errNodeChainAppendExecution
		}
		if err := l.stop.stop(ctx); err != nil {
			return err
		}
	}
	if l.control != nil {
		if err := l.control.close(ctx); err != nil {
			return err
		}
	}
	if l.stop != nil {
		if err := l.stop.close(ctx); err != nil {
			return err
		}
	}
	l.mu.Lock()
	l.closed = true
	l.prepared = false
	l.mu.Unlock()
	l.runtime.mu.Lock()
	delete(l.runtime.pending, l)
	l.runtime.mu.Unlock()
	return ctx.Err()
}

type nodeChainAppendExecutionRemoteCandidate struct {
	self                     *nodeChainAppendExecutionRemoteCandidate
	lease                    *nodeChainAppendExecutionLease
	source                   candidateResponseSource
	request                  multihoprelay.NodeChainPrefixCandidateRequest
	capture                  multihoprelay.NodeChainPrefixCandidateCapture
	control                  *nodeChainExecutionIO
	stop                     *nodeChainAppendExecutionRetirement
	io                       *leaseStopIO
	ctx                      context.Context
	cancel                   context.CancelFunc
	ready                    chan struct{}
	gate                     chan struct{}
	mu                       sync.Mutex
	issued, prepared, closed bool
	dials                    int
}

func (l *nodeChainAppendExecutionLease) newCandidate(ctx context.Context, source candidateResponseSource, purpose, externalTarget string) (*nodeChainAppendExecutionRemoteCandidate, error) {
	if !l.frontCurrent() {
		return nil, errNodeChainAppendExecution
	}
	l.mu.Lock()
	if l.candidate != nil || l.closed {
		l.mu.Unlock()
		return nil, errNodeChainAppendExecution
	}
	lifetime, cancel := context.WithCancel(l.ctx)
	op := &nodeChainAppendExecutionRemoteCandidate{lease: l, source: source, ctx: lifetime, cancel: cancel, ready: make(chan struct{}), gate: make(chan struct{}, 1), io: newLeaseStopIO(lifetime)}
	op.self = op
	l.candidate = op
	l.mu.Unlock()
	err := op.initialize(ctx, purpose, externalTarget)
	return op, err
}
func (op *nodeChainAppendExecutionRemoteCandidate) initialize(ctx context.Context, purpose, externalTarget string) error {
	defer close(op.ready)
	l := op.lease
	if err := l.verifyPrefix(ctx, false); err != nil {
		return err
	}
	trial, err := randomHex(16)
	if err != nil {
		return err
	}
	operation, err := randomHex(16)
	if err != nil {
		return err
	}
	l.mu.Lock()
	lease, capture := l.lease, l.capture
	l.mu.Unlock()
	deadline := time.Now().Add(multihoprelay.NodeChainCandidateLifetime)
	if lease.ExpiresAt.Before(deadline) {
		deadline = lease.ExpiresAt
	}
	op.request = multihoprelay.NodeChainPrefixCandidateRequest{Schema: 1, Purpose: multihoprelay.NodeChainPrefixPurpose, Lease: l.request.Clone(), LeaseOwnerID: capture.OwnerID, TrialID: trial, OperationID: operation, CandidateID: op.source.Target.ID, CandidateSourceSHA256: op.source.Target.SourceSHA256, AppendPosition: l.runtime.preparation.AppendPosition(), InventorySHA256: l.request.InventorySHA256, ChildPurpose: purpose, ExternalTarget: externalTarget, ExpiresAt: deadline.UnixMilli()}
	mode := l.runtime.preparation.CandidateMode()
	if nodeChainAppendExecutionPacketMode(mode) {
		if l.descriptor.PacketCandidateMode() != mode || op.source.PacketOptions == "" || !nodeChainCanonicalPeer(op.source.ClientKey) {
			return errNodeChainAppendExecution
		}
		op.request.Schema = 2
		op.request.CandidateMode, op.request.CandidateClientPublicKey = mode, op.source.ClientKey
	}
	if op.request.Validate() != nil {
		return errNodeChainAppendExecution
	}
	op.control, err = l.runtime.newControl()
	if err != nil {
		return err
	}
	op.stop, err = l.runtime.newRetirement(l, op)
	if err != nil {
		return err
	}
	body, err := json.Marshal(op.request)
	if err != nil {
		return err
	}
	op.mu.Lock()
	op.issued = true
	op.mu.Unlock()
	started := time.Now()
	raw, err := op.control.exchangePrefixCandidate(ctx, "PUT", body)
	if err != nil {
		return err
	}
	var receipt multihoprelay.NodeChainPrefixCandidateReceipt
	if exactJSON(raw, &receipt, 16<<10) != nil {
		return errNodeChainAppendExecution
	}
	actual, err := multihoprelay.RestoreNodeChainPrefixCandidateCapture(capture, op.request, receipt.OwnerID)
	if err != nil || receipt.Validate(actual, "", started, time.Now()) != nil || !receipt.Prepared || receipt.Drained || receipt.Connections != 0 {
		return errNodeChainAppendExecution
	}
	op.mu.Lock()
	op.capture = actual
	op.prepared = true
	op.mu.Unlock()
	return ctx.Err()
}
func (op *nodeChainAppendExecutionRemoteCandidate) lock(ctx context.Context) error {
	if ctx == nil {
		return errNodeChainAppendExecution
	}
	select {
	case op.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (op *nodeChainAppendExecutionRemoteCandidate) current() bool {
	if op == nil || op.self != op {
		return false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.prepared && !op.closed && op.ctx.Err() == nil && time.Now().UnixMilli() < op.request.ExpiresAt && op.lease.frontCurrent()
}
func (op *nodeChainAppendExecutionRemoteCandidate) verify(ctx context.Context) error {
	if !op.current() {
		return errNodeChainAppendExecution
	}
	if err := op.lease.verifyPrefix(ctx, false); err != nil {
		return err
	}
	if err := op.lock(ctx); err != nil {
		return err
	}
	defer func() { <-op.gate }()
	nonce, err := randomHex(32)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Request multihoprelay.NodeChainPrefixCandidateRequest `json:"request"`
		Nonce   string                                        `json:"nonce"`
	}{op.request, nonce})
	if err != nil {
		return err
	}
	started := time.Now()
	raw, err := op.control.exchangePrefixCandidate(ctx, "POST", body)
	if err != nil {
		return err
	}
	op.mu.Lock()
	capture, count := op.capture, op.dials
	op.mu.Unlock()
	receipt, err := multihoprelay.DecodeNodeChainPrefixCandidateReceipt(raw, capture, nonce, started, time.Now())
	if err != nil || !receipt.Prepared || receipt.Drained || receipt.Connections != count {
		return errNodeChainAppendExecution
	}
	return ctx.Err()
}
func (op *nodeChainAppendExecutionRemoteCandidate) dial(ctx context.Context, ordinal int) (net.Conn, error) {
	if !op.current() || op.lease.runtime.HealthyContext(ctx) != nil {
		return nil, errNodeChainAppendExecution
	}
	if err := op.lock(ctx); err != nil {
		return nil, err
	}
	defer func() { <-op.gate }()
	api, err := privateAPI(op.source.API)
	if err != nil {
		return nil, err
	}
	grant, err := op.capture.FrontGrant(api.Host, ordinal)
	if err != nil {
		return nil, err
	}
	username, password, err := op.capture.FrontCredentials(grant, api.Host)
	if err != nil {
		return nil, err
	}
	call, finish, err := op.io.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	tag := op.lease.runtime.preparation.original.proofs[0].Tag
	original, err := op.lease.runtime.dialControl(call, tag, op.lease.front, op.lease, nil)
	var owned net.Conn
	var keepErr error
	if original != nil {
		owned, keepErr = op.io.keep(original)
	}
	if err != nil || keepErr != nil || owned == nil || !op.current() {
		if owned != nil {
			_ = owned.Close()
		}
		return nil, errors.Join(err, keepErr, errNodeChainAppendExecution)
	}
	if err = remoteCandidateSOCKSConnect(call, owned, username, password, grant.Address); err != nil {
		_ = owned.Close()
		return nil, err
	}
	op.mu.Lock()
	op.dials++
	op.mu.Unlock()
	return owned, nil
}
func (op *nodeChainAppendExecutionRemoteCandidate) close(ctx context.Context) error {
	if op == nil {
		return nil
	}
	op.cancel()
	op.io.retire()
	select {
	case <-op.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := op.lock(ctx); err != nil {
		return err
	}
	defer func() { <-op.gate }()
	op.mu.Lock()
	closed, issued := op.closed, op.issued
	op.mu.Unlock()
	if closed {
		return nil
	}
	if issued {
		if op.stop == nil {
			return errNodeChainAppendExecution
		}
		if err := op.stop.stop(ctx); err != nil {
			return err
		}
	}
	if op.control != nil {
		if err := op.control.close(ctx); err != nil {
			return err
		}
	}
	if err := op.io.wait(ctx); err != nil {
		return err
	}
	if op.stop != nil {
		if err := op.stop.close(ctx); err != nil {
			return err
		}
	}
	op.mu.Lock()
	op.closed = true
	op.prepared = false
	op.mu.Unlock()
	op.lease.mu.Lock()
	if op.lease.candidate == op {
		op.lease.candidate = nil
	}
	op.lease.mu.Unlock()
	return ctx.Err()
}
