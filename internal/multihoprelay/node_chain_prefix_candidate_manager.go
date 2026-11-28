package multihoprelay

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// An operation remains attached to its exact lease until constructor, Prepare
// and native Close all join. A timeout never releases its replacement slot.
type nodeChainPrefixCandidateOwned struct {
	process    NodeChainPrefixProcess
	owner      *nodeChainPrefixOwnedProcess
	capture    NodeChainPrefixCandidateCapture
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	expiryDone chan struct{}
	closeGate  chan struct{}
	mu         sync.Mutex
	native     NodeChainPrefixCandidateOperation
	retired    bool
	drained    bool
	reads      int
	readDone   chan struct{}
}

// Exactly one owned expiry/cancellation worker attempts the bounded native join.
// Every external Close joins that worker before retrying the same native handle.
// A failed join retains the slot; a later Create can retry only an expired slot.
func (op *nodeChainPrefixCandidateOwned) runExpiry() {
	defer close(op.expiryDone)
	<-op.ctx.Done()
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = op.drain(cleanup)
}
func (op *nodeChainPrefixCandidateOwned) close(ctx context.Context) error {
	op.mu.Lock()
	op.retired = true
	op.cancel()
	op.mu.Unlock()
	select {
	case <-op.expiryDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	return op.drain(ctx)
}
func (op *nodeChainPrefixCandidateOwned) drain(ctx context.Context) error {
	op.mu.Lock()
	op.retired = true
	reads := op.readDone
	op.cancel()
	op.mu.Unlock()
	select {
	case <-op.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if reads != nil {
		select {
		case <-reads:
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
	native, drained := op.native, op.drained
	op.mu.Unlock()
	if drained {
		return nil
	}
	if native != nil {
		if err := native.Close(ctx); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	op.mu.Lock()
	op.drained = true
	op.mu.Unlock()
	op.owner.mu.Lock()
	if op.owner.candidate == op {
		op.owner.candidate = nil
	}
	op.owner.mu.Unlock()
	return nil
}

// Retain canonical requests for exact late cancellation acknowledgments until
// bounded admission needs capacity. A live original is never evicted, and
// pruning cannot authorize an expired PUT or an unknown expired DELETE.
func (o *nodeChainPrefixOwnedProcess) pruneCandidateAttempts(now time.Time) {
	if len(o.candidateAttempts) < nodeChainPrefixAttemptLimit {
		return
	}
	for id, q := range o.candidateAttempts {
		if q.ExpiresAt <= now.UnixMilli() && (o.candidate == nil || o.candidate.capture.Request.OperationID != id) {
			delete(o.candidateAttempts, id)
		}
	}
}
func sameNodeChainPrefixCandidate(a, b NodeChainPrefixCandidateRequest) bool {
	x, e := a.Digest()
	y, f := b.Digest()
	return e == nil && f == nil && x == y
}

// Lookup checks the original registry on every admission/status. Cleanup uses
// only captured authority, so a removed registry cannot strand its own sockets.
func (m *Manager) prefixCandidateOwner(peer netip.Addr, q NodeChainPrefixCandidateRequest, cleanup bool) (*nodeChainPrefixOwnedProcess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if q.Validate() != nil || m.validatePrefixRequest(peer, q.Lease) != nil {
		return nil, ErrOwnership
	}
	active := m.leases[PeerKey(peer)]
	if active == nil || active.prefix == nil || !sameNodeChainPrefixRequest(active.prefix.capture.Request, q.Lease) {
		return nil, ErrOwnership
	}
	o := active.prefix
	if o.capture.Validate() != nil || q.LeaseOwnerID != o.capture.OwnerID {
		return nil, ErrOwnership
	}
	if !cleanup {
		source, err := m.prefixSourceLocked(q.Lease)
		if m.closed || active.retired || !active.ExpiresAt.After(m.now()) || q.ExpiresAt > active.ExpiresAt.UnixMilli() || err != nil || !sameNodeChainPrefixSource(source, o.capture.Source) {
			return nil, ErrOwnership
		}
	}
	return o, nil
}
func (m *Manager) prefixCandidateCurrent(ctx context.Context, peer netip.Addr, q NodeChainPrefixCandidateRequest, expected *nodeChainPrefixOwnedProcess) error {
	challenge, err := nodeChainSecret()
	if err != nil {
		return err
	}
	status, err := m.PrefixStatus(ctx, peer, q.Lease, challenge)
	if err != nil {
		return err
	}
	if status.Receipt.Phase != NodeChainPrefixPrepared {
		return ErrUnavailable
	}
	o, err := m.prefixCandidateOwner(peer, q, false)
	if err != nil || o != expected {
		return ErrOwnership
	}
	return nil
}

func (m *Manager) CreatePrefixCandidate(ctx context.Context, peer netip.Addr, request NodeChainPrefixCandidateRequest) (NodeChainPrefixCandidateReceipt, error) {
	q := request.Clone()
	o, err := m.prefixCandidateOwner(peer, q, false)
	if err != nil {
		return NodeChainPrefixCandidateReceipt{}, err
	}
	o.mu.Lock()
	old := o.candidate
	o.mu.Unlock()
	if old != nil && old.ctx.Err() != nil {
		if err := old.close(ctx); err != nil {
			return NodeChainPrefixCandidateReceipt{}, err
		}
	}
	if err = m.prefixCandidateCurrent(ctx, peer, q, o); err != nil {
		return NodeChainPrefixCandidateReceipt{}, err
	}
	m.mu.Lock()
	var leaseExpiry time.Time
	if active := m.leases[PeerKey(peer)]; active != nil && active.prefix == o && !active.retired {
		leaseExpiry = active.ExpiresAt
	}
	m.mu.Unlock()
	o.mu.Lock()
	capability, ok := o.p.(NodeChainPrefixCandidateProcess)
	if !ok {
		o.mu.Unlock()
		return NodeChainPrefixCandidateReceipt{}, ErrUnavailable
	}
	if o.phase != NodeChainPrefixPrepared || o.ctx.Err() != nil {
		o.mu.Unlock()
		return NodeChainPrefixCandidateReceipt{}, ErrUnavailable
	}
	if o.candidate != nil {
		o.mu.Unlock()
		return NodeChainPrefixCandidateReceipt{}, ErrBusy
	}
	// Check replay identity before eviction: changing an old deadline must not
	// erase that same operation's conflict under capacity pressure.
	if _, exists := o.candidateAttempts[q.OperationID]; exists {
		o.mu.Unlock()
		return NodeChainPrefixCandidateReceipt{}, ErrOwnership
	}
	for _, previous := range o.candidateAttempts {
		if previous.TrialID == q.TrialID {
			o.mu.Unlock()
			return NodeChainPrefixCandidateReceipt{}, ErrOwnership
		}
	}
	o.pruneCandidateAttempts(m.now())
	if o.candidateAttempts == nil {
		o.candidateAttempts = make(map[string]NodeChainPrefixCandidateRequest)
	}
	if len(o.candidateAttempts) >= nodeChainPrefixAttemptLimit {
		o.mu.Unlock()
		return NodeChainPrefixCandidateReceipt{}, ErrOwnership
	}
	capture, err := NewNodeChainPrefixCandidateCapture(o.capture, q, leaseExpiry, m.now())
	if err != nil {
		o.mu.Unlock()
		return NodeChainPrefixCandidateReceipt{}, err
	}
	operationCtx, cancel := context.WithDeadline(o.ctx, time.UnixMilli(q.ExpiresAt))
	op := &nodeChainPrefixCandidateOwned{owner: o, process: o.p, capture: capture, ctx: operationCtx, cancel: cancel, done: make(chan struct{}), expiryDone: make(chan struct{}), closeGate: make(chan struct{}, 1)}
	o.candidateAttempts[q.OperationID] = q.Clone()
	o.candidate = op
	o.mu.Unlock()
	go op.runExpiry()
	// HTTP cancellation revokes this operation while construction is admitted.
	// Stop the callback only after a successful complete before/after bracket.
	stopRequest := context.AfterFunc(ctx, cancel)
	defer stopRequest()
	type preparationResult struct {
		receipt NodeChainPrefixCandidateReceipt
		err     error
	}
	result := make(chan preparationResult, 1)
	// This worker is joined by op.done, even if the HTTP caller expires first.
	// Its returned native allocation stays attached before any foreign Prepare.
	go func() {
		defer close(op.done)
		receipt, workErr := func() (NodeChainPrefixCandidateReceipt, error) {
			native, err := capability.NewPrefixCandidateOperation(operationCtx, capture.Clone())
			op.mu.Lock()
			op.native = native
			op.mu.Unlock()
			if err != nil {
				return NodeChainPrefixCandidateReceipt{}, err
			}
			if native == nil || operationCtx.Err() != nil {
				return NodeChainPrefixCandidateReceipt{}, ErrUnavailable
			}
			started := m.now()
			r, err := native.Prepare(operationCtx)
			if err != nil {
				return r, err
			}
			if operationCtx.Err() != nil || ctx.Err() != nil || r.Validate(capture, "", started, m.now()) != nil || !r.Prepared || r.Drained {
				return r, ErrUnavailable
			}
			return r, m.prefixCandidateCurrent(ctx, peer, q, o)
		}()
		result <- preparationResult{receipt, workErr}
	}()
	var receipt NodeChainPrefixCandidateReceipt
	var workErr error
	select {
	case <-op.done:
		outcome := <-result
		receipt, workErr = outcome.receipt, outcome.err
	case <-ctx.Done():
		workErr = ctx.Err()
	case <-operationCtx.Done():
		workErr = operationCtx.Err()
	}
	if workErr == nil {
		o.mu.Lock()
		op.mu.Lock()
		valid := o.candidate == op && o.p == op.process && !op.retired && operationCtx.Err() == nil && o.phase == NodeChainPrefixPrepared
		op.mu.Unlock()
		o.mu.Unlock()
		if valid && stopRequest() && ctx.Err() == nil {
			return receipt, nil
		}
		workErr = ErrUnavailable
	}
	// Keep the captured handle attached if the request's cleanup budget expired.
	closeErr := op.close(ctx)

	return NodeChainPrefixCandidateReceipt{}, errors.Join(workErr, closeErr)
}
func (m *Manager) PrefixCandidateStatus(ctx context.Context, peer netip.Addr, request NodeChainPrefixCandidateRequest, challenge string) (NodeChainPrefixCandidateReceipt, error) {
	if !proofID.MatchString(challenge) {
		return NodeChainPrefixCandidateReceipt{}, ErrOwnership
	}
	q := request.Clone()
	o, err := m.prefixCandidateOwner(peer, q, false)
	if err != nil {
		return NodeChainPrefixCandidateReceipt{}, err
	}
	if err = m.prefixCandidateCurrent(ctx, peer, q, o); err != nil {
		return NodeChainPrefixCandidateReceipt{}, err
	}
	o.mu.Lock()
	op := o.candidate
	o.mu.Unlock()
	if op == nil || !sameNodeChainPrefixCandidate(op.capture.Request, q) {
		return NodeChainPrefixCandidateReceipt{}, ErrOwnership
	}
	select {
	case <-op.done:
	default:
		return NodeChainPrefixCandidateReceipt{}, ErrBusy
	}
	op.mu.Lock()
	native, retired := op.native, op.retired
	if native == nil || retired || op.ctx.Err() != nil || op.reads != 0 {
		op.mu.Unlock()
		return NodeChainPrefixCandidateReceipt{}, ErrUnavailable
	}
	if op.reads == 0 {
		op.readDone = make(chan struct{})
	}
	readDone := op.readDone
	op.reads++
	op.mu.Unlock()
	readCtx, cancelRead := context.WithCancel(ctx)
	stopRead := context.AfterFunc(op.ctx, cancelRead)
	type statusResult struct {
		receipt NodeChainPrefixCandidateReceipt
		err     error
	}
	result := make(chan statusResult, 1)
	go func() {
		defer func() {
			stopRead()
			cancelRead()
			op.mu.Lock()
			op.reads--
			if op.reads == 0 {
				close(op.readDone)
				op.readDone = nil
			}
			op.mu.Unlock()
		}()
		receipt, err := func() (NodeChainPrefixCandidateReceipt, error) {
			started := m.now()
			r, err := native.Snapshot(readCtx, challenge)
			if err != nil {
				return NodeChainPrefixCandidateReceipt{}, err
			}
			if r.Validate(op.capture, challenge, started, m.now()) != nil || !r.Prepared || r.Drained || op.ctx.Err() != nil {
				return NodeChainPrefixCandidateReceipt{}, ErrUnavailable
			}
			if err = m.prefixCandidateCurrent(ctx, peer, q, o); err != nil {
				return NodeChainPrefixCandidateReceipt{}, err
			}
			o.mu.Lock()
			op.mu.Lock()
			valid := o.candidate == op && o.p == op.process && !op.retired
			op.mu.Unlock()
			o.mu.Unlock()
			if !valid {
				return NodeChainPrefixCandidateReceipt{}, ErrOwnership
			}
			return r, nil
		}()
		result <- statusResult{receipt, err}
	}()
	select {
	case outcome := <-result:
		// Retain this exact read until its original worker releases the hold.
		// Publishing sooner can reject the next serial read as still in flight.
		select {
		case <-readDone:
		case <-ctx.Done():
			cancelRead()
			return NodeChainPrefixCandidateReceipt{}, ctx.Err()
		case <-op.ctx.Done():
			cancelRead()
			return NodeChainPrefixCandidateReceipt{}, op.ctx.Err()
		}
		if ctx.Err() != nil || op.ctx.Err() != nil {
			return NodeChainPrefixCandidateReceipt{}, ErrUnavailable
		}
		return outcome.receipt, outcome.err
	case <-ctx.Done():
		cancelRead()
		return NodeChainPrefixCandidateReceipt{}, ctx.Err()
	case <-op.ctx.Done():
		cancelRead()
		return NodeChainPrefixCandidateReceipt{}, op.ctx.Err()
	}

}
func (m *Manager) DeletePrefixCandidate(ctx context.Context, peer netip.Addr, request NodeChainPrefixCandidateRequest) error {
	q := request.Clone()
	o, err := m.prefixCandidateOwner(peer, q, true)
	if err != nil {
		return err
	}
	o.mu.Lock()
	if o.candidateAttempts == nil {
		o.candidateAttempts = make(map[string]NodeChainPrefixCandidateRequest)
	}
	old, seen := o.candidateAttempts[q.OperationID]
	if seen && !sameNodeChainPrefixCandidate(old, q) {
		o.mu.Unlock()
		return ErrOwnership
	}
	if !seen {
		// An evicted or unknown expired request has no retained ACK authority.
		if q.ExpiresAt <= m.now().UnixMilli() || q.ExpiresAt > m.now().Add(NodeChainCandidateLifetime).UnixMilli() {
			o.mu.Unlock()
			return ErrOwnership
		}
		// Only a new bounded cancellation tombstone may need eviction. Known
		// requests above retain their exact digest even at capacity.
		o.pruneCandidateAttempts(m.now())
		if len(o.candidateAttempts) >= nodeChainPrefixAttemptLimit {
			o.mu.Unlock()
			return ErrOwnership
		}
		o.candidateAttempts[q.OperationID] = q.Clone()
	}
	op := o.candidate
	if op == nil || op.capture.Request.OperationID != q.OperationID {
		o.mu.Unlock()
		return nil
	}
	if !sameNodeChainPrefixCandidate(op.capture.Request, q) {
		o.mu.Unlock()
		return ErrOwnership
	}
	o.mu.Unlock()
	return op.close(ctx)
}
