package multihoprelay

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// An operation remains attached to its exact lease until constructor, Prepare
// and native Close all join. A timeout never releases its replacement slot.
type nodeChainCandidateOwned struct {
	process    NodeChainProcess
	owner      *nodeChainOwnedProcess
	capture    NodeChainCandidateCapture
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	expiryDone chan struct{}
	closeGate  chan struct{}
	mu         sync.Mutex
	native     NodeChainCandidateOperation
	retired    bool
	drained    bool
	reads      int
	readDone   chan struct{}
}

// Exactly one owned expiry/cancellation worker attempts the bounded native join.
// Every external Close joins that worker before retrying the same native handle.
// A failed join retains the slot; a later Create can retry only an expired slot.
func (op *nodeChainCandidateOwned) runExpiry() {
	defer close(op.expiryDone)
	<-op.ctx.Done()
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = op.drain(cleanup)
}
func (op *nodeChainCandidateOwned) close(ctx context.Context) error {
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
func (op *nodeChainCandidateOwned) drain(ctx context.Context) error {
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
func (o *nodeChainOwnedProcess) pruneCandidateAttempts(now time.Time) {
	if len(o.candidateAttempts) < nodeChainAttemptLimit {
		return
	}
	for id, q := range o.candidateAttempts {
		if q.DeadlineAt <= now.UnixMilli() && (o.candidate == nil || o.candidate.capture.Request.Operation != id) {
			delete(o.candidateAttempts, id)
		}
	}
}
func sameNodeChainCandidate(a, b NodeChainCandidateRequest) bool {
	x, e := a.Digest()
	y, f := b.Digest()
	return e == nil && f == nil && x == y
}

// Lookup checks the original registry on every admission/status. Cleanup uses
// only captured authority, so a removed registry cannot strand its own sockets.
func (m *Manager) candidateOwner(peer netip.Addr, q NodeChainCandidateRequest, cleanup bool) (*nodeChainOwnedProcess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if q.Validate() != nil || m.validateChainRequest(peer, q.Lease) != nil {
		return nil, ErrOwnership
	}
	active := m.leases[PeerKey(peer)]
	if active == nil || active.chain == nil || !sameNodeChainRequest(active.chain.capture.Request, q.Lease) {
		return nil, ErrOwnership
	}
	o := active.chain
	digest, err := o.capture.Digest()
	if err != nil || q.OwnerID != o.capture.OwnerID || q.CaptureSHA256 != digest {
		return nil, ErrOwnership
	}
	if !cleanup {
		source, err := m.chainSourceLocked(q.Lease)
		if m.closed || active.retired || !active.ExpiresAt.After(m.now()) || q.DeadlineAt > active.ExpiresAt.UnixMilli() || err != nil || !sameNodeChainSource(source, o.capture.Source) {
			return nil, ErrOwnership
		}
	}
	return o, nil
}
func (m *Manager) candidateCurrent(ctx context.Context, peer netip.Addr, q NodeChainCandidateRequest, expected *nodeChainOwnedProcess) error {
	challenge, err := nodeChainSecret()
	if err != nil {
		return err
	}
	status, err := m.ChainStatus(ctx, peer, q.Lease, challenge)
	if err != nil {
		return err
	}
	if status.Receipt.Phase != NodeChainReady {
		return ErrUnavailable
	}
	o, err := m.candidateOwner(peer, q, false)
	if err != nil || o != expected {
		return ErrOwnership
	}
	return nil
}

func (m *Manager) CreateChainCandidate(ctx context.Context, peer netip.Addr, request NodeChainCandidateRequest) (NodeChainCandidateReceipt, error) {
	q := request.Clone()
	o, err := m.candidateOwner(peer, q, false)
	if err != nil {
		return NodeChainCandidateReceipt{}, err
	}
	o.mu.Lock()
	old := o.candidate
	o.mu.Unlock()
	if old != nil && old.ctx.Err() != nil {
		if err := old.close(ctx); err != nil {
			return NodeChainCandidateReceipt{}, err
		}
	}
	if err = m.candidateCurrent(ctx, peer, q, o); err != nil {
		return NodeChainCandidateReceipt{}, err
	}
	o.mu.Lock()
	capability, ok := o.p.(NodeChainCandidateProcess)
	if !ok {
		o.mu.Unlock()
		return NodeChainCandidateReceipt{}, ErrUnavailable
	}
	if o.phase != NodeChainReady || o.ctx.Err() != nil {
		o.mu.Unlock()
		return NodeChainCandidateReceipt{}, ErrUnavailable
	}
	if o.candidate != nil {
		o.mu.Unlock()
		return NodeChainCandidateReceipt{}, ErrBusy
	}
	// Check replay identity before eviction: changing an old deadline must not
	// erase that same operation's conflict under capacity pressure.
	if _, exists := o.candidateAttempts[q.Operation]; exists {
		o.mu.Unlock()
		return NodeChainCandidateReceipt{}, ErrOwnership
	}
	o.pruneCandidateAttempts(m.now())
	if o.candidateAttempts == nil {
		o.candidateAttempts = make(map[string]NodeChainCandidateRequest)
	}
	if len(o.candidateAttempts) >= nodeChainAttemptLimit {
		o.mu.Unlock()
		return NodeChainCandidateReceipt{}, ErrOwnership
	}
	capture, err := NewNodeChainCandidateCapture(o.capture, q, m.now())
	if err != nil {
		o.mu.Unlock()
		return NodeChainCandidateReceipt{}, err
	}
	operationCtx, cancel := context.WithDeadline(o.ctx, time.UnixMilli(q.DeadlineAt))
	op := &nodeChainCandidateOwned{owner: o, process: o.p, capture: capture, ctx: operationCtx, cancel: cancel, done: make(chan struct{}), expiryDone: make(chan struct{}), closeGate: make(chan struct{}, 1)}
	o.candidateAttempts[q.Operation] = q.Clone()
	o.candidate = op
	o.mu.Unlock()
	go op.runExpiry()
	// HTTP cancellation revokes this operation while construction is admitted.
	// Stop the callback only after a successful complete before/after bracket.
	stopRequest := context.AfterFunc(ctx, cancel)
	defer stopRequest()
	type preparationResult struct {
		receipt NodeChainCandidateReceipt
		err     error
	}
	result := make(chan preparationResult, 1)
	// This worker is joined by op.done, even if the HTTP caller expires first.
	// Its returned native allocation stays attached before any foreign Prepare.
	go func() {
		defer close(op.done)
		receipt, workErr := func() (NodeChainCandidateReceipt, error) {
			native, err := capability.NewCandidateOperation(operationCtx, capture.Clone())
			op.mu.Lock()
			op.native = native
			op.mu.Unlock()
			if err != nil {
				if err == ErrCandidateNotRegistered {
					return NodeChainCandidateReceipt{}, ErrUnavailable
				}
				return NodeChainCandidateReceipt{}, err
			}
			if native == nil || operationCtx.Err() != nil {
				return NodeChainCandidateReceipt{}, ErrUnavailable
			}
			r, err := native.Prepare(operationCtx)
			if err != nil {
				return r, err
			}
			if operationCtx.Err() != nil || ctx.Err() != nil || r.Validate(capture) != nil || !r.Prepared || r.Retired || r.Drained {
				return r, ErrUnavailable
			}
			return r, m.candidateCurrent(ctx, peer, q, o)
		}()
		result <- preparationResult{receipt, workErr}
	}()
	var receipt NodeChainCandidateReceipt
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
		valid := o.candidate == op && o.p == op.process && !op.retired && operationCtx.Err() == nil && o.phase == NodeChainReady
		op.mu.Unlock()
		o.mu.Unlock()
		if valid && stopRequest() && ctx.Err() == nil {
			return receipt, nil
		}
		workErr = ErrUnavailable
	}
	// Keep the captured handle attached if the request's cleanup budget expired.
	closeErr := op.close(ctx)
	if workErr == ErrCandidateNotRegistered {
		if (q.Schema != 2 && q.Schema != 3 && !q.IsPacketResponse()) || closeErr != nil || ctx.Err() != nil || !stopRequest() || m.now().UnixMilli() >= q.DeadlineAt {
			return NodeChainCandidateReceipt{}, ErrUnavailable
		}
		if err := m.candidateCurrent(ctx, peer, q, o); err != nil {
			return NodeChainCandidateReceipt{}, err
		}
		o.mu.Lock()
		current := o.candidate == nil && o.p == op.process && o.ctx.Err() == nil && o.phase == NodeChainReady && sameNodeChainCandidate(o.candidateAttempts[q.Operation], q)
		o.mu.Unlock()
		if !current {
			return NodeChainCandidateReceipt{}, ErrOwnership
		}
		return NodeChainCandidateReceipt{}, &CandidateRegistryAbsence{capture: capture.Clone()}
	}
	return NodeChainCandidateReceipt{}, workErr
}
func (m *Manager) ChainCandidateStatus(ctx context.Context, peer netip.Addr, request NodeChainCandidateRequest) (NodeChainCandidateReceipt, error) {
	q := request.Clone()
	o, err := m.candidateOwner(peer, q, false)
	if err != nil {
		return NodeChainCandidateReceipt{}, err
	}
	if err = m.candidateCurrent(ctx, peer, q, o); err != nil {
		return NodeChainCandidateReceipt{}, err
	}
	o.mu.Lock()
	op := o.candidate
	o.mu.Unlock()
	if op == nil || !sameNodeChainCandidate(op.capture.Request, q) {
		return NodeChainCandidateReceipt{}, ErrOwnership
	}
	select {
	case <-op.done:
	default:
		return NodeChainCandidateReceipt{}, ErrBusy
	}
	op.mu.Lock()
	native, retired := op.native, op.retired
	if native == nil || retired || op.ctx.Err() != nil || op.reads != 0 {
		op.mu.Unlock()
		return NodeChainCandidateReceipt{}, ErrUnavailable
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
		receipt NodeChainCandidateReceipt
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
		receipt, err := func() (NodeChainCandidateReceipt, error) {
			r, err := native.Snapshot(readCtx)
			if err != nil {
				return NodeChainCandidateReceipt{}, err
			}
			if r.Validate(op.capture) != nil || !r.Prepared || r.Retired || r.Drained || op.ctx.Err() != nil {
				return NodeChainCandidateReceipt{}, ErrUnavailable
			}
			if err = m.candidateCurrent(ctx, peer, q, o); err != nil {
				return NodeChainCandidateReceipt{}, err
			}
			o.mu.Lock()
			op.mu.Lock()
			valid := o.candidate == op && o.p == op.process && !op.retired
			op.mu.Unlock()
			o.mu.Unlock()
			if !valid {
				return NodeChainCandidateReceipt{}, ErrOwnership
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
			return NodeChainCandidateReceipt{}, ctx.Err()
		case <-op.ctx.Done():
			cancelRead()
			return NodeChainCandidateReceipt{}, op.ctx.Err()
		}
		if ctx.Err() != nil || op.ctx.Err() != nil {
			return NodeChainCandidateReceipt{}, ErrUnavailable
		}
		return outcome.receipt, outcome.err
	case <-ctx.Done():
		cancelRead()
		return NodeChainCandidateReceipt{}, ctx.Err()
	case <-op.ctx.Done():
		cancelRead()
		return NodeChainCandidateReceipt{}, op.ctx.Err()
	}

}
func (m *Manager) DeleteChainCandidate(ctx context.Context, peer netip.Addr, request NodeChainCandidateRequest) error {
	q := request.Clone()
	o, err := m.candidateOwner(peer, q, true)
	if err != nil {
		return err
	}
	o.mu.Lock()
	if o.candidateAttempts == nil {
		o.candidateAttempts = make(map[string]NodeChainCandidateRequest)
	}
	old, seen := o.candidateAttempts[q.Operation]
	if seen && !sameNodeChainCandidate(old, q) {
		o.mu.Unlock()
		return ErrOwnership
	}
	if !seen {
		// An evicted or unknown expired request has no retained ACK authority.
		if q.DeadlineAt <= m.now().UnixMilli() || q.DeadlineAt > m.now().Add(NodeChainCandidateLifetime).UnixMilli() {
			o.mu.Unlock()
			return ErrOwnership
		}
		// Only a new bounded cancellation tombstone may need eviction. Known
		// requests above retain their exact digest even at capacity.
		o.pruneCandidateAttempts(m.now())
		if len(o.candidateAttempts) >= nodeChainAttemptLimit {
			o.mu.Unlock()
			return ErrOwnership
		}
		o.candidateAttempts[q.Operation] = q.Clone()
	}
	op := o.candidate
	if op == nil || op.capture.Request.Operation != q.Operation {
		o.mu.Unlock()
		return nil
	}
	if !sameNodeChainCandidate(op.capture.Request, q) {
		o.mu.Unlock()
		return ErrOwnership
	}
	o.mu.Unlock()
	return op.close(ctx)
}
