package mobilemultihop

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

type nodeChainExecutionRemoteOperation struct {
	engine                   *nodeChainExecutionRemoteCandidateEngine
	target                   hopmeasure.CandidateTarget
	attempt                  *nodeChainExecutionAttempt
	ctx                      context.Context
	cancel                   context.CancelFunc
	ready                    chan struct{}
	gate                     chan struct{}
	io                       *leaseStopIO
	control                  *nodeChainExecutionIO
	stop                     LeaseStop
	capture                  NodeChainExecutionCandidateStopCapture
	native                   multihoprelay.NodeChainCandidateCapture
	front                    string
	mu                       sync.Mutex
	issued, prepared, closed bool
	dials                    int
}

func newNodeChainExecutionRemoteOperation(parent context.Context, e *nodeChainExecutionRemoteCandidateEngine, target hopmeasure.CandidateTarget) *nodeChainExecutionRemoteOperation {
	ctx, cancel := context.WithCancel(parent)
	op := &nodeChainExecutionRemoteOperation{engine: e, target: target, ctx: ctx, cancel: cancel, ready: make(chan struct{}), gate: make(chan struct{}, 1), io: newLeaseStopIO(ctx)}
	op.gate <- struct{}{}
	return op
}
func (op *nodeChainExecutionRemoteOperation) initialize(ctx context.Context) error {
	defer close(op.ready)
	e := op.engine
	s := e.plan.trial
	s.mu.Lock()
	attempt, closed := s.attempt, s.closed
	s.mu.Unlock()
	if attempt == nil || closed {
		return nodeChainExecutionError
	}
	attempt.mu.Lock()
	if attempt.closing || attempt.stopped || attempt.candidate != nil {
		attempt.mu.Unlock()
		return nodeChainExecutionError
	}
	// Reserve cancellation before capturing native authority, which may itself
	// return late. The whole lease cannot disappear behind that callback.
	attempt.candidate = op
	op.attempt = attempt
	lease := attempt.lease
	request := attempt.request.Clone()
	source := attempt.source.Clone()
	deadline := remoteCandidateDeadline(ctx, attempt.deadline)
	attempt.mu.Unlock()
	if !attempt.fresh() {
		return nodeChainExecutionError
	}
	operation, err := randomHex(32)
	if err != nil {
		return err
	}
	password, err := randomHex(32)
	if err != nil {
		return err
	}
	original := multihoprelay.NodeChainCapture{Schema: 1, Request: request, Source: source, RegistrySHA256: lease.RegistrySHA256, OwnerID: lease.OwnerID, Peer: request.Peer, Host: lease.Host, BootstrapDeadline: lease.BootstrapDeadline}
	digest, err := original.Digest()
	if err != nil {
		return err
	}
	q := multihoprelay.NodeChainCandidateRequest{Schema: 1, Lease: request, OwnerID: lease.OwnerID, CaptureSHA256: digest, Operation: operation, ExecutionSHA256: e.plan.identity.SourceSHA256, Trial: s.id, SelectionEpoch: s.selectionEpoch, InventorySHA256: externalDigest([]byte(e.plan.packet.inventory)), Position: e.plan.packet.prefix.Position, CandidateID: op.target.ID, CandidateSourceSHA256: op.target.SourceSHA256, Address: op.target.Address, DeadlineAt: deadline.UnixMilli(), Password: password}
	capture, err := s.candidateStopCapture(ctx, q)
	if err != nil {
		return err
	}
	op.capture = capture
	if e.plan.projection.policy.ValidateFront(lease.Host, lease.Port) != nil {
		return nodeChainExecutionError
	}
	op.front = net.JoinHostPort(lease.Host, strconv.Itoa(lease.Port))
	stop, err := e.plan.engine.(NodeChainExecutionCandidateStopEngine).CaptureExecutionCandidateStop(ctx, capture)
	// Retain a nonnil capability even when its factory returns an error.
	op.stop = stop
	if err != nil || stop == nil {
		return errors.Join(err, nodeChainExecutionError)
	}
	current := func(call context.Context) error {
		if op.ctx.Err() != nil {
			return op.ctx.Err()
		}
		return e.current(call)
	}
	control, err := newNodeChainExecutionIO(capture.entryTag, capture.api, capture.token, e.plan.engine.Dial, current)
	if err != nil {
		return err
	}
	control.testTLS = e.plan.runtime.testTLS
	op.control = control
	if err := e.current(ctx); err != nil {
		return err
	}
	return op.ctx.Err()
}
func (op *nodeChainExecutionRemoteOperation) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-op.gate:
		return nil
	}
}
func (op *nodeChainExecutionRemoteOperation) verify(ctx context.Context) error {
	if err := op.lock(ctx); err != nil {
		return err
	}
	defer func() { op.gate <- struct{}{} }()
	select {
	case <-op.ready:
	default:
		return nodeChainExecutionError
	}
	if op.closed || op.stop == nil || op.control == nil || op.ctx.Err() != nil || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	if err := op.engine.base.trial.Verify(ctx); err != nil {
		return err
	}
	call, cancel := context.WithDeadline(ctx, time.UnixMilli(op.capture.request.DeadlineAt))
	defer cancel()
	stopCancel := context.AfterFunc(op.ctx, cancel)
	defer stopCancel()
	method := "POST"
	if !op.prepared {
		if op.issued {
			return nodeChainExecutionError
		}
		method = "PUT"
		op.issued = true
	}
	for {
		// Both grant/status and the original lease renewal ask the same native
		// worker for a fresh increasing sequence. Bracket the complete HTTP
		// exchange with the original attempt's gate so neither can overtake
		// the other's receipt. DELETE owns an independent stop capability.
		unlock, err := op.attempt.lockRPC(call, op.control)
		if err != nil {
			return err
		}
		raw, err := op.control.exchangeCandidate(call, method, []byte(op.capture.body))
		unlock()
		if err != nil {
			return err
		}
		var receipt multihoprelay.NodeChainCandidateReceipt
		if exactJSON(raw, &receipt, multihoprelay.NodeChainCandidateResponseMaximumBytes) != nil {
			return nodeChainExecutionError
		}
		capture := op.native
		if !op.prepared {
			capture = multihoprelay.NodeChainCandidateCapture{Schema: 1, Lease: op.capture.lease.Clone(), Request: op.capture.request.Clone(), Member: op.capture.lease.Source.Members[op.capture.request.Position-1], OperationOwnerID: receipt.OperationOwnerID}
		}
		op.mu.Lock()
		dials := op.dials
		op.mu.Unlock()
		if receipt.Validate(capture) != nil || !receipt.Prepared || receipt.Retired || receipt.Drained || receipt.Accepted != dials {
			return nodeChainExecutionError
		}
		if !receipt.InFlight {
			op.native = capture
			op.prepared = true
			return op.engine.current(call)
		}
		// A local socket Close may precede remote EOF processing. Observe its exact
		// original join outside the measured Dial interval, never start sample N+1
		// while sample N owns the server's single in-flight slot.
		method = "POST"
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-call.Done():
			timer.Stop()
			return call.Err()
		}
	}
}
func (op *nodeChainExecutionRemoteOperation) dial(ctx context.Context, address string) (net.Conn, error) {
	if err := op.lock(ctx); err != nil {
		return nil, err
	}
	defer func() { op.gate <- struct{}{} }()
	if op.closed || !op.prepared || op.ctx.Err() != nil || address != op.target.Address {
		return nil, nodeChainExecutionError
	}
	op.mu.Lock()
	if op.dials >= multihoprelay.NodeChainCandidateMaximumConnects {
		op.mu.Unlock()
		return nil, nodeChainExecutionError
	}
	op.mu.Unlock()
	call, finish, err := op.io.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if err := op.engine.current(call); err != nil {
		return nil, err
	}
	conn, dialErr := op.engine.plan.engine.Dial(call, op.capture.entryTag, op.front)
	var keepErr error
	if conn != nil {
		conn, keepErr = op.io.keep(conn)
	}
	if conn == nil || dialErr != nil || keepErr != nil {
		return conn, errors.Join(dialErr, keepErr, nodeChainExecutionError)
	}
	// This stream carries only SOCKS authentication and one literal CONNECT.
	// The service immediately closes it; no caller can use it for payload I/O.
	if err := remoteCandidateSOCKSConnect(call, conn, op.native.Username(), op.capture.request.Password, address); err != nil {
		return conn, err
	}
	op.mu.Lock()
	op.dials++
	op.mu.Unlock()
	if err := op.engine.current(call); err != nil {
		return conn, err
	}
	return conn, call.Err()
}
func (op *nodeChainExecutionRemoteOperation) close(ctx context.Context) error {
	if op == nil || ctx == nil {
		return nodeChainExecutionError
	}
	op.cancel()
	op.io.retire()
	select {
	case <-op.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	if op.control != nil {
		op.control.cancel()
	}
	if err := op.lock(ctx); err != nil {
		return err
	}
	defer func() { op.gate <- struct{}{} }()
	if op.closed {
		return ctx.Err()
	}
	// Cancellation tombstones precede the late original PUT join, but neither
	// HTTP ACK nor process death waives the retained local sockets/callbacks.
	var stopErr error
	if op.issued {
		if op.stop == nil {
			return nodeChainExecutionError
		}
		stopErr = op.stop.Stop(ctx)
	}
	var controlErr error
	if op.control != nil {
		controlErr = op.control.close(ctx)
	}
	if err := errors.Join(stopErr, controlErr, op.io.wait(ctx), ctx.Err()); err != nil {
		return err
	}
	if op.stop != nil {
		op.stop.Discard()
	}
	op.closed = true
	if op.attempt != nil {
		op.attempt.mu.Lock()
		if op.attempt.candidate == op {
			op.attempt.candidate = nil
		}
		op.attempt.mu.Unlock()
	}
	return nil
}

func remoteCandidateSOCKSConnect(ctx context.Context, conn net.Conn, username, password, address string) error {
	if ctx == nil || conn == nil || len(username) < 1 || len(username) > 255 || len(password) < 1 || len(password) > 255 {
		return nodeChainExecutionError
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nodeChainExecutionError
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || portErr != nil || ip.Zone() != "" || ip.Is4In6() || number < 1 || number > 65535 {
		return nodeChainExecutionError
	}
	write := func(data []byte) error {
		for len(data) > 0 {
			n, err := conn.Write(data)
			if err != nil {
				return err
			}
			if n <= 0 {
				return io.ErrShortWrite
			}
			data = data[n:]
		}
		return nil
	}
	if err := write([]byte{5, 1, 2}); err != nil {
		return err
	}
	var auth [2]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil {
		return err
	}
	if auth != [2]byte{5, 2} {
		return nodeChainExecutionError
	}
	credentials := append([]byte{1, byte(len(username))}, []byte(username)...)
	credentials = append(credentials, byte(len(password)))
	credentials = append(credentials, []byte(password)...)
	defer clear(credentials)
	if err := write(credentials); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, auth[:]); err != nil {
		return err
	}
	if auth != [2]byte{1, 0} {
		return nodeChainExecutionError
	}
	frame := []byte{5, 1, 0}
	if ip.Is4() {
		frame = append(frame, 1)
		a := ip.As4()
		frame = append(frame, a[:]...)
	} else {
		frame = append(frame, 4)
		a := ip.As16()
		frame = append(frame, a[:]...)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(number))
	if err := write(frame); err != nil {
		return err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nodeChainExecutionError
	}
	size := 0
	if reply[3] == 1 {
		size = 6
	} else if reply[3] == 4 {
		size = 18
	} else {
		return nodeChainExecutionError
	}
	suffix := make([]byte, size)
	if _, err := io.ReadFull(conn, suffix); err != nil {
		return err
	}
	return ctx.Err()
}
