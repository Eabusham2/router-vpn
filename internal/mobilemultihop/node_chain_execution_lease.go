package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

type nodeChainExecutionAttempt struct {
	mu              sync.Mutex
	request         multihoprelay.NodeChainRequest
	source          multihoprelay.NodeChainDescriptor
	stop            LeaseStop
	issued, stopped bool
	closing         bool
	candidate       *nodeChainExecutionRemoteOperation
	lease           multihoprelay.NodeChainLease
	deadline        time.Time
	receipt         multihoprelay.NodeChainReceipt
	proofDeadline   time.Time
	started         time.Time
	rpcGate         chan struct{}
	rpcPending      *leaseStopIO // protected by rpcGate, including original late I/O
	renewDone       chan struct{}
}

func (a *nodeChainExecutionAttempt) lockRPC(ctx context.Context, control *nodeChainExecutionIO) (func(), error) {
	if a == nil || ctx == nil || control == nil {
		return nil, nodeChainExecutionError
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.rpcGate:
	}
	// Candidate and lease use separate HTTP owners. A cancelled caller can
	// return while its original callback, socket or Close is still draining.
	if previous := a.rpcPending; previous != nil {
		if err := previous.wait(ctx); err != nil {
			a.rpcGate <- struct{}{}
			return nil, err
		}
		a.rpcPending = nil
	}
	return func() {
		// The selected attempt owns every active grant, status and renewal RPC
		// on these controls. A concurrent Close clears pending only after join.
		control.mu.Lock()
		a.rpcPending = control.pending
		control.mu.Unlock()
		a.rpcGate <- struct{}{}
	}, nil
}

func (a *nodeChainExecutionAttempt) fresh() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.issued && !a.stopped && a.lease.Phase == multihoprelay.NodeChainReady && a.receipt.Phase == multihoprelay.NodeChainReady && time.Now().Before(a.deadline) && time.Now().Before(a.proofDeadline)
}
func (a *nodeChainExecutionAttempt) stopOriginal(ctx context.Context) error {
	a.mu.Lock()
	a.closing = true
	stopped, issued, stop, candidate := a.stopped, a.issued, a.stop, a.candidate
	a.mu.Unlock()
	// The exact candidate DELETE must join while this original VPN lease still
	// exists. A failed or late acquisition remains attached for the next Stop.
	if candidate != nil {
		if err := candidate.close(ctx); err != nil {
			return err
		}
	}
	if stopped {
		return ctx.Err()
	}
	if issued && stop == nil {
		return errors.New("ordered attempt lost its pre-acquisition cleanup authority")
	}
	if issued {
		if err := stop.Stop(ctx); err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.stopped = true
	a.deadline = time.Time{}
	a.proofDeadline = time.Time{}
	a.mu.Unlock()
	return ctx.Err()
}
func (a *nodeChainExecutionAttempt) discardStopped() {
	a.mu.Lock()
	stop, stopped := a.stop, a.stopped
	a.mu.Unlock()
	if stopped && stop != nil {
		stop.Discard()
	}
}

func (s *nodeChainExecutionTrial) acquire(ctx context.Context) error {
	if err := s.runtime.current(ctx, s, true); err != nil {
		return err
	}
	data, err := s.controlIO.exchange(ctx, "GET", nodeChainExecutionLeasePath, nil, multihoprelay.MaxNodeChainCapabilitiesBytes)
	if err != nil {
		return err
	}
	request, err := s.runtime.projection.policy.NewAttempt(string(data))
	if err != nil {
		return err
	}
	s.runtime.mu.Lock()
	identity := s.runtime.identity
	s.runtime.mu.Unlock()
	capture, err := s.runtime.projection.stopCapture(request, identity)
	if err != nil {
		return err
	}
	attempt := &nodeChainExecutionAttempt{request: request.Clone(), source: s.runtime.projection.policy.Descriptor(), rpcGate: make(chan struct{}, 1)}
	attempt.rpcGate <- struct{}{}
	s.mu.Lock()
	if s.attempt != nil || s.closed {
		s.mu.Unlock()
		return nodeChainExecutionError
	}
	s.attempt = attempt
	s.mu.Unlock()
	stop, err := s.runtime.engine.CaptureExecutionStop(ctx, capture)
	// A late returned cleanup capability is still the original attempt's.
	attempt.mu.Lock()
	attempt.stop = stop
	attempt.mu.Unlock()
	if err != nil || stop == nil {
		return errors.Join(err, nodeChainExecutionError)
	}
	if err = s.runtime.current(ctx, s, true); err != nil {
		return err
	}
	attempt.mu.Lock()
	attempt.issued = true
	attempt.started = time.Now()
	attempt.mu.Unlock()
	if err = s.renew(ctx); err != nil {
		return err
	}
	attempt.mu.Lock()
	attempt.renewDone = make(chan struct{})
	renewDone := attempt.renewDone
	attempt.mu.Unlock()
	go s.keepLease(renewDone)
	for {
		if err := s.status(ctx, false); err != nil {
			return err
		}
		if attempt.fresh() {
			return s.runtime.current(ctx, s, true)
		}
		attempt.mu.Lock()
		deadline := attempt.lease.BootstrapDeadline
		attempt.mu.Unlock()
		if deadline.IsZero() || !time.Now().Before(deadline) {
			return errors.New("ordered server bootstrap expired")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-s.lifetime.Done():
			timer.Stop()
			return s.lifetime.Err()
		case <-timer.C:
		}
	}
}

func (s *nodeChainExecutionTrial) validateLease(lease multihoprelay.NodeChainLease, now time.Time, renewal bool) error {
	s.mu.Lock()
	a := s.attempt
	s.mu.Unlock()
	if a == nil {
		return nodeChainExecutionError
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	registry, err := a.source.Digest()
	if err != nil || a.stopped || !a.issued || !reflect.DeepEqual(lease.Request, a.request) || lease.NodeID != a.source.EntryNodeID || !proofID.MatchString(lease.OwnerID) ||
		lease.RegistrySHA256 != registry || lease.DNSPolicySHA256 != a.source.DNSPolicySHA256 || !reflect.DeepEqual(lease.Users, a.request.Users) ||
		s.runtime.projection.policy.ValidateFront(lease.Host, lease.Port) != nil || lease.Phase != multihoprelay.NodeChainPending && lease.Phase != multihoprelay.NodeChainReady {
		return nodeChainExecutionError
	}
	if !renewal && (a.lease.OwnerID == "" || !lease.ExpiresAt.Equal(a.lease.ExpiresAt)) {
		return nodeChainExecutionError
	}
	remaining := lease.ExpiresAt.Sub(now)
	if remaining < 2*time.Second || remaining > 305*time.Second {
		return nodeChainExecutionError
	}
	_, offset := lease.BootstrapDeadline.Zone()
	if lease.BootstrapDeadline.IsZero() || offset != 0 {
		return nodeChainExecutionError
	}
	if a.lease.OwnerID == "" {
		if !lease.BootstrapDeadline.After(a.started) || lease.BootstrapDeadline.After(now.Add(multihoprelay.NodeChainBootstrapLimit)) {
			return nodeChainExecutionError
		}
	} else if lease.OwnerID != a.lease.OwnerID || lease.BootstrapDeadline != a.lease.BootstrapDeadline || lease.Host != a.lease.Host || lease.Port != a.lease.Port ||
		a.lease.Phase == multihoprelay.NodeChainReady && lease.Phase != multihoprelay.NodeChainReady {
		return nodeChainExecutionError
	}
	if lease.Phase == multihoprelay.NodeChainPending && !now.Before(lease.BootstrapDeadline) {
		return nodeChainExecutionError
	}
	// Preserve a local monotonic deadline; wall-clock movement cannot extend
	// the original acknowledgement, and snapshots never refresh this value.
	a.lease = lease
	a.lease.Request = lease.Request.Clone()
	a.lease.Users = append([]multihoprelay.NodeChainUser(nil), lease.Users...)
	if renewal {
		a.deadline = now.Add(remaining)
	}
	return nil
}

func (s *nodeChainExecutionTrial) renew(ctx context.Context) error {
	s.mu.Lock()
	a := s.attempt
	s.mu.Unlock()
	if a == nil {
		return nodeChainExecutionError
	}
	unlock, err := a.lockRPC(ctx, s.controlIO)
	if err != nil {
		return err
	}
	defer unlock()
	a.mu.Lock()
	request := a.request.Clone()
	stopped := a.stopped
	a.mu.Unlock()
	if stopped {
		return nodeChainExecutionError
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	data, err := s.controlIO.exchange(ctx, "PUT", nodeChainExecutionLeasePath, raw, multihoprelay.MaxControlResponseBytes)
	if err != nil {
		return err
	}
	var lease multihoprelay.NodeChainLease
	if exactJSON(data, &lease, multihoprelay.MaxControlResponseBytes) != nil {
		return nodeChainExecutionError
	}
	if err = s.validateLease(lease, time.Now(), true); err != nil {
		return err
	}
	return s.runtime.current(ctx, s, true)
}

func nodeChainStatusRequest(request multihoprelay.NodeChainRequest, nonce string) ([]byte, error) {
	return json.Marshal(struct {
		multihoprelay.NodeChainRequest
		StatusNonce string `json:"status_nonce"`
	}{request, nonce})
}

func (s *nodeChainExecutionTrial) status(ctx context.Context, requireReady bool) error {
	s.mu.Lock()
	a := s.attempt
	s.mu.Unlock()
	if a == nil {
		return nodeChainExecutionError
	}
	unlock, err := a.lockRPC(ctx, s.controlIO)
	if err != nil {
		return err
	}
	defer unlock()
	nonce, err := randomHex(32)
	if err != nil {
		return err
	}
	a.mu.Lock()
	request := a.request.Clone()
	source := a.source.Clone()
	old := a.lease
	stopped := a.stopped
	sequence := a.receipt.Sequence
	previousProof, previousHeartbeat := a.receipt.ProofAt, a.receipt.HeartbeatAt
	a.mu.Unlock()
	if stopped || old.OwnerID == "" {
		return nodeChainExecutionError
	}
	raw, err := nodeChainStatusRequest(request, nonce)
	if err != nil {
		return err
	}
	started := time.Now()
	data, err := s.controlIO.exchange(ctx, "POST", nodeChainExecutionLeasePath, raw, multihoprelay.MaxControlResponseBytes)
	if err != nil {
		return err
	}
	now := time.Now()
	var status multihoprelay.NodeChainLeaseStatus
	if len(request.Users) > multihoprelay.NodeChainMaximumMembers {
		var update multihoprelay.NodeChainStatusUpdate
		if exactJSON(data, &update, multihoprelay.MaxControlResponseBytes) != nil {
			return nodeChainExecutionError
		}
		status, err = update.RestoreLease(old)
		if err != nil {
			return err
		}
	} else if exactJSON(data, &status, multihoprelay.MaxControlResponseBytes) != nil {
		return nodeChainExecutionError
	}
	// Validate the complete status before changing any original lease receipt.
	capture := multihoprelay.NodeChainCapture{Schema: 1, Request: request, Source: source, RegistrySHA256: old.RegistrySHA256, OwnerID: old.OwnerID, Peer: request.Peer, Host: old.Host, BootstrapDeadline: old.BootstrapDeadline}
	if multihoprelay.ValidateNodeChainReceipt(status.Receipt, capture, nonce, started, now) != nil || status.Receipt.Sequence <= sequence || status.Receipt.ProofAt < previousProof || status.Receipt.HeartbeatAt < previousHeartbeat ||
		status.Lease.Phase != status.Receipt.Phase || requireReady && status.Receipt.Phase != multihoprelay.NodeChainReady {
		return nodeChainExecutionError
	}
	if err = s.validateLease(status.Lease, now, false); err != nil {
		return err
	}
	if err = s.runtime.current(ctx, s, true); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped || a.receipt.Sequence != sequence || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	a.receipt = status.Receipt.Clone()
	if status.Receipt.Phase == multihoprelay.NodeChainReady {
		remaining := time.Duration(15+5*min(len(source.Members), multihoprelay.NodeChainMaximumMembers))*time.Second - now.Sub(time.UnixMilli(status.Receipt.ProofAt))
		if remaining <= 0 {
			return nodeChainExecutionError
		}
		if status.Receipt.ProofAt != previousProof || a.proofDeadline.IsZero() {
			a.proofDeadline = now.Add(remaining)
		}
	}
	return nil
}

func (s *nodeChainExecutionTrial) renewAndProve(ctx context.Context) error {
	if s.execution == "server" {
		if err := s.status(ctx, true); err != nil {
			return err
		}
	}
	return s.proveComplete(ctx)
}

// Renewal has its own joined lifetime because a configured 15-second lease
// must not expire while a valid complete path proof visits several prefixes.
// It never changes the immutable bootstrap bound, request or native owner.
func (s *nodeChainExecutionTrial) keepLease(done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.lifetime.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(s.lifetime, 8*time.Second)
			err := s.renew(ctx)
			cancel()
			if err != nil {
				s.cancel()
				barrier, finish := context.WithTimeout(context.Background(), 5*time.Second)
				_, _ = s.revokeTerminal(barrier)
				finish()
				return
			}
		}
	}
}

func (a *nodeChainExecutionAttempt) joinRenew(ctx context.Context) error {
	a.mu.Lock()
	done := a.renewDone
	a.mu.Unlock()
	if done == nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return ctx.Err()
	}
}
