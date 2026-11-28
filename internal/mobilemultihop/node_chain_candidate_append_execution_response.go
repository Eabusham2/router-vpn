package mobilemultihop

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

// One original service request owns comparison, final recheck, their complete
// retirement and the distinct fifty-response operation. A failed Close keeps
// this same owner and its Local activity hold; a new request cannot replace it.
type nodeChainAppendExecutionRun struct {
	self                *nodeChainAppendExecutionRun
	runtime             *NodeChainCandidateAppendExecutionRuntime
	source              candidateResponseSource
	request             string
	ctx                 context.Context
	cancel              context.CancelFunc
	ready               chan struct{}
	gate                chan struct{}
	mu                  sync.Mutex
	initialized, closed bool
	winning             routechoice.Execution
	trial               *nodeChainAppendExecutionTrial
	lease               *nodeChainAppendExecutionLease
	remote              *nodeChainAppendExecutionRemoteCandidate
	localIO             *nodeChainExecutionIO
	packet              *nodeChainAppendExecutionPacket
	packetDeadline      time.Time
	hysteria            *nodeChainAppendExecutionHysteria
	hysteriaDeadline    time.Time
	ordinal             int
}

func (r *NodeChainCandidateAppendExecutionRuntime) openResponseRun(ctx context.Context, target hopmeasure.CandidateTarget) (hopmeasure.CandidateResponseRun, error) {
	if err := r.HealthyContext(ctx); err != nil {
		return nil, err
	}
	if err := r.local.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	var source candidateResponseSource
	found := false
	for _, actual := range r.preparation.original.candidates.responses {
		if actual.Target == target {
			source, found = actual, true
		}
	}
	packetMode := nodeChainAppendExecutionPacketMode(r.preparation.CandidateMode())
	var packetDeadline, hysteriaDeadline time.Time
	if packetMode {
		var bounded bool
		packetDeadline, bounded = ctx.Deadline()
		if !found || !bounded || source.PacketOptions == "" || source.Hysteria2Options != "" ||
			source.Method != "" || source.Password != "" || !nodeChainCanonicalPeer(source.ClientKey) || !nodeChainCanonicalPeer(source.ServerKey) {
			return nil, errNodeChainAppendExecution
		}
	} else if r.preparation.CandidateMode() == "hysteria2" {
		var bounded bool
		hysteriaDeadline, bounded = ctx.Deadline()
		if !found || !bounded || source.Hysteria2Options == "" || source.PacketOptions != "" ||
			source.Method != "" || source.Password != "" || source.ClientKey != "" || source.ServerKey != "" {
			return nil, errNodeChainAppendExecution
		}
	} else if !found || source.Method == "" || source.Password == "" || wrapCandidateSS2022 == nil {
		return nil, errNodeChainAppendExecution
	}
	r.mu.Lock()
	service := r.service
	r.mu.Unlock()
	if service == nil {
		return nil, errNodeChainAppendExecution
	}
	var state struct {
		Request string `json:"request_id"`
	}
	if json.Unmarshal([]byte(service.StatusContextJSON(ctx)), &state) != nil || state.Request == "" {
		return nil, errNodeChainAppendExecution
	}
	r.mu.Lock()
	if r.retired || r.active != nil || len(r.pending) != 0 {
		r.mu.Unlock()
		return nil, errNodeChainAppendExecution
	}
	lifetime, cancel := context.WithCancel(r.lifetime)
	run := &nodeChainAppendExecutionRun{runtime: r, source: source, request: state.Request, ctx: lifetime, cancel: cancel, ready: make(chan struct{}), gate: make(chan struct{}, 1), packetDeadline: packetDeadline, hysteriaDeadline: hysteriaDeadline}
	run.self = run
	r.active = run
	r.resultRequest, r.winning, r.selection = state.Request, "", ""
	r.mu.Unlock()
	err := run.initialize(ctx)
	return run, err
}
func (s *nodeChainAppendExecutionRun) current(ctx context.Context) error {
	if s == nil || s.self != s || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil {
		return errNodeChainAppendExecution
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	s.runtime.mu.Lock()
	original := s.runtime.active == s
	s.runtime.mu.Unlock()
	if closed || !original {
		return errNodeChainAppendExecution
	}
	if err := s.runtime.HealthyContext(ctx); err != nil {
		return err
	}
	return s.runtime.local.VerifyMeasurement(ctx)
}
func (s *nodeChainAppendExecutionRun) initialize(ctx context.Context) error {
	defer close(s.ready)
	winner := routechoice.Server
	if s.runtime.preparation.Execution() == "auto" {
		entry := s.runtime.preparation.policy.localMembers[0].ProfileID
		candidates := []routechoice.Candidate{{Execution: routechoice.Local, Transport: "ordered-prefix-append", EntryID: entry, ExitID: s.source.Target.ID}, {Execution: routechoice.Server, Transport: "ordered-prefix-append", EntryID: entry, ExitID: s.source.Target.ID}}
		result, active, err := routechoice.Compare(ctx, candidates, s, routechoice.Options{Targets: []string{"https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"}})
		if raw, e := json.Marshal(result); e == nil {
			s.runtime.mu.Lock()
			if s.runtime.active == s && s.runtime.resultRequest == s.request {
				s.runtime.selection = string(raw)
			}
			s.runtime.mu.Unlock()
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		trial := s.trial
		s.mu.Unlock()
		if active == nil || trial == nil || active != trial || result.Winner == nil || result.Final == nil || !result.Final.Eligible || result.Final.ScoreMS == nil || result.Final.Candidate != *result.Winner {
			return errNodeChainAppendExecution
		}
		winner = result.Winner.Execution
		// Compare's two one-use streams are never counted as fifty-response slots.
		cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
		err = trial.Close(cleanup)
		finish()
		if err != nil {
			return err
		}
	}
	if winner != routechoice.Local && winner != routechoice.Server {
		return errNodeChainAppendExecution
	}
	if err := s.current(ctx); err != nil {
		return err
	}
	if winner == routechoice.Server {
		lease, err := s.runtime.newLease(ctx)
		s.mu.Lock()
		s.lease = lease
		s.mu.Unlock()
		if err != nil || lease == nil {
			return errors.Join(err, errNodeChainAppendExecution)
		}
		remote, err := lease.newCandidate(ctx, s.source, multihoprelay.NodeChainPrefixPrivateResponse, "")
		s.mu.Lock()
		s.remote = remote
		s.mu.Unlock()
		if err != nil || remote == nil {
			return errors.Join(err, errNodeChainAppendExecution)
		}
	} else {
		tag := s.runtime.preparation.original.proofs[s.runtime.preparation.original.position].Tag
		dial := s.runtime.local.Dial
		if s.source.PacketOptions != "" {
			packet, err := s.reserveLocalPacket(ctx, s.ctx, "", s.current)
			s.mu.Lock()
			s.packet = packet
			s.mu.Unlock()
			if err != nil || packet == nil {
				return errors.Join(err, errNodeChainAppendExecution)
			}
			if err = packet.open(ctx); err != nil {
				return err
			}
			dial = packet.dial
		} else if s.source.Hysteria2Options != "" {
			hysteria, err := s.captureLocalHysteria(ctx, s.ctx, "", s.current)
			s.mu.Lock()
			s.hysteria = hysteria
			s.mu.Unlock()
			if err != nil || hysteria == nil {
				return errors.Join(err, errNodeChainAppendExecution)
			}
			if err = hysteria.open(ctx); err != nil {
				return err
			}
			dial = hysteria.dial
		}
		owned, err := newNodeChainExecutionIO(tag, s.source.API, s.source.Token, dial, s.current)
		s.mu.Lock()
		s.localIO = owned
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}
	if err := s.current(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.winning, s.initialized = winner, true
	s.mu.Unlock()
	s.runtime.mu.Lock()
	if s.runtime.active != s || s.runtime.resultRequest != s.request {
		s.runtime.mu.Unlock()
		return errNodeChainAppendExecution
	}
	s.runtime.winning = string(winner)
	s.runtime.mu.Unlock()
	return nil
}
func (s *nodeChainAppendExecutionRun) verify(ctx context.Context) error {
	if s == nil || s.self != s || ctx == nil {
		return errNodeChainAppendExecution
	}
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.gate }()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		// A read may retain this run just before its original Close joins.
		// Reobserve the same Local source only after every remote owner retired.
		s.runtime.mu.Lock()
		joined := s.runtime.active == nil && len(s.runtime.pending) == 0
		s.runtime.mu.Unlock()
		if !joined {
			return errNodeChainAppendExecution
		}
		if err := s.runtime.HealthyContext(ctx); err != nil {
			return err
		}
		return s.runtime.local.VerifyMeasurement(ctx)
	}
	if err := s.current(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	initialized, remote := s.initialized, s.remote
	s.mu.Unlock()
	if initialized && remote != nil {
		return remote.verify(ctx)
	}
	return ctx.Err()
}
func (s *nodeChainAppendExecutionRun) Respond(ctx context.Context, complete func() error) (failure error) {
	if complete == nil || s.current(ctx) != nil {
		return errNodeChainAppendExecution
	}
	s.mu.Lock()
	initialized, winning, remote, local, packet, hysteria, ordinal := s.initialized, s.winning, s.remote, s.localIO, s.packet, s.hysteria, s.ordinal
	s.mu.Unlock()
	if !initialized || ordinal < 0 || ordinal >= hopmeasure.LatencyBenchmarkSamples {
		return errNodeChainAppendExecution
	}
	if winning == routechoice.Local {
		if local == nil || remote != nil || (s.source.PacketOptions != "") != (packet != nil) || (s.source.Hysteria2Options != "") != (hysteria != nil) || packet != nil && hysteria != nil {
			return errNodeChainAppendExecution
		}
		tag := s.runtime.preparation.original.proofs[s.runtime.preparation.original.position].Tag
		_, failure = local.run(ctx, func(call context.Context, operation *leaseStopIO) ([]byte, error) {
			nonce, err := randomHex(16)
			if err != nil {
				return nil, err
			}
			var nativeDial func(context.Context, string, string) (net.Conn, error)
			if packet != nil {
				nativeDial = packet.dial
			}
			if hysteria != nil {
				nativeDial = hysteria.dial
			}
			if nativeDial != nil {
				return nil, s.source.exchangeChallenge(call, func(parent context.Context, actual, address string) (net.Conn, error) {
					original, e := nativeDial(parent, actual, address)
					var owned net.Conn
					var keepErr error
					if original != nil {
						owned, keepErr = operation.keep(original)
					}
					return owned, errors.Join(e, keepErr)
				}, tag, nonce, func(string) error { return complete() })
			}
			dial := func(parent context.Context, actual, address string) (net.Conn, error) {
				original, e := s.runtime.local.Dial(parent, actual, address)
				var owned net.Conn
				var keepErr error
				if original != nil {
					owned, keepErr = operation.keep(original)
				}
				return owned, errors.Join(e, keepErr)
			}
			wrap := func(parent context.Context, original net.Conn, method, password, address string) (net.Conn, error) {
				actual, e := wrapCandidateSS2022(parent, original, method, password, address)
				var owned net.Conn
				var keepErr error
				if actual != nil {
					owned, keepErr = operation.keep(actual)
				}
				return owned, errors.Join(e, keepErr)
			}
			return nil, s.source.exchangeNonce(call, dial, wrap, tag, nonce, func(string) error { return complete() })
		})
	} else if winning == routechoice.Server && remote != nil && local == nil {
		failure = s.remoteResponse(ctx, remote, ordinal, complete)
	} else {
		return errNodeChainAppendExecution
	}
	if failure == nil {
		s.mu.Lock()
		if s.ordinal != ordinal || s.closed {
			s.mu.Unlock()
			return errNodeChainAppendExecution
		}
		s.ordinal++
		s.mu.Unlock()
	}
	return failure
}
func (s *nodeChainAppendExecutionRun) remoteResponse(ctx context.Context, remote *nodeChainAppendExecutionRemoteCandidate, ordinal int, complete func() error) (failure error) {
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	request := hopmeasure.CandidateChallengeMAC(s.source.Token, s.source.NodeID, nonce, false)
	expected := hopmeasure.CandidateChallengeMAC(s.source.Token, s.source.NodeID, nonce, true)
	conn, err := remote.dial(ctx, ordinal)
	if conn != nil {
		defer func() { failure = errors.Join(failure, conn.Close()) }()
	}
	if err != nil || conn == nil {
		return errors.Join(err, errNodeChainAppendExecution)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return errNodeChainAppendExecution
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	frame := nonce + request
	if n, e := io.WriteString(conn, frame); e != nil || n != len(frame) {
		return errors.Join(e, io.ErrShortWrite)
	}
	reply := make([]byte, len(expected))
	if _, err = io.ReadFull(conn, reply); err != nil {
		return err
	}
	if !hmac.Equal(reply, []byte(expected)) {
		return errNodeChainAppendExecution
	}
	if err = complete(); err != nil {
		return err
	}
	var tail [1]byte
	if n, e := conn.Read(tail[:]); n != 0 || e != io.EOF {
		return errNodeChainAppendExecution
	}
	return ctx.Err()
}
func (s *nodeChainAppendExecutionRun) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.closeContext(ctx)
}
func (s *nodeChainAppendExecutionRun) closeContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return errNodeChainAppendExecution
	}
	// An admitted observation finishes before intentional run cancellation.
	// Later observations wait for this same original retirement transaction.
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.gate }()
	s.cancel()
	select {
	case <-s.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	closed, trial, remote, lease, local, packet, hysteria := s.closed, s.trial, s.remote, s.lease, s.localIO, s.packet, s.hysteria
	s.mu.Unlock()
	if closed {
		return nil
	}
	var failure error
	if trial != nil {
		failure = errors.Join(failure, trial.Close(ctx))
	}
	if remote != nil {
		failure = errors.Join(failure, remote.close(ctx))
	}
	if lease != nil {
		failure = errors.Join(failure, lease.close(ctx))
	}
	if local != nil {
		failure = errors.Join(failure, local.close(ctx))
	}
	// No key can be released while an original stream or trial is unjoined.
	if failure == nil && ctx.Err() == nil && packet != nil {
		failure = packet.close()
	}
	if failure == nil && ctx.Err() == nil && hysteria != nil {
		failure = hysteria.close()
	}
	if failure != nil || ctx.Err() != nil {
		return errors.Join(failure, ctx.Err())
	}
	s.mu.Lock()
	if s.trial != nil {
		s.mu.Unlock()
		return errNodeChainAppendExecution
	}
	s.closed = true
	s.mu.Unlock()
	s.runtime.mu.Lock()
	if s.runtime.active == s {
		s.runtime.active = nil
	}
	s.runtime.mu.Unlock()
	s.runtime.releaseJoinedHolds()
	return nil
}

// A trial is an actual client-observed path through this same candidate. Local
// uses the original last prefix reader; Server uses its provisioned worker and
// purpose-bound raw front streams. Both preserve end-to-end HTTP/TLS timing.
type nodeChainAppendExecutionTrial struct {
	self                *nodeChainAppendExecutionTrial
	run                 *nodeChainAppendExecutionRun
	candidate           routechoice.Candidate
	target, id          string
	ctx                 context.Context
	cancel              context.CancelFunc
	ready               chan struct{}
	gate                chan struct{}
	mu                  sync.Mutex
	initialized, closed bool
	lease               *nodeChainAppendExecutionLease
	remote              *nodeChainAppendExecutionRemoteCandidate
	proofIO             *nodeChainExecutionIO
	packet              *nodeChainAppendExecutionPacket
	hysteria            *nodeChainAppendExecutionHysteria
}

func (s *nodeChainAppendExecutionRun) Open(context.Context, routechoice.Candidate) (routechoice.Session, error) {
	return nil, errNodeChainAppendExecution
}
func (s *nodeChainAppendExecutionRun) OpenTarget(ctx context.Context, candidate routechoice.Candidate, target string) (routechoice.Session, error) {
	if s.current(ctx) != nil || !candidate.Valid() || candidate.Transport != "ordered-prefix-append" || candidate.EntryID != s.runtime.preparation.policy.localMembers[0].ProfileID || candidate.ExitID != s.source.Target.ID || !nodeChainExecutionTarget(target) {
		return nil, errNodeChainAppendExecution
	}
	s.mu.Lock()
	if s.trial != nil || s.closed {
		s.mu.Unlock()
		return nil, errNodeChainAppendExecution
	}
	lifetime, cancel := context.WithCancel(s.ctx)
	trial := &nodeChainAppendExecutionTrial{run: s, candidate: candidate, target: target, ctx: lifetime, cancel: cancel, ready: make(chan struct{}), gate: make(chan struct{}, 1)}
	trial.self = trial
	s.trial = trial
	s.mu.Unlock()
	err := trial.initialize(ctx)
	return trial, err
}
func (t *nodeChainAppendExecutionTrial) initialize(ctx context.Context) error {
	defer close(t.ready)
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	if t.candidate.Execution == routechoice.Server {
		lease, e := t.run.runtime.newLease(ctx)
		t.mu.Lock()
		t.lease = lease
		t.mu.Unlock()
		if e != nil || lease == nil {
			return errors.Join(e, errNodeChainAppendExecution)
		}
		remote, e := lease.newCandidate(ctx, t.run.source, multihoprelay.NodeChainPrefixComparePair, t.target)
		t.mu.Lock()
		t.remote = remote
		t.mu.Unlock()
		if e != nil || remote == nil {
			return errors.Join(e, errNodeChainAppendExecution)
		}
	} else if t.candidate.Execution == routechoice.Local && t.run.source.PacketOptions != "" {
		packet, e := t.run.reserveLocalPacket(ctx, t.ctx, t.target, t.current)
		t.mu.Lock()
		t.packet = packet
		t.mu.Unlock()
		if e != nil || packet == nil {
			return errors.Join(e, errNodeChainAppendExecution)
		}
		if e = packet.open(ctx); e != nil {
			return e
		}
	} else if t.candidate.Execution == routechoice.Local && t.run.source.Hysteria2Options != "" {
		hysteria, e := t.run.captureLocalHysteria(ctx, t.ctx, t.target, t.current)
		t.mu.Lock()
		t.hysteria = hysteria
		t.mu.Unlock()
		if e != nil || hysteria == nil {
			return errors.Join(e, errNodeChainAppendExecution)
		}
		if e = hysteria.open(ctx); e != nil {
			return e
		}
	}
	tag := t.run.runtime.preparation.original.proofs[t.run.runtime.preparation.original.position].Tag
	proof, err := newNodeChainExecutionIO(tag, t.run.source.API, t.run.source.Token, t.dial, t.current)
	t.mu.Lock()
	t.proofIO = proof
	t.mu.Unlock()
	if err != nil {
		return err
	}
	remoteCapture := ""
	if t.remote != nil {
		remoteCapture, err = t.remote.capture.Digest()
		if err != nil {
			return err
		}
	}
	id, err := nodeChainAppendExecutionDigest("routervpn-append-execution-trial-v1", []any{t.run.runtime.CaptureSHA256(), t.run.request, t.run.source.Target, t.candidate, t.target, nonce, remoteCapture})
	if err != nil {
		return err
	}
	if err = t.current(ctx); err != nil {
		return err
	}
	t.mu.Lock()
	t.id, t.initialized = id, true
	t.mu.Unlock()
	return nil
}
func (t *nodeChainAppendExecutionTrial) current(ctx context.Context) error {
	if t == nil || t.self != t || ctx == nil || ctx.Err() != nil || t.ctx.Err() != nil {
		return errNodeChainAppendExecution
	}
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	t.run.mu.Lock()
	same := t.run.trial == t
	t.run.mu.Unlock()
	if closed || !same {
		return errNodeChainAppendExecution
	}
	return t.run.current(ctx)
}
func (t *nodeChainAppendExecutionTrial) Verify(ctx context.Context) error {
	if err := t.current(ctx); err != nil {
		return err
	}
	t.mu.Lock()
	initialized, remote := t.initialized, t.remote
	t.mu.Unlock()
	if !initialized {
		return errNodeChainAppendExecution
	}
	if remote != nil {
		return remote.verify(ctx)
	}
	return ctx.Err()
}
func (t *nodeChainAppendExecutionTrial) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	value, _ := t.IdentityContext(ctx)
	return value
}
func (t *nodeChainAppendExecutionTrial) IdentityContext(ctx context.Context) (string, error) {
	if err := t.Verify(ctx); err != nil {
		return "", err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.id == "" {
		return "", errNodeChainAppendExecution
	}
	return t.id, nil
}
func (t *nodeChainAppendExecutionTrial) dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if t.current(ctx) != nil {
		return nil, errNodeChainAppendExecution
	}
	p := t.run.runtime.preparation.original
	actualTag := p.proofs[p.position].Tag
	api, err := privateAPI(t.run.source.API)
	if err != nil || tag != actualTag {
		return nil, errNodeChainAppendExecution
	}
	target, err := url.Parse(t.target)
	if err != nil {
		return nil, errNodeChainAppendExecution
	}
	ordinal := -1
	if address == api.Host {
		ordinal = 0
	} else if address == net.JoinHostPort(target.Hostname(), "443") {
		ordinal = 1
	}
	if ordinal < 0 {
		return nil, errNodeChainAppendExecution
	}
	t.mu.Lock()
	remote, packet, hysteria := t.remote, t.packet, t.hysteria
	t.mu.Unlock()
	if t.candidate.Execution == routechoice.Server {
		if remote == nil {
			return nil, errNodeChainAppendExecution
		}
		return remote.dial(ctx, ordinal)
	}
	if t.candidate.Execution != routechoice.Local || remote != nil {
		return nil, errNodeChainAppendExecution
	}
	source := t.run.source
	if source.PacketOptions != "" {
		if packet == nil {
			return nil, errNodeChainAppendExecution
		}
		return packet.dial(ctx, actualTag, address)
	}
	if source.Hysteria2Options != "" {
		if hysteria == nil || packet != nil {
			return nil, errNodeChainAppendExecution
		}
		return hysteria.dial(ctx, actualTag, address)
	}
	if packet != nil || hysteria != nil {
		return nil, errNodeChainAppendExecution
	}
	return dialCandidateStream(ctx, t.run.runtime.local.Dial, wrapCandidateSS2022, actualTag, source.Target.Address, source.Method, source.Password, address)
}
func (t *nodeChainAppendExecutionTrial) probe(ctx context.Context, target, token string, accept func([]byte) error) (time.Duration, error) {
	if t.current(ctx) != nil {
		return 0, errNodeChainAppendExecution
	}
	t.mu.Lock()
	owned := t.proofIO
	initialized := t.initialized
	t.mu.Unlock()
	if !initialized || owned == nil {
		return 0, errNodeChainAppendExecution
	}
	interval, err := hopmeasure.StartInterval()
	if err != nil {
		return 0, err
	}
	_, err = owned.run(ctx, func(call context.Context, operation *leaseStopIO) ([]byte, error) {
		data, e := externalProofHTTP(call, func(parent context.Context, tag, address string) (net.Conn, error) {
			original, dialErr := t.dial(parent, tag, address)
			var retained net.Conn
			var keepErr error
			if original != nil {
				retained, keepErr = operation.keep(original)
			}
			return retained, errors.Join(dialErr, keepErr)
		}, owned.tag, target, token, t.run.runtime.local.testTLS)
		if e != nil {
			return nil, e
		}
		if e = accept(data); e != nil {
			return nil, e
		}
		return nil, nil
	})
	if err != nil {
		return 0, err
	}
	return interval.Duration()
}
func (t *nodeChainAppendExecutionTrial) ProbeLast(ctx context.Context) (time.Duration, error) {
	return t.probe(ctx, healthURL(t.run.source.API), t.run.source.Token, func(data []byte) error {
		var value struct {
			OK     bool   `json:"ok"`
			NodeID string `json:"node_id"`
			Proof  string `json:"proof"`
		}
		if exactJSON(data, &value, 8192) != nil || !value.OK || value.NodeID != t.run.source.NodeID || value.Proof != "router-vpn-private-agent-v1" {
			return errNodeChainAppendExecution
		}
		return nil
	})
}
func (t *nodeChainAppendExecutionTrial) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	if target != t.target || !nodeChainExecutionTarget(target) {
		return 0, errNodeChainAppendExecution
	}
	nonce, err := randomHex(16)
	if err != nil {
		return 0, err
	}
	return t.probe(ctx, target+"?routervpn_proof="+nonce, "", func(data []byte) error {
		address, count := "", 0
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ip=") {
				address, count = strings.TrimSpace(strings.TrimPrefix(line, "ip=")), count+1
			}
		}
		if count != 1 || !externalPublicIP(address) {
			return errNodeChainAppendExecution
		}
		return nil
	})
}
func (t *nodeChainAppendExecutionTrial) Close(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if ctx == nil {
		return errNodeChainAppendExecution
	}
	t.cancel()
	select {
	case <-t.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case t.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-t.gate }()
	t.mu.Lock()
	closed, proof, remote, lease, packet, hysteria := t.closed, t.proofIO, t.remote, t.lease, t.packet, t.hysteria
	t.mu.Unlock()
	if closed {
		return nil
	}
	var failure error
	if proof != nil {
		failure = errors.Join(failure, proof.close(ctx))
	}
	if remote != nil {
		failure = errors.Join(failure, remote.close(ctx))
	}
	if lease != nil {
		failure = errors.Join(failure, lease.close(ctx))
	}
	if failure == nil && ctx.Err() == nil && packet != nil {
		failure = packet.close()
	}
	if failure == nil && ctx.Err() == nil && hysteria != nil {
		failure = hysteria.close()
	}
	if failure != nil || ctx.Err() != nil {
		return errors.Join(failure, ctx.Err())
	}
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.run.mu.Lock()
	if t.run.trial == t {
		t.run.trial = nil
	}
	t.run.mu.Unlock()
	return nil
}
