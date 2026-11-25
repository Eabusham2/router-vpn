package multihoprelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func candidateRequestFixture(t *testing.T, c NodeChainCapture) NodeChainCandidateRequest {
	t.Helper()
	digest, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return NodeChainCandidateRequest{Schema: 1, Lease: c.Request.Clone(), OwnerID: c.OwnerID, CaptureSHA256: digest, Operation: strings.Repeat("a", 64), ExecutionSHA256: strings.Repeat("b", 64), Trial: strings.Repeat("c", 32), SelectionEpoch: 1, InventorySHA256: strings.Repeat("d", 64), Position: 1, CandidateID: "candidate", CandidateSourceSHA256: strings.Repeat("e", 64), Address: "192.168.1.9:443", DeadlineAt: time.Now().Add(time.Minute).UnixMilli(), Password: strings.Repeat("9", 64)}
}
func candidateCaptureFixture(t *testing.T) NodeChainCandidateCapture {
	t.Helper()
	lease := chainCaptureFixture(t, 2)
	c, err := NewNodeChainCandidateCapture(lease, candidateRequestFixture(t, lease), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestNodeChainCandidateStrictAuthority(t *testing.T) {
	c := candidateCaptureFixture(t)
	raw, _ := json.Marshal(c.Request)
	if _, err := DecodeNodeChainCandidateRequest(raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*NodeChainCandidateRequest){
		"entry":             func(q *NodeChainCandidateRequest) { q.Position = 0 },
		"final":             func(q *NodeChainCandidateRequest) { q.Position = 2 },
		"foreign-owner":     func(q *NodeChainCandidateRequest) { q.OwnerID = strings.Repeat("f", 64) },
		"hostname":          func(q *NodeChainCandidateRequest) { q.Address = "candidate.example:443" },
		"mapped":            func(q *NodeChainCandidateRequest) { q.Address = "[::ffff:192.168.1.9]:443" },
		"extended-deadline": func(q *NodeChainCandidateRequest) { q.DeadlineAt = time.Now().Add(2 * time.Minute).UnixMilli() },
	} {
		t.Run(name, func(t *testing.T) {
			q := c.Request.Clone()
			mutate(&q)
			if _, err := NewNodeChainCandidateCapture(c.Lease, q, time.Now()); err == nil {
				t.Fatal("foreign candidate authority accepted")
			}
		})
	}
	for name, bad := range map[string]string{"duplicate": `{"schema":1,` + string(raw[1:]), "tag": strings.TrimSuffix(string(raw), "}") + `,"tag":"node-final"}`, "case": strings.Replace(string(raw), `"position"`, `"Position"`, 1), "null": strings.Replace(string(raw), `"position":1`, `"position":null`, 1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNodeChainCandidateRequest([]byte(bad)); err == nil {
				t.Fatal("ambiguous candidate request accepted")
			}
		})
	}

	ack, err := NewNodeChainCandidateCloseAcknowledgement(c.Request)
	if err != nil {
		t.Fatal(err)
	}
	ackRaw, _ := json.Marshal(ack)
	if _, err := DecodeNodeChainCandidateCloseAcknowledgement(ackRaw, c.Request); err != nil {
		t.Fatal(err)
	}
	stale := c.Request.Clone()
	stale.Operation = strings.Repeat("f", 64)
	if ack.Validate(stale) == nil {
		t.Fatal("same-session old candidate close acknowledged")
	}
	if _, err := DecodeNodeChainCandidateCloseAcknowledgement([]byte(`{"node_id":"old","session_id":"old","stopped":true}`), c.Request); err == nil {
		t.Fatal("legacy lease-only close acknowledged candidate")
	}
	frame := NodeChainCandidateIPCRequest{1, "candidate-prepare", strings.Repeat("7", 64), c}
	wire, _ := json.Marshal(frame)
	if _, err := DecodeNodeChainCandidateIPCRequest(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNodeChainIPCRequest(wire); err == nil {
		t.Fatal("legacy worker parser widened")
	}
	frame.Operation = "bootstrap"
	if frame.Validate() == nil {
		t.Fatal("candidate frame became proof authority")
	}
	frame.Operation = "candidate-close"
	digest, _ := c.Digest()
	response := NodeChainCandidateIPCResponse{Schema: 1, Operation: frame.Operation, Nonce: frame.Nonce, CaptureSHA256: digest, OK: true}
	rawResponse, _ := json.Marshal(response)
	if len(rawResponse) > NodeChainCandidateResponseMaximumBytes {
		t.Fatal("fixed candidate response exceeded bound")
	}
	if _, err := DecodeNodeChainCandidateIPCResponse(rawResponse, frame); err != nil {
		t.Fatal(err)
	}
	response.OK = false
	if response.Validate(frame) == nil {
		t.Fatal("failed native close acknowledged")
	}
	response.OK = true
	response.Operation = "candidate-status"
	if response.Validate(frame) == nil {
		t.Fatal("wrong operation response accepted")
	}
	response.Operation = frame.Operation
	response.Nonce = strings.Repeat("a", 64)
	if response.Validate(frame) == nil {
		t.Fatal("late response accepted")
	}
	if _, err := DecodeNodeChainCandidateIPCResponse(append(rawResponse, []byte(strings.Repeat(" ", NodeChainCandidateResponseMaximumBytes))...), frame); err == nil {
		t.Fatal("unbounded candidate response accepted")
	}

}
func TestNodeChainCandidateConnectQuotaAndJoin(t *testing.T) {
	c := candidateCaptureFixture(t)
	a, err := NewNodeChainCandidateAdmission(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < NodeChainCandidateMaximumConnects; i++ {
		release, err := a.Begin(context.Background(), c.Username(), c.Request.Password, "tcp", c.Request.Address)
		if err != nil {
			t.Fatal(i, err)
		}
		if _, err := a.Begin(context.Background(), c.Username(), c.Request.Password, "tcp", c.Request.Address); err == nil {
			t.Fatal("parallel candidate admitted")
		}
		release()
		release()
	}
	if _, err := a.Begin(context.Background(), c.Username(), c.Request.Password, "tcp", c.Request.Address); err == nil {
		t.Fatal("fifty-first candidate admitted")
	}
	if a.Snapshot().Accepted != 50 {
		t.Fatal("quota changed")
	}
	b, _ := NewNodeChainCandidateAdmission(context.Background(), c)
	release, err := b.Begin(context.Background(), c.Username(), c.Request.Password, "tcp", c.Request.Address)
	if err != nil {
		t.Fatal(err)
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if b.CloseContext(expired) == nil {
		t.Fatal("unjoined native connect released")
	}
	if r := b.Snapshot(); r.Drained || !r.Retired || !r.InFlight {
		t.Fatal("lost drain ownership")
	}
	release()
	if err := b.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !b.Snapshot().Drained {
		t.Fatal("original drain not joined")
	}
	fresh, err := NewNodeChainCandidateAdmission(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.CloseContext(context.Background())
	copy := NodeChainCandidateAdmission{self: fresh.self, capture: fresh.capture.Clone(), ctx: fresh.ctx, cancel: fresh.cancel}
	if _, err := copy.Begin(context.Background(), c.Username(), c.Request.Password, "tcp", c.Request.Address); err == nil {
		t.Fatal("copied admission accepted")
	}
	for _, target := range []struct{ network, address string }{{"udp", c.Request.Address}, {"tcp", "192.168.1.10:443"}} {
		if _, err := fresh.Begin(context.Background(), c.Username(), c.Request.Password, target.network, target.address); err == nil {
			t.Fatal("target widened")
		}
	}
}

// Controlled native boundaries exercise real Manager ownership, never claim
// a provider connection or encrypted packet route from these receipts.
type candidateFixtureOperation struct {
	prepareError   error
	capture        NodeChainCandidateCapture
	prepared       bool
	admission      *NodeChainCandidateAdmission
	prepareEntered chan struct{}
	prepareRelease chan struct{}
	readEntered    chan struct{}
	readRelease    chan struct{}
	failClose      bool
	mu             sync.Mutex
	closes         int
}

func (p *candidateFixtureOperation) Prepare(ctx context.Context) (NodeChainCandidateReceipt, error) {
	if p.prepareEntered != nil {
		close(p.prepareEntered)
		<-p.prepareRelease
	}
	if p.prepareError != nil {
		return NodeChainCandidateReceipt{}, p.prepareError
	}
	p.mu.Lock()
	p.prepared = ctx.Err() == nil
	p.mu.Unlock()
	return p.receipt(), ctx.Err()
}
func (p *candidateFixtureOperation) receipt() NodeChainCandidateReceipt {
	p.mu.Lock()
	prepared := p.prepared
	p.mu.Unlock()
	usage := p.admission.Snapshot()
	c := p.capture
	digest, _ := c.Digest()
	return NodeChainCandidateReceipt{1, c.Request.Operation, c.OperationOwnerID, digest, c.Request.DeadlineAt, prepared, usage.Retired, usage.Drained, usage.Accepted, usage.InFlight}
}
func (p *candidateFixtureOperation) Snapshot(context.Context) (NodeChainCandidateReceipt, error) {
	p.mu.Lock()
	entered, release := p.readEntered, p.readRelease
	p.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	return p.receipt(), nil
}
func (p *candidateFixtureOperation) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closes++
	fail := p.failClose
	p.mu.Unlock()
	if fail {
		return errors.New("controlled unjoined native operation")
	}
	return p.admission.CloseContext(ctx)
}

type candidateFixtureProcess struct {
	prepareError error
	failClose    bool
	*nodeChainFixtureProcess
	operation                      *candidateFixtureOperation
	prepareEntered, prepareRelease chan struct{}
	mu                             sync.Mutex
	creates                        int
}

func (p *candidateFixtureProcess) NewCandidateOperation(ctx context.Context, c NodeChainCandidateCapture) (NodeChainCandidateOperation, error) {
	a, err := NewNodeChainCandidateAdmission(ctx, c)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.creates++
	p.operation = &candidateFixtureOperation{prepareError: p.prepareError, failClose: p.failClose, capture: c.Clone(), admission: a, prepareEntered: p.prepareEntered, prepareRelease: p.prepareRelease}
	return p.operation, nil
}

type candidateFixtureRunner struct {
	nodeChainFixtureRunner
	process          *candidateFixtureProcess
	entered, release chan struct{}
}

func (r *candidateFixtureRunner) StartChain(ctx context.Context, c NodeChainCapture) (NodeChainProcess, error) {
	p := newNodeChainFixtureProcess(c)
	p.finish()
	r.process = &candidateFixtureProcess{nodeChainFixtureProcess: p, prepareEntered: r.entered, prepareRelease: r.release}
	return r.process, nil
}
func candidateManagerFixture(t *testing.T, r *candidateFixtureRunner) (*Manager, netip.Addr, NodeChainCandidateRequest) {
	t.Helper()
	m := nodeChainFixtureManager(t, 2, r)
	peer := netip.MustParseAddr("10.77.0.2")
	lease := nodeChainFixtureRequestFor(t, m, peer)
	nodeChainFixtureAcquire(t, m, peer, lease)
	deadline := time.Now().Add(time.Second)
	for {
		challenge, _ := nodeChainSecret()
		status, err := m.ChainStatus(context.Background(), peer, lease, challenge)
		if err == nil && status.Receipt.Phase == NodeChainReady {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("fixture original worker not ready", err)
		}
		time.Sleep(time.Millisecond)
	}
	return m, peer, candidateRequestFixture(t, r.process.capture)
}
func TestNodeChainCandidateManagerRetainsOriginalOperation(t *testing.T) {
	r := &candidateFixtureRunner{}
	m, peer, q := candidateManagerFixture(t, r)
	defer nodeChainFixtureClose(t, m)
	receipt, err := m.CreateChainCandidate(context.Background(), peer, q)
	if err != nil || !receipt.Prepared {
		t.Fatal("original candidate prepare", err)
	}
	original := r.process.operation
	if _, err = m.CreateChainCandidate(context.Background(), peer, q); !errors.Is(err, ErrBusy) {
		t.Fatal("duplicate preparation", err)
	}
	if r.process.creates != 1 || original.closes != 0 {
		t.Fatal("duplicate retired original")
	}
	original.mu.Lock()
	original.failClose = true
	original.mu.Unlock()
	if m.DeleteChainCandidate(context.Background(), peer, q) == nil {
		t.Fatal("unjoined operation released")
	}
	replacement := q.Clone()
	replacement.Operation = strings.Repeat("f", 64)
	if _, err = m.CreateChainCandidate(context.Background(), peer, replacement); err == nil {
		t.Fatal("replacement bypassed held drain", err)
	}
	original.mu.Lock()
	original.failClose = false
	original.mu.Unlock()
	if err = m.DeleteChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	if _, err = m.CreateChainCandidate(context.Background(), peer, replacement); err != nil {
		t.Fatal(err)
	}
	next := r.process.operation
	if err = m.DeleteChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	if next.closes != 0 {
		t.Fatal("stale same-inventory cleanup retired replacement")
	}
	if _, err = m.ChainCandidateStatus(context.Background(), peer, replacement); err != nil {
		t.Fatal(err)
	}
}
func TestNodeChainCandidateManagerCancellationJoin(t *testing.T) {
	r := &candidateFixtureRunner{entered: make(chan struct{}), release: make(chan struct{})}
	m, peer, q := candidateManagerFixture(t, r)
	defer nodeChainFixtureClose(t, m)
	result := make(chan error, 1)
	go func() { _, err := m.CreateChainCandidate(context.Background(), peer, q); result <- err }()
	select {
	case <-r.entered:
	case <-time.After(time.Second):
		t.Fatal("Prepare did not begin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if m.DeleteChainCandidate(ctx, peer, q) == nil {
		t.Fatal("unjoined Prepare released")
	}
	close(r.release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("late Prepare published readiness")
		}
	case <-time.After(time.Second):
		t.Fatal("Prepare did not join")
	}
	if err := m.DeleteChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	late := q.Clone()
	late.Operation = strings.Repeat("f", 64)
	if err := m.DeleteChainCandidate(context.Background(), peer, late); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateChainCandidate(context.Background(), peer, late); err == nil {
		t.Fatal("cancel-before-create accepted delayed request")
	}
}

func TestNodeChainCandidateManagerHeldStatusAndLeaseStop(t *testing.T) {
	r := &candidateFixtureRunner{}
	m, peer, q := candidateManagerFixture(t, r)
	defer nodeChainFixtureClose(t, m)
	if _, err := m.CreateChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	op := r.process.operation
	entered, release := make(chan struct{}), make(chan struct{})
	op.mu.Lock()
	op.readEntered = entered
	op.readRelease = release
	op.mu.Unlock()
	result := make(chan error, 1)
	go func() { _, err := m.ChainCandidateStatus(context.Background(), peer, q); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("status did not enter original callback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if m.DeleteChainCandidate(ctx, peer, q) == nil {
		t.Fatal("held status released replacement slot")
	}
	op.mu.Lock()
	closes := op.closes
	op.mu.Unlock()
	if closes != 0 {
		t.Fatal("native Close ran before admitted status joined")
	}
	close(release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("late status published after retirement")
		}
	case <-time.After(time.Second):
		t.Fatal("status callback did not join")
	}
	if err := m.DeleteChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	next := q.Clone()
	next.Operation = strings.Repeat("f", 64)
	if _, err := m.CreateChainCandidate(context.Background(), peer, next); err != nil {
		t.Fatal(err)
	}
	op = r.process.operation
	op.mu.Lock()
	op.failClose = true
	op.mu.Unlock()
	m.mu.Lock()
	owner := m.leases[PeerKey(peer)].chain
	m.mu.Unlock()
	if owner.Stop(context.Background()) == nil {
		t.Fatal("lease stop discarded unjoined candidate")
	}
	if !r.process.Alive() || r.process.stops.Load() != 0 {
		t.Fatal("original worker stopped before candidate drain")
	}
	op.mu.Lock()
	op.failClose = false
	op.mu.Unlock()
	if err := owner.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.process.Alive() {
		t.Fatal("original worker not joined")
	}
}

func TestNodeChainCandidateManagerExpiryRetainsJoin(t *testing.T) {
	r := &candidateFixtureRunner{}
	m, peer, q := candidateManagerFixture(t, r)
	defer nodeChainFixtureClose(t, m)
	q.DeadlineAt = time.Now().Add(300 * time.Millisecond).UnixMilli()
	if _, err := m.CreateChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	original := r.process.operation
	m.mu.Lock()
	owner := m.leases[PeerKey(peer)].chain
	m.mu.Unlock()
	owner.mu.Lock()
	op := owner.candidate
	owner.mu.Unlock()
	select {
	case <-op.expiryDone:
	case <-time.After(2 * time.Second):
		t.Fatal("idle expiry did not join original operation")
	}
	if r := original.admission.Snapshot(); !r.Retired || !r.Drained {
		t.Fatal("idle expiry lost native cleanup")
	}
	next := q.Clone()
	next.Operation = strings.Repeat("f", 64)
	next.DeadlineAt = time.Now().Add(time.Minute).UnixMilli()
	if _, err := m.CreateChainCandidate(context.Background(), peer, next); err != nil {
		t.Fatal("drained expiry retained busy slot", err)
	}
	if err := m.DeleteChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	if r.process.operation == original || r.process.operation.closes != 0 {
		t.Fatal("expired owner closed replacement")
	}
}

func TestNodeChainCandidateExpiryHeldCallbacks(t *testing.T) {
	for _, kind := range []string{"prepare", "status"} {
		t.Run(kind, func(t *testing.T) {
			r := &candidateFixtureRunner{}
			entered, release := make(chan struct{}), make(chan struct{})
			if kind == "prepare" {
				r.entered, r.release = entered, release
			}
			m, peer, q := candidateManagerFixture(t, r)
			defer nodeChainFixtureClose(t, m)
			q.DeadlineAt = time.Now().Add(400 * time.Millisecond).UnixMilli()
			result := make(chan error, 1)
			if kind == "prepare" {
				go func() { _, err := m.CreateChainCandidate(context.Background(), peer, q); result <- err }()
			} else {
				if _, err := m.CreateChainCandidate(context.Background(), peer, q); err != nil {
					t.Fatal(err)
				}
				native := r.process.operation
				native.mu.Lock()
				native.readEntered, native.readRelease = entered, release
				native.mu.Unlock()
				go func() { _, err := m.ChainCandidateStatus(context.Background(), peer, q); result <- err }()
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("expiry fixture callback not entered")
			}
			m.mu.Lock()
			owner := m.leases[PeerKey(peer)].chain
			m.mu.Unlock()
			owner.mu.Lock()
			op := owner.candidate
			owner.mu.Unlock()
			select {
			case <-op.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("original grant deadline not retained")
			}
			owner.mu.Lock()
			same := owner.candidate == op
			owner.mu.Unlock()
			if !same {
				t.Fatal("expiry released unjoined callback")
			}
			select {
			case <-op.expiryDone:
				t.Fatal("expiry cleanup lost its held callback")
			default:
			}
			close(release)
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("expired callback published success")
				}
			case <-time.After(time.Second):
				t.Fatal("expired callback did not join")
			}
			select {
			case <-op.expiryDone:
			case <-time.After(time.Second):
				t.Fatal("expiry worker did not join")
			}
			if err := m.DeleteChainCandidate(context.Background(), peer, q); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeChainCandidateRequestDeadlineRetainsCallback(t *testing.T) {
	r := &candidateFixtureRunner{entered: make(chan struct{}), release: make(chan struct{})}
	m, peer, q := candidateManagerFixture(t, r)
	defer nodeChainFixtureClose(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := m.CreateChainCandidate(ctx, peer, q); result <- err }()
	select {
	case <-r.entered:
	case <-time.After(time.Second):
		t.Fatal("request callback not admitted")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expired request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP deadline blocked on native callback")
	}
	m.mu.Lock()
	owner := m.leases[PeerKey(peer)].chain
	m.mu.Unlock()
	owner.mu.Lock()
	op := owner.candidate
	owner.mu.Unlock()
	if op == nil {
		t.Fatal("request deadline lost allocated native handle")
	}
	select {
	case <-op.done:
		t.Fatal("unjoined Prepare forgotten")
	default:
	}
	close(r.release)
	if err := m.DeleteChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
}

func TestNodeChainCandidatePrunesOnlyJoinedExpiredAttempts(t *testing.T) {
	r := &candidateFixtureRunner{}
	m, peer, q := candidateManagerFixture(t, r)
	defer nodeChainFixtureClose(t, m)
	m.mu.Lock()
	owner := m.leases[PeerKey(peer)].chain
	m.mu.Unlock()
	expired := q.Clone()
	expired.DeadlineAt = time.Now().Add(-time.Second).UnixMilli()
	owner.mu.Lock()
	owner.candidateAttempts = make(map[string]NodeChainCandidateRequest)
	for i := 0; i < nodeChainAttemptLimit; i++ {
		old := expired.Clone()
		old.Operation = fmt.Sprintf("%064x", i+1)
		owner.candidateAttempts[old.Operation] = old
	}
	owner.mu.Unlock()
	// A retained old operation cannot renew itself by changing its deadline
	// while capacity eviction would otherwise remove its original request.
	known := expired.Clone()
	known.Operation = fmt.Sprintf("%064x", 1)
	changed := known.Clone()
	changed.DeadlineAt = time.Now().Add(time.Minute).UnixMilli()
	if _, err := m.CreateChainCandidate(context.Background(), peer, changed); err == nil {
		t.Fatal("changed deadline erased retained operation before eviction")
	}
	changed = known.Clone()
	changed.Password = strings.Repeat("c", 32)
	if err := m.DeleteChainCandidate(context.Background(), peer, changed); err == nil {
		t.Fatal("altered expired request received original acknowledgment")
	}
	if err := m.DeleteChainCandidate(context.Background(), peer, known); err != nil {
		t.Fatal("exact retained expired request lost acknowledgment at capacity", err)
	}
	unknown := expired.Clone()
	unknown.Operation = strings.Repeat("e", 64)
	if err := m.DeleteChainCandidate(context.Background(), peer, unknown); err == nil {
		t.Fatal("unknown expired request received cleanup acknowledgment")
	}
	owner.mu.Lock()
	if len(owner.candidateAttempts) != nodeChainAttemptLimit {
		owner.mu.Unlock()
		t.Fatal("exact cancellation unexpectedly pruned bounded history")
	}
	// An expired operation still holding its original slot is not prunable.
	held := expired.Clone()
	held.Operation = strings.Repeat("f", 64)
	owner.candidateAttempts[held.Operation] = held
	owner.candidate = &nodeChainCandidateOwned{capture: NodeChainCandidateCapture{Request: held}}
	owner.pruneCandidateAttempts(time.Now())
	if len(owner.candidateAttempts) != 1 {
		owner.mu.Unlock()
		t.Fatal("expired held authority pruned or joined history leaked")
	}
	owner.candidate = nil
	owner.mu.Unlock()
	if err := m.DeleteChainCandidate(context.Background(), peer, known); err == nil {
		t.Fatal("evicted request regained cleanup acknowledgment")
	}
	if _, err := m.CreateChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal("joined expired tombstones exhausted live lease", err)
	}
	if err := m.DeleteChainCandidate(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	expired.Operation = strings.Repeat("b", 64)
	if _, err := m.CreateChainCandidate(context.Background(), peer, expired); err == nil {
		t.Fatal("pruning revived expired operation")
	}
}
func TestNodeChainCandidateWireIdentityCannotFollowReplacement(t *testing.T) {
	c := candidateCaptureFixture(t)
	old, err := NewNodeChainCandidateAdmission(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, err := NewNodeChainCandidateCapture(c.Lease, c.Request, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if next.Username() == c.Username() {
		t.Fatal("server-generated wire identity reused")
	}
	replacement, err := NewNodeChainCandidateAdmission(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.CloseContext(context.Background())
	if _, err := replacement.Begin(context.Background(), c.Username(), c.Request.Password, "tcp", c.Request.Address); err == nil {
		t.Fatal("old credentials consumed replacement quota")
	}
	if _, err := old.Begin(context.Background(), next.Username(), next.Request.Password, "tcp", next.Request.Address); err == nil {
		t.Fatal("old captured handshake followed replacement")
	}
	release, err := replacement.Begin(context.Background(), next.Username(), next.Request.Password, "tcp", next.Request.Address)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if replacement.Snapshot().Accepted != 1 {
		t.Fatal("stale authentication consumed quota")
	}
}
