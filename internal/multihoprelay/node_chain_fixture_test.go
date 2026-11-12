package multihoprelay

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These workers exercise the shipping Manager, capture and receipt validators.
// They own no socket, native binary or encryption engine; their positive replies
// are controlled protocol inputs, never evidence of a working native path.
type nodeChainFixtureProcess struct {
	capture           NodeChainCapture
	alive             atomic.Bool
	ready             atomic.Bool
	stopFail          atomic.Bool
	stops             atomic.Int32
	sequence          atomic.Uint64
	bootstrap         chan struct{}
	release           chan struct{}
	releaseOnce       sync.Once
	mu                sync.Mutex
	ctx               context.Context
	blockedNonce      string
	readEntered       chan struct{}
	readRelease       chan struct{}
	readHonorsContext bool
	transform         func(*NodeChainReceipt)
}

func newNodeChainFixtureProcess(c NodeChainCapture) *nodeChainFixtureProcess {
	p := &nodeChainFixtureProcess{capture: c.Clone(), bootstrap: make(chan struct{}), release: make(chan struct{})}
	p.alive.Store(true)
	return p
}

func (p *nodeChainFixtureProcess) Alive() bool { return p.alive.Load() }
func (p *nodeChainFixtureProcess) Stop(context.Context) error {
	p.stops.Add(1)
	if p.stopFail.Load() {
		return errors.New("controlled original child has not joined")
	}
	p.alive.Store(false)
	return nil
}
func (p *nodeChainFixtureProcess) Bootstrap(ctx context.Context) error {
	p.mu.Lock()
	p.ctx = ctx
	p.mu.Unlock()
	close(p.bootstrap)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.release:
		if err := ctx.Err(); err != nil {
			return err
		}
		p.ready.Store(true)
		return nil
	}
}
func (p *nodeChainFixtureProcess) finish() { p.releaseOnce.Do(func() { close(p.release) }) }
func (p *nodeChainFixtureProcess) Snapshot(ctx context.Context, challenge string) (NodeChainReceipt, error) {
	c := p.capture
	digest, err := c.Digest()
	if err != nil {
		return NodeChainReceipt{}, err
	}
	now := time.Now().UnixMilli()
	r := NodeChainReceipt{Schema: 1, SessionID: c.Request.SessionID, OwnerID: c.OwnerID, Peer: c.Peer, SourceSHA256: c.Source.SourceSHA256,
		RegistrySHA256: c.RegistrySHA256, DNSPolicySHA256: c.Source.DNSPolicySHA256, CaptureSHA256: digest, Nonce: challenge,
		Sequence: p.sequence.Add(1), HeartbeatAt: now, Phase: NodeChainPending, FrontReady: true}
	if p.ready.Load() {
		r.Phase, r.TrafficAllowed, r.DNSProven, r.PublicProven, r.ProofAt = NodeChainReady, true, true, true, now
		for _, member := range c.Source.Members {
			r.Prefixes = append(r.Prefixes, NodeChainPrefixReceipt{Position: member.Position, ProfileID: member.ProfileID, NodeID: member.NodeID, Mode: member.Mode, Proven: true, ResponseMS: float64(member.Position) + 0.25})
		}
	}
	p.mu.Lock()
	blocked, entered, release, honors, transform := p.blockedNonce == challenge, p.readEntered, p.readRelease, p.readHonorsContext, p.transform
	p.mu.Unlock()
	if blocked {
		close(entered)
		// The uncooperative variant deliberately returns after cancellation. The
		// production manager, rather than this boundary double, must reject it.
		if honors {
			select {
			case <-release:
			case <-ctx.Done():
				return NodeChainReceipt{}, ctx.Err()
			}
		} else {
			<-release
		}
	}
	if transform != nil {
		transform(&r)
	}
	return r, nil
}
func (p *nodeChainFixtureProcess) block(challenge string, honors bool) (<-chan struct{}, chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blockedNonce, p.readEntered, p.readRelease, p.readHonorsContext = challenge, make(chan struct{}), make(chan struct{}), honors
	return p.readEntered, p.readRelease
}

type nodeChainFixtureOrdinaryProcess struct {
	alive    atomic.Bool
	stopFail atomic.Bool
}

func (p *nodeChainFixtureOrdinaryProcess) Alive() bool { return p.alive.Load() }
func (p *nodeChainFixtureOrdinaryProcess) Stop(context.Context) error {
	if p.stopFail.Load() {
		return errors.New("ordinary original child has not joined")
	}
	p.alive.Store(false)
	return nil
}

type nodeChainFixtureRunner struct {
	mu             sync.Mutex
	workers        []*nodeChainFixtureProcess
	ordinary       []*nodeChainFixtureOrdinaryProcess
	ordinaryStarts atomic.Int32
	startGate      <-chan struct{}
	startSeen      chan struct{}
	startOnce      sync.Once
	ignoreStart    bool
	startErr       error
	mutateInput    bool
	configure      func(*nodeChainFixtureProcess)
}

func (r *nodeChainFixtureRunner) Start(context.Context, []byte, Lease) (Process, error) {
	r.ordinaryStarts.Add(1)
	p := &nodeChainFixtureOrdinaryProcess{}
	p.alive.Store(true)
	r.mu.Lock()
	r.ordinary = append(r.ordinary, p)
	r.mu.Unlock()
	return p, nil
}
func (r *nodeChainFixtureRunner) StartChain(ctx context.Context, capture NodeChainCapture) (NodeChainProcess, error) {
	if err := capture.Validate(); err != nil {
		return nil, err
	}
	p := newNodeChainFixtureProcess(capture)
	if r.configure != nil {
		r.configure(p)
	}
	r.mu.Lock()
	r.workers = append(r.workers, p)
	r.mu.Unlock()
	if r.mutateInput {
		capture.Source.Members[0].ProfileID = "runner-replacement"
		capture.Request.Users[0].Password = strings.Repeat("e", 48)
		capture.Request.LocalPacketPublicKeys[0] = "runner-replacement"
	}
	if r.startSeen != nil {
		r.startOnce.Do(func() { close(r.startSeen) })
	}
	if r.startGate != nil {
		if r.ignoreStart {
			<-r.startGate
		} else {
			select {
			case <-r.startGate:
			case <-ctx.Done():
				return p, ctx.Err()
			}
		}
	}
	return p, r.startErr
}
func (r *nodeChainFixtureRunner) worker(t *testing.T, index int) *nodeChainFixtureProcess {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if index >= len(r.workers) {
		t.Fatal("original ordered worker was not created")
	}
	return r.workers[index]
}
func (r *nodeChainFixtureRunner) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.workers) }

func nodeChainFixtureConfig(t *testing.T, count int) Config {
	t.Helper()
	c := config()
	c.LastPort, c.TTLSeconds = c.FirstPort+7, 300
	source := chainCaptureFixture(t, count).Source
	source.EntryNodeID = req().EntryNodeID
	c.NodeChains = []NodeChainDescriptor{source}
	return c
}
func nodeChainFixtureManager(t *testing.T, count int, r Runner) *Manager {
	t.Helper()
	m, err := New(nodeChainFixtureConfig(t, count), req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func nodeChainFixtureRequestFor(t *testing.T, m *Manager, peer netip.Addr) NodeChainRequest {
	t.Helper()
	challenge, err := m.PacketChallenge(peer)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	source := m.cfg.NodeChains[0].Clone()
	port := m.cfg.FirstPort
	m.mu.Unlock()
	q := chainCaptureFixture(t, len(source.Members)).Request
	q.EntryNodeID, q.SourceSHA256, q.DNSPolicySHA256 = source.EntryNodeID, source.SourceSHA256, source.DNSPolicySHA256
	q.DescriptorSHA256, err = source.Digest()
	if err != nil {
		t.Fatal(err)
	}
	q.Epoch, q.Peer, q.AcquireExpiresAt, q.Port = challenge.Epoch, challenge.Peer, challenge.ExpiresAt, port
	return q
}
func nodeChainFixtureAcquire(t *testing.T, m *Manager, peer netip.Addr, q NodeChainRequest) NodeChainLease {
	t.Helper()
	lease, err := m.CreateChain(context.Background(), peer, q)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}
func nodeChainFixtureOrdinaryRequest(m *Manager) Request {
	q := req()
	q.EntryNodeID = m.node
	return q
}
func nodeChainFixtureClose(t *testing.T, m *Manager) {
	t.Helper()
	if err := m.Close(context.Background()); err != nil {
		t.Error(err)
	}
}

// A complete MAX chain is validated by New and Build in the collision tests;
// it is never represented by a MAX label around an ordinary packet transport.
func nodeChainFixturePacketExit(t *testing.T, mode string, seed byte, alias bool) Exit {
	t.Helper()
	private := []byte(strings.Repeat(string(seed), 32))
	if alias {
		private[0] ^= 7
		private[31] ^= 128
	}
	encoded := base64.StdEncoding.EncodeToString(private)
	if mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" {
		return identityExit(t, "packet-owner", mode, encoded)
	}
	baseMode := mode
	if CompleteMAXMode(mode) {
		baseMode = MAXBaseMode(mode)
	}
	exit := pqExit(t, baseMode)
	exit.ID = "packet-owner"
	exit.Transport["private_key"] = encoded
	if !CompleteMAXMode(mode) {
		return exit
	}
	base := exit.Transport
	tags := MAXRelayTags()
	base["tag"], base["detour"] = tags.Root, tags.Middle
	base["peers"].([]any)[0].(map[string]any)["address"] = "10.88.0.1"
	base["pq"].(map[string]any)["endpoint"] = "10.88.0.1:51822"
	// Reuse the existing real inline-certificate builder. This only constructs
	// validated private source bytes; no PQ or other native diagnostic runs.
	outer := compositeExit(t, "split", "").Transport["udp"].(map[string]any)
	outer["tag"] = tags.Outer
	middle := map[string]any{"type": "shadowsocks", "tag": tags.Middle, "server": "10.88.0.1", "server_port": 8388,
		"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))), "detour": tags.Outer}
	exit.Mode = mode
	exit.Transport = map[string]any{"endpoint": base, "outbounds": []any{middle, outer}}
	if _, err := validateTransport(exit); err != nil {
		t.Fatal("complete MAX fixture did not validate", err)
	}
	return exit
}
