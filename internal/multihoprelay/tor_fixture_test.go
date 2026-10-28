package multihoprelay

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These controlled workers exercise the real lease manager and native receipt
// boundary. They do not stand in for a tested Tor binary, circuit or image.
type torFixtureProcess struct {
	capture           TorCapture
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
	transform         func(*TorReceipt)
}

func newTorFixtureProcess(c TorCapture) *torFixtureProcess {
	p := &torFixtureProcess{capture: c, bootstrap: make(chan struct{}), release: make(chan struct{})}
	p.alive.Store(true)
	return p
}

func (p *torFixtureProcess) Alive() bool { return p.alive.Load() }
func (p *torFixtureProcess) Stop(context.Context) error {
	p.stops.Add(1)
	if p.stopFail.Load() {
		return errors.New("controlled unjoined child")
	}
	p.alive.Store(false)
	return nil
}
func (p *torFixtureProcess) Bootstrap(ctx context.Context) error {
	p.mu.Lock()
	p.ctx = ctx
	p.mu.Unlock()
	close(p.bootstrap)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.release:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p.ready.Store(true)
		return nil
	}
}
func (p *torFixtureProcess) finish() { p.releaseOnce.Do(func() { close(p.release) }) }
func (p *torFixtureProcess) Snapshot(ctx context.Context, challenge string) (TorReceipt, error) {
	c := p.capture
	now := time.Now().UnixMilli()
	r := TorReceipt{Schema: 1, SessionID: c.Request.SessionID, OwnerID: c.OwnerID, Peer: c.Peer, SourceSHA256: c.Source.SourceSHA256,
		RegistrySHA256: c.RegistrySHA256, DNSPolicySHA256: c.Source.DNSPolicySHA256, FrontSHA256: c.FrontSHA256(), Nonce: challenge,
		Sequence: p.sequence.Add(1), HeartbeatAt: now, Phase: TorPending, Bootstrap: 25, FrontReady: true}
	if p.ready.Load() {
		r.Phase, r.Bootstrap, r.TrafficAllowed = TorReady, 100, true
		r.ExitIP, r.IsTor, r.DNSProven, r.ProofAt = "203.0.113.20", true, true, now
	}
	p.mu.Lock()
	blocked, entered, release, transform, honors := p.blockedNonce == challenge, p.readEntered, p.readRelease, p.transform, p.readHonorsContext
	p.mu.Unlock()
	if blocked {
		close(entered)
		// Deliberately allow a late response after cancellation; the actual
		// manager must reject it rather than trust the fixture's cooperation.
		if honors {
			select {
			case <-release:
			case <-ctx.Done():
				return TorReceipt{}, ctx.Err()
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

type torFixtureRunner struct {
	mu          sync.Mutex
	workers     []*torFixtureProcess
	startGate   <-chan struct{}
	startSeen   chan struct{}
	startOnce   sync.Once
	ignoreStart bool
}

func (r *torFixtureRunner) Start(context.Context, []byte, Lease) (Process, error) {
	return &process{alive: true}, nil
}
func (r *torFixtureRunner) StartTor(ctx context.Context, capture TorCapture) (TorProcess, error) {
	if capture.Validate() != nil {
		return nil, errors.New("invalid native capture")
	}
	p := newTorFixtureProcess(capture)
	r.mu.Lock()
	r.workers = append(r.workers, p)
	r.mu.Unlock()
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
	return p, nil
}
func (r *torFixtureRunner) worker(t *testing.T, index int) *torFixtureProcess {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if index >= len(r.workers) {
		t.Fatal("owned worker was not created")
	}
	return r.workers[index]
}

func torFixtureConfig() Config {
	c := config()
	c.LastPort, c.TTLSeconds = c.FirstPort+2, 300
	c.TorExits = []TorExitSource{{ID: "saved-tor", Mode: "tor-bridge", SourceSHA256: strings.Repeat("c", 64), DNSPolicySHA256: strings.Repeat("d", 64)}}
	return c
}
func torFixtureRequest() TorRequest {
	s := torFixtureConfig().TorExits[0]
	return TorRequest{SessionID: strings.Repeat("b", 32), EntryNodeID: req().EntryNodeID, ExitID: s.ID, ExitMode: s.Mode, SourceSHA256: s.SourceSHA256, DNSPolicySHA256: s.DNSPolicySHA256,
		Epoch: strings.Repeat("9", 64), Peer: "10.77.0.2", AcquireExpiresAt: time.Now().Add(packetAcquireLifetime).Unix()}
}
func torFixtureRequestFor(t *testing.T, m *Manager, peer netip.Addr) TorRequest {
	t.Helper()
	challenge, err := m.PacketChallenge(peer)
	if err != nil {
		t.Fatal(err)
	}
	q := torFixtureRequest()
	q.Epoch, q.Peer, q.AcquireExpiresAt = challenge.Epoch, challenge.Peer, challenge.ExpiresAt
	return q
}
func torFixtureManager(t *testing.T, r *torFixtureRunner) *Manager {
	t.Helper()
	m, err := New(torFixtureConfig(), req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func torFixtureAcquire(t *testing.T, m *Manager, peer string, q TorRequest) TorLease {
	t.Helper()
	if q.Peer != peer {
		// A distinct authenticated peer obtains its own challenge; copying the
		// first peer's wire request is deliberately not a valid acquisition.
		challenge, err := m.TorChallenge(netip.MustParseAddr(peer))
		if err != nil {
			t.Fatal(err)
		}
		q.Epoch, q.Peer, q.AcquireExpiresAt = challenge.Epoch, challenge.Peer, challenge.ExpiresAt
	}
	lease, err := m.CreateTor(context.Background(), netip.MustParseAddr(peer), q)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}
