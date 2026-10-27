package multihoprelay

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

func TestTorLeaseAbsentWorkerNeverAdvertisesOrReserves(t *testing.T) {
	r := &runner{}
	config := torFixtureConfig()
	m, err := New(config, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	if challenge, sources, err := m.TorAvailable(netip.MustParseAddr("10.77.0.2")); !errors.Is(err, ErrUnavailable) || challenge != (ExternalPacketChallenge{}) || sources != nil {
		t.Fatal("private source references advertised without a native worker", challenge, sources, err)
	}
	for _, row := range m.Available() {
		if torMode(row["exit_mode"]) {
			t.Fatal("private source reference was advertised as a runtime capability")
		}
	}
	if _, err := m.CreateTor(context.Background(), netip.MustParseAddr("10.77.0.2"), torFixtureRequestFor(t, m, netip.MustParseAddr("10.77.0.2"))); !errors.Is(err, ErrUnavailable) || len(m.leases) != 0 || len(m.torAttempts) != 0 || r.starts != 0 {
		t.Fatal("missing native worker acquired or reserved a Tor lease", err)
	}
	config.TorExits[0].SourceSHA256 = strings.Repeat("e", 64)
	if m.cfg.TorExits[0].SourceSHA256 != torFixtureRequest().SourceSHA256 {
		t.Fatal("caller changed the frozen registry")
	}
	for _, mutate := range []func(*TorExitSource){
		func(s *TorExitSource) { s.ID = "../other" }, func(s *TorExitSource) { s.Mode = "shadowsocks" },
		func(s *TorExitSource) { s.SourceSHA256 = "unproved" }, func(s *TorExitSource) { s.DNSPolicySHA256 = "" },
	} {
		bad := torFixtureConfig()
		mutate(&bad.TorExits[0])
		if _, err := New(bad, req().EntryNodeID, r); err == nil {
			t.Fatal("invalid private source reference accepted")
		}
	}
}

func TestTorDiscoveryCapturesDetachedSourcesAndActualPeerWithoutAcquiring(t *testing.T) {
	runner := &torFixtureRunner{}
	m := torFixtureManager(t, runner)
	peer := netip.MustParseAddr("10.77.0.2")
	challenge, sources, err := m.TorAvailable(peer)
	want := torFixtureConfig().TorExits[0]
	if err != nil || challenge.Validate() != nil || challenge.Peer != peer.String() || challenge.Epoch != m.packetEpoch ||
		len(sources) != 1 || sources[0] != want || len(m.leases) != 0 || len(m.torAttempts) != 0 || len(runner.workers) != 0 {
		t.Fatal("discovery failed to capture source/peer or started a worker", challenge, sources, err)
	}
	sources[0].ID, sources[0].SourceSHA256 = "another-source", strings.Repeat("e", 64)
	_, again, err := m.TorAvailable(peer)
	if err != nil || len(again) != 1 || again[0] != want || m.cfg.TorExits[0] != want {
		t.Fatal("caller changed private Tor registry through discovery", again, err)
	}
	for _, invalid := range []string{"203.0.113.4", "127.0.0.1", "0.0.0.0", "ff02::1", "fd77::2%eth0"} {
		if c, refs, err := m.TorAvailable(netip.MustParseAddr(invalid)); !errors.Is(err, ErrOwnership) || c != (ExternalPacketChallenge{}) || refs != nil {
			t.Fatal("invalid peer received source discovery", invalid, c, refs, err)
		}
	}
	other, _, err := m.TorAvailable(netip.MustParseAddr("10.77.0.3"))
	if err != nil || other.Epoch != challenge.Epoch || other.Peer != "10.77.0.3" {
		t.Fatal("discovery reused another peer's challenge", other, err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, refs, err := m.TorAvailable(peer); !errors.Is(err, ErrUnavailable) || c != (ExternalPacketChallenge{}) || refs != nil {
		t.Fatal("closed manager retained discovery", c, refs, err)
	}
	config := torFixtureConfig()
	config.TorExits = nil
	empty, err := New(config, req().EntryNodeID, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close(context.Background())
	if c, refs, err := empty.TorAvailable(peer); !errors.Is(err, ErrUnavailable) || c != (ExternalPacketChallenge{}) || refs != nil {
		t.Fatal("unprovisioned native worker advertised Tor", c, refs, err)
	}
}

func TestTorLeaseBootstrapAndStatusDoNotHoldGlobalLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &torFixtureRunner{}
		m := torFixtureManager(t, r)
		defer func() {
			if err := m.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}()
		q := torFixtureRequestFor(t, m, netip.MustParseAddr("10.77.0.2"))
		start := time.Now()
		lease := torFixtureAcquire(t, m, "10.77.0.2", q)
		p := r.worker(t, 0)
		<-p.bootstrap
		if lease.Phase != TorPending || lease.BootstrapDeadline.Sub(start) != TorBootstrapLimit || !time.Now().Equal(start) {
			t.Fatal("PUT waited for Tor bootstrap or lost its absolute deadline")
		}
		ordinary, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), req())
		if err != nil || ordinary.Port == lease.Port || !time.Now().Equal(start) {
			t.Fatal("pending bootstrap blocked another peer or shared its port", err)
		}
		other := torFixtureAcquire(t, m, "10.77.0.4", q)
		if other.Port == lease.Port || other.Username == lease.Username || other.Password == lease.Password || other.OwnerID == lease.OwnerID {
			t.Fatal("independent peers shared a front or native owner")
		}
		status, err := m.TorStatus(context.Background(), netip.MustParseAddr("10.77.0.2"), q, strings.Repeat("e", 64))
		if err != nil || status.Receipt.Phase != TorPending || status.Receipt.TrafficAllowed || status.Receipt.IsTor || status.Receipt.DNSProven {
			t.Fatal("pending lease invented connection proof", err)
		}
		p.finish()
		synctest.Wait()
		status, err = m.TorStatus(context.Background(), netip.MustParseAddr("10.77.0.2"), q, strings.Repeat("f", 64))
		if err != nil || status.Lease.Phase != TorReady || !status.Receipt.TrafficAllowed || !status.Receipt.DNSProven || !status.Receipt.IsTor {
			t.Fatal("complete owned proof did not become ready", err)
		}
		if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q.request()); err == nil {
			t.Fatal("legacy API renewed Tor while omitting the source pin")
		}
		if err := m.Delete(context.Background(), netip.MustParseAddr("10.77.0.2"), q.request()); err == nil || !p.Alive() {
			t.Fatal("legacy API deleted a typed Tor owner")
		}
	})
}

func TestTorLeaseRenewalCannotExtendAbsoluteBootstrapDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &torFixtureRunner{}
		m := torFixtureManager(t, r)
		defer m.Close(context.Background())
		peer := netip.MustParseAddr("10.77.0.2")
		q := torFixtureRequestFor(t, m, peer)
		lease := torFixtureAcquire(t, m, peer.String(), q)
		p := r.worker(t, 0)
		for i := 0; i < 2; i++ {
			time.Sleep(time.Minute)
			renewed, err := m.CreateTor(context.Background(), peer, q)
			if err != nil || renewed.OwnerID != lease.OwnerID || !renewed.BootstrapDeadline.Equal(lease.BootstrapDeadline) || !renewed.ExpiresAt.After(lease.ExpiresAt) {
				t.Fatal("renewal replaced owner or extended bootstrap", err)
			}
		}
		time.Sleep(time.Minute + time.Millisecond)
		synctest.Wait()
		if p.Alive() || p.stops.Load() == 0 {
			t.Fatal("absolute bootstrap expiry did not cancel and join its worker")
		}
		if err := m.Sweep(context.Background()); err != nil || len(m.leases) != 0 {
			t.Fatal("expired bootstrap retained a confirmed drained lease", err)
		}
		if _, err := m.CreateTor(context.Background(), peer, q); !errors.Is(err, ErrOwnership) {
			t.Fatal("expired attempt was resurrected", err)
		}
	})
}

func TestTorLeaseReadyContextSurvivesAdmissionDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &torFixtureRunner{}
		m := torFixtureManager(t, r)
		peer := netip.MustParseAddr("10.77.0.2")
		q := torFixtureRequestFor(t, m, peer)
		torFixtureAcquire(t, m, peer.String(), q)
		p := r.worker(t, 0)
		<-p.bootstrap
		p.finish()
		synctest.Wait()
		if _, err := m.TorStatus(context.Background(), peer, q, strings.Repeat("e", 64)); err != nil {
			t.Fatal("ready proof was not adopted", err)
		}
		time.Sleep(TorBootstrapLimit + time.Second)
		p.mu.Lock()
		owned := p.ctx
		p.mu.Unlock()
		if owned == nil || owned.Err() != nil || !p.Alive() {
			t.Fatal("successful admission cancelled the context owning native sockets")
		}
		if _, err := m.CreateTor(context.Background(), peer, q); err != nil {
			t.Fatal("live ready owner could not renew", err)
		}
		if err := m.DeleteTor(context.Background(), peer, q); err != nil || owned.Err() == nil || p.Alive() {
			t.Fatal("delete did not revoke and join the same context", err)
		}
	})
}

func TestTorLeaseDelayedStatusCannotAdoptChangedRegistry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &torFixtureRunner{}
		m := torFixtureManager(t, r)
		defer m.Close(context.Background())
		peer := netip.MustParseAddr("10.77.0.2")
		q := torFixtureRequestFor(t, m, peer)
		lease := torFixtureAcquire(t, m, peer.String(), q)
		p := r.worker(t, 0)
		p.finish()
		synctest.Wait()
		challenge := strings.Repeat("e", 64)
		p.mu.Lock()
		p.blockedNonce, p.readEntered, p.readRelease = challenge, make(chan struct{}), make(chan struct{})
		entered, release := p.readEntered, p.readRelease
		p.mu.Unlock()
		result := make(chan error, 1)
		go func() { _, err := m.torStatus(context.Background(), peer, q, challenge, true); result <- err }()
		<-entered
		// This create must complete while native status is deliberately blocked.
		if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), req()); err != nil {
			t.Fatal("native status held the manager lock", err)
		}
		m.mu.Lock()
		m.cfg.TorExits[0].DNSPolicySHA256 = strings.Repeat("f", 64)
		m.mu.Unlock()
		close(release)
		if err := <-result; !errors.Is(err, ErrOwnership) {
			t.Fatal("late status adopted a different registry/DNS owner", err)
		}
		if !m.leases[PeerKey(peer)].ExpiresAt.Equal(lease.ExpiresAt) {
			t.Fatal("stale status extended the lease")
		}
		if err := m.DeleteTor(context.Background(), peer, q); err != nil || p.Alive() {
			t.Fatal("registry change prevented exact old-owner cleanup", err)
		}
	})
}

func TestTorLeaseLateStatusCannotTouchReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &torFixtureRunner{}
		m := torFixtureManager(t, r)
		defer m.Close(context.Background())
		peer := netip.MustParseAddr("10.77.0.2")
		q := torFixtureRequestFor(t, m, peer)
		torFixtureAcquire(t, m, peer.String(), q)
		p := r.worker(t, 0)
		p.finish()
		synctest.Wait()
		challenge := strings.Repeat("e", 64)
		p.mu.Lock()
		p.blockedNonce, p.readEntered, p.readRelease = challenge, make(chan struct{}), make(chan struct{})
		entered, release := p.readEntered, p.readRelease
		p.mu.Unlock()
		result := make(chan error, 1)
		go func() { _, err := m.torStatus(context.Background(), peer, q, challenge, true); result <- err }()
		<-entered
		if err := m.DeleteTor(context.Background(), peer, q); err != nil {
			t.Fatal(err)
		}
		next := q
		next.SessionID = strings.Repeat("c", 32)
		replacement := torFixtureAcquire(t, m, peer.String(), next)
		close(release)
		if err := <-result; err == nil {
			t.Fatal("cancelled old status was adopted")
		}
		active := m.leases[PeerKey(peer)]
		if active.tor.capture.OwnerID != replacement.OwnerID || active.retired || !active.ExpiresAt.Equal(replacement.ExpiresAt) || !r.worker(t, 1).Alive() {
			t.Fatal("old callback mutated or stopped replacement")
		}
	})
}

func TestTorLeaseCancelledLateStartRetainsPortUntilJoined(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate, seen := make(chan struct{}), make(chan struct{})
		r := &torFixtureRunner{startGate: gate, startSeen: seen, ignoreStart: true}
		c := torFixtureConfig()
		c.LastPort = c.FirstPort
		m, err := New(c, req().EntryNodeID, r)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close(context.Background())
		peer := netip.MustParseAddr("10.77.0.2")
		q := torFixtureRequestFor(t, m, peer)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { _, err := m.CreateTor(ctx, peer, q); result <- err }()
		<-seen
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled startup was reported as acquired", err)
		}
		if len(m.leases) != 1 || !m.leases[PeerKey(peer)].retired {
			t.Fatal("unjoined cancelled startup lost its port ownership")
		}
		if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), req()); err == nil {
			t.Fatal("another peer reused an unjoined pending worker's port")
		}
		close(gate)
		synctest.Wait()
		p := r.worker(t, 0)
		if p.Alive() || p.stops.Load() == 0 {
			t.Fatal("late worker escaped captured cleanup")
		}
		if err := m.Sweep(context.Background()); err != nil || len(m.leases) != 0 {
			t.Fatal("joined cancelled worker did not release ownership", err)
		}
		if _, err := m.CreateTor(context.Background(), peer, q); !errors.Is(err, ErrOwnership) {
			t.Fatal("cancelled request resurrected", err)
		}
	})
}

func TestTorLeaseFailedStopAndDeleteBeforePutRetainOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &torFixtureRunner{}
		m := torFixtureManager(t, r)
		defer m.Close(context.Background())
		peer := netip.MustParseAddr("10.77.0.2")
		q := torFixtureRequestFor(t, m, peer)
		if err := m.DeleteTor(context.Background(), peer, q); err != nil {
			t.Fatal(err)
		}
		if _, err := m.CreateTor(context.Background(), peer, q); !errors.Is(err, ErrOwnership) {
			t.Fatal("DELETE-before-PUT allowed late acquisition", err)
		}
		q.SessionID = strings.Repeat("c", 32)
		torFixtureAcquire(t, m, peer.String(), q)
		p := r.worker(t, 0)
		p.stopFail.Store(true)
		if err := m.DeleteTor(context.Background(), peer, q); err == nil || len(m.leases) != 1 || !m.leases[PeerKey(peer)].retired {
			t.Fatal("failed native join released a port or resurrectable owner")
		}
		if _, err := m.CreateTor(context.Background(), peer, q); err == nil {
			t.Fatal("failed cleanup allowed renewal")
		}
		p.stopFail.Store(false)
		if err := m.DeleteTor(context.Background(), peer, q); err != nil || p.Alive() || len(m.leases) != 0 {
			t.Fatal("exact retry could not complete owned cleanup", err)
		}
	})
}

func TestTorLeaseWrongSourcePeerAndDNSDoNotAcquire(t *testing.T) {
	for name, mutate := range map[string]func(*TorRequest){
		"session":                func(q *TorRequest) { q.SessionID = "old" },
		"entry":                  func(q *TorRequest) { q.EntryNodeID = strings.Repeat("e", 64) },
		"mode":                   func(q *TorRequest) { q.ExitMode = "tor" },
		"source":                 func(q *TorRequest) { q.SourceSHA256 = strings.Repeat("e", 64) },
		"dns":                    func(q *TorRequest) { q.DNSPolicySHA256 = strings.Repeat("e", 64) },
		"partial-front":          func(q *TorRequest) { q.Port = 26240 },
		"same-front-credentials": func(q *TorRequest) { q.Port = 26240; q.Username = strings.Repeat("e", 48); q.Password = q.Username },
	} {
		t.Run(name, func(t *testing.T) {
			r := &torFixtureRunner{}
			m := torFixtureManager(t, r)
			q := torFixtureRequestFor(t, m, netip.MustParseAddr("10.77.0.2"))
			mutate(&q)
			if _, err := m.CreateTor(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err == nil || len(r.workers) != 0 || len(m.leases) != 0 {
				t.Fatal("invalid acquisition started a worker", err)
			}
		})
	}
}

func TestTorLeaseMonotonicBootstrapBoundSurvivesDelayedTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &torFixtureRunner{}
		m := torFixtureManager(t, r)
		defer m.Close(context.Background())
		peer := netip.MustParseAddr("10.77.0.2")
		q := torFixtureRequestFor(t, m, peer)
		torFixtureAcquire(t, m, peer.String(), q)
		p, owner := r.worker(t, 0), m.leases[PeerKey(peer)].tor
		<-p.bootstrap
		// Simulate a delayed runtime timer without changing production policy.
		// The independent monotonic adoption guard must still reject the result.
		owner.mu.Lock()
		owner.bootstrapTimer.Stop()
		owner.mu.Unlock()
		time.Sleep(TorBootstrapLimit + time.Millisecond)
		p.finish()
		synctest.Wait()
		if p.Alive() || p.stops.Load() == 0 {
			t.Fatal("late bootstrap escaped the independent absolute deadline")
		}
		if _, err := m.TorStatus(context.Background(), peer, q, strings.Repeat("f", 64)); err == nil {
			t.Fatal("late native proof became Ready")
		}
	})
}

func TestTorLeaseProofLossAndStatusTimeoutRetireOnlyOwnedWorker(t *testing.T) {
	for _, failure := range []string{"unproved-bootstrap", "lost-dns-proof", "status-timeout"} {
		t.Run(failure, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &torFixtureRunner{}
				m := torFixtureManager(t, r)
				defer m.Close(context.Background())
				peer := netip.MustParseAddr("10.77.0.2")
				q := torFixtureRequestFor(t, m, peer)
				torFixtureAcquire(t, m, peer.String(), q)
				p := r.worker(t, 0)
				if failure == "unproved-bootstrap" {
					p.mu.Lock()
					p.transform = func(r *TorReceipt) {
						if r.Phase == TorReady {
							r.DNSProven = false
						}
					}
					p.mu.Unlock()
				}
				p.finish()
				synctest.Wait()
				if failure != "unproved-bootstrap" {
					if _, err := m.TorStatus(context.Background(), peer, q, strings.Repeat("e", 64)); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), req()); err != nil {
					t.Fatal(err)
				}
				other := m.leases["10.77.0.3"].p
				if failure == "lost-dns-proof" {
					p.mu.Lock()
					p.transform = func(r *TorReceipt) { r.DNSProven = false }
					p.mu.Unlock()
				}
				challenge := strings.Repeat("f", 64)
				if failure == "status-timeout" {
					p.mu.Lock()
					p.blockedNonce, p.readEntered, p.readRelease, p.readHonorsContext = challenge, make(chan struct{}), make(chan struct{}), true
					p.mu.Unlock()
				}
				started := time.Now()
				if _, err := m.TorStatus(context.Background(), peer, q, challenge); err == nil {
					t.Fatal("unproved native worker remained ready")
				}
				if failure == "status-timeout" && time.Since(started) != torStatusLimit {
					t.Fatal("native status read lost its bounded deadline")
				}
				synctest.Wait()
				if p.Alive() || !other.Alive() {
					t.Fatal("proof failure did not isolate cleanup to its owned worker")
				}
			})
		})
	}
}

func TestTorLeaseAcquisitionChallengeRejectsReplayAfterExpiryOrRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &torFixtureRunner{}
		m := torFixtureManager(t, r)
		peer := netip.MustParseAddr("10.77.0.2")
		challenge, err := m.TorChallenge(peer)
		if err != nil || challenge.Epoch != m.packetEpoch || challenge.Peer != peer.String() || challenge.ExpiresAt != time.Now().Add(packetAcquireLifetime).Unix() {
			t.Fatal("invalid authenticated acquisition challenge", err)
		}
		q := torFixtureRequestFor(t, m, peer)
		if err := m.DeleteTor(context.Background(), peer, q); err != nil {
			t.Fatal(err)
		}
		time.Sleep(packetAcquireLifetime + time.Second)
		if _, err := m.CreateTor(context.Background(), peer, q); !errors.Is(err, ErrOwnership) || len(r.workers) != 0 {
			t.Fatal("expired cancelled request acquired after its tombstone aged", err)
		}
		fresh := torFixtureRequestFor(t, m, peer)
		fresh.SessionID = strings.Repeat("c", 32)
		if _, err := m.CreateTor(context.Background(), netip.MustParseAddr("10.77.0.3"), fresh); !errors.Is(err, ErrOwnership) {
			t.Fatal("challenge crossed authenticated peers", err)
		}
		restarted := torFixtureManager(t, r)
		if _, err := restarted.CreateTor(context.Background(), peer, fresh); !errors.Is(err, ErrOwnership) || len(r.workers) != 0 {
			t.Fatal("old manager epoch acquired after server restart", err)
		}
		future := fresh
		future.AcquireExpiresAt = time.Now().Add(packetAcquireLifetime + time.Second).Unix()
		if _, err := m.CreateTor(context.Background(), peer, future); !errors.Is(err, ErrOwnership) {
			t.Fatal("client extended the acquisition window", err)
		}
	})
}
