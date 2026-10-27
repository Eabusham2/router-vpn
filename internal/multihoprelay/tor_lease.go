package multihoprelay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	TorBootstrapLimit = 3 * time.Minute
	torStartLimit     = 8 * time.Second
	torStatusLimit    = time.Second
	torAttemptLimit   = 1024
)

// TorRunner is an explicit native capability, not a fallback to Runner.Start.
// StartTor resolves the exact private source, binds the authenticated private
// front with forwarding disabled, and returns promptly. It must not bootstrap
// Tor or retain the HTTP request context. Its context belongs to the lease and
// remains live after successful startup, until retirement or native failure.
// The shipping relayExecRunner intentionally does not implement this interface
// until the real Tor worker, protected control channel and image are adopted.
type TorRunner interface {
	StartTor(context.Context, TorCapture) (TorProcess, error)
}

// TorProcess owns the native front, Tor child, PT workers and control channel.
// Bootstrap must keep application forwarding closed until it has actual Tor
// and selected-DNS proof. Snapshot must answer the fresh nonce through its
// authenticated native owner channel, not read an arbitrary caller path.
// Stop must join every owned child and listener; a failure retains the lease.
type TorProcess interface {
	Process
	Bootstrap(context.Context) error
	Snapshot(context.Context, string) (TorReceipt, error)
}

type torAttempt struct {
	request TorRequest
	until   time.Time
	retired bool
}

type torOwnedProcess struct {
	mu             sync.Mutex
	capture        TorCapture
	runner         TorRunner
	now            func() time.Time
	ctx            context.Context
	cancel         context.CancelFunc
	started        chan struct{}
	done           chan struct{}
	startOnce      sync.Once
	stopGate       chan struct{}
	p              TorProcess
	phase          TorPhase
	frontReady     bool
	bootstrapped   bool
	drained        bool
	bootstrapTimer *time.Timer
}

func torSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("Tor owner identity could not be generated")
	}
	return hex.EncodeToString(raw[:]), nil
}

func newTorOwnedProcess(capture TorCapture, runner TorRunner, now func() time.Time) *torOwnedProcess {
	ctx, cancel := context.WithCancel(context.Background())
	return &torOwnedProcess{capture: capture, runner: runner, now: now, ctx: ctx, cancel: cancel,
		started: make(chan struct{}), done: make(chan struct{}), stopGate: make(chan struct{}, 1), phase: TorPending}
}

func (o *torOwnedProcess) launch() {
	o.mu.Lock()
	o.bootstrapTimer = time.AfterFunc(time.Until(o.capture.BootstrapDeadline), func() { o.expire(o.capture.BootstrapDeadline, false) })
	o.mu.Unlock()
	go o.run()
}

func (o *torOwnedProcess) signalStarted() { o.startOnce.Do(func() { close(o.started) }) }

func (o *torOwnedProcess) expire(deadline time.Time, startup bool) {
	o.mu.Lock()
	if o.phase != TorPending || startup && o.frontReady || o.now().Before(deadline) {
		o.mu.Unlock()
		return
	}
	o.phase = TorFailed
	o.cancel()
	o.mu.Unlock()
	go o.cleanup()
}

func (o *torOwnedProcess) fail() {
	o.mu.Lock()
	if o.phase == TorRetired || o.phase == TorFailed {
		o.mu.Unlock()
		return
	}
	o.phase = TorFailed
	o.cancel()
	o.mu.Unlock()
	go o.cleanup()
}

func (o *torOwnedProcess) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = o.Stop(ctx)
}

func (o *torOwnedProcess) run() {
	defer func() {
		o.signalStarted()
		close(o.done)
		o.mu.Lock()
		failed := o.phase == TorFailed || o.phase == TorRetired || o.ctx.Err() != nil
		o.mu.Unlock()
		// A late StartTor result is still ours, even if an earlier bounded Stop
		// could not join it. Retry cleanup after that result is captured.
		if failed {
			go o.cleanup()
		}
	}()
	startupDeadline := o.now().Add(torStartLimit)
	startupTimer := time.AfterFunc(torStartLimit, func() { o.expire(startupDeadline, true) })
	defer startupTimer.Stop()
	p, err := o.runner.StartTor(o.ctx, o.capture)
	o.mu.Lock()
	o.p = p
	o.mu.Unlock()
	if err != nil || p == nil || !p.Alive() || o.ctx.Err() != nil || !o.now().Before(startupDeadline) {
		o.fail()
		return
	}
	receipt, err := o.read(p, "")
	if err != nil || receipt.Phase != TorPending {
		o.fail()
		return
	}
	o.mu.Lock()
	if o.phase != TorPending || o.ctx.Err() != nil || !o.now().Before(startupDeadline) {
		o.mu.Unlock()
		o.fail()
		return
	}
	o.frontReady = true
	o.mu.Unlock()
	startupTimer.Stop()
	o.signalStarted()

	// This call is outside Manager.mu and its context is owned by the lease.
	// Successful bootstrap does not cancel the context that owns Tor sockets.
	if err := p.Bootstrap(o.ctx); err != nil {
		o.fail()
		return
	}
	receipt, err = o.read(p, "")
	o.mu.Lock()
	if err != nil || receipt.Phase != TorReady || o.phase != TorPending || o.ctx.Err() != nil || !p.Alive() || !o.now().Before(o.capture.BootstrapDeadline) {
		o.mu.Unlock()
		o.fail()
		return
	}
	// The worker's proof is necessary but not authority to publish Ready.
	// The manager adopts it only after a fresh status read and an exact
	// registry/peer/lease recheck under its lock. No native goroutine needs
	// that global lock to finish or join during Delete/Sweep/Close.
	o.bootstrapped = true
	o.mu.Unlock()
}

func (o *torOwnedProcess) read(p TorProcess, challenge string) (TorReceipt, error) {
	if challenge == "" {
		var err error
		challenge, err = torSecret()
		if err != nil {
			return TorReceipt{}, err
		}
	}
	started := o.now()
	ctx, cancel := context.WithTimeout(o.ctx, torStatusLimit)
	defer cancel()
	receipt, err := p.Snapshot(ctx, challenge)
	if err != nil || ctx.Err() != nil || !p.Alive() || ValidateTorReceipt(receipt, o.capture, challenge, started, o.now()) != nil {
		return TorReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (o *torOwnedProcess) snapshot(ctx context.Context, challenge string) (TorReceipt, error) {
	o.mu.Lock()
	p, phase, front := o.p, o.phase, o.frontReady
	o.mu.Unlock()
	if !front || p == nil || (phase != TorPending && phase != TorReady) || ctx.Err() != nil {
		return TorReceipt{}, ErrUnavailable
	}
	started := o.now()
	readCtx, cancel := context.WithTimeout(ctx, torStatusLimit)
	stop := context.AfterFunc(o.ctx, cancel)
	defer func() { stop(); cancel() }()
	receipt, err := p.Snapshot(readCtx, challenge)
	if err != nil || readCtx.Err() != nil || !p.Alive() || ValidateTorReceipt(receipt, o.capture, challenge, started, o.now()) != nil {
		if ctx.Err() == nil && o.ctx.Err() == nil {
			// A live caller observed a stale, unproved or unresponsive native
			// owner. Retire it; cancelling just this HTTP read does not do so.
			o.fail()
		}
		return TorReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (o *torOwnedProcess) usableLocked() bool {
	if o.drained || !o.frontReady || o.ctx.Err() != nil || o.p == nil || !o.p.Alive() ||
		(o.phase != TorPending && o.phase != TorReady) || o.phase == TorPending && !o.now().Before(o.capture.BootstrapDeadline) {
		return false
	}
	return true
}

func (o *torOwnedProcess) usable() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.usableLocked()
}

func (o *torOwnedProcess) adoptReceipt(receipt TorReceipt) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.usableLocked() {
		return false
	}
	// Called only after the manager has rechecked its source/owner under lock.
	// A worker's early ready response cannot outrun completed bootstrap, and
	// an out-of-order pending read cannot overwrite an adopted Ready state.
	if receipt.Phase == TorReady && o.bootstrapped {
		o.phase = TorReady
		o.bootstrapTimer.Stop()
		return true
	}
	return receipt.Phase == o.phase
}

func (o *torOwnedProcess) terminal() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.phase == TorFailed || o.phase == TorRetired || o.ctx.Err() != nil ||
		o.phase == TorPending && !o.now().Before(o.capture.BootstrapDeadline) || o.p != nil && !o.p.Alive()
}

// Alive retains ownership until a successful joined Stop, including a late
// process returned by a cancelled startup. Failure is not permission to reuse
// the port or delete an unjoined worker's private workspace.
func (o *torOwnedProcess) Alive() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.drained
}

func (o *torOwnedProcess) Stop(ctx context.Context) error {
	// Revocation is immediate even when a caller cancelled its cleanup wait.
	// The port still remains reserved until a later Stop confirms the join.
	o.mu.Lock()
	o.phase = TorRetired
	o.cancel()
	if o.bootstrapTimer != nil {
		o.bootstrapTimer.Stop()
	}
	o.mu.Unlock()
	select {
	case o.stopGate <- struct{}{}:
		defer func() { <-o.stopGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	o.mu.Lock()
	drained := o.drained
	o.mu.Unlock()
	if drained {
		return nil
	}
	select {
	case <-o.started:
	case <-ctx.Done():
		return errors.New("Tor startup has not joined")
	}
	o.mu.Lock()
	p := o.p
	o.mu.Unlock()
	if p != nil {
		if err := p.Stop(ctx); err != nil || p.Alive() {
			return errors.New("Tor child teardown is unverified")
		}
	}
	select {
	case <-o.done:
	case <-ctx.Done():
		return errors.New("Tor bootstrap has not joined")
	}
	o.mu.Lock()
	o.drained = true
	o.mu.Unlock()
	return nil
}

func (m *Manager) validateTorRequest(peer netip.Addr, q TorRequest) error {
	if !peer.IsValid() || peer.Zone() != "" || !peer.IsPrivate() || !nonce.MatchString(q.SessionID) || q.EntryNodeID != m.node ||
		q.Epoch != m.packetEpoch || q.Peer != PeerKey(peer) || q.AcquireExpiresAt <= 0 ||
		!ident.MatchString(q.ExitID) || !torMode(q.ExitMode) || !proofID.MatchString(q.SourceSHA256) || !proofID.MatchString(q.DNSPolicySHA256) {
		return ErrOwnership
	}
	if q.Port != 0 || q.Username != "" || q.Password != "" {
		if q.Port < m.cfg.FirstPort || q.Port > m.cfg.LastPort || !listenerSecret.MatchString(q.Username) || !listenerSecret.MatchString(q.Password) || q.Username == q.Password {
			return ErrOwnership
		}
	}
	return nil
}

// TorChallenge shares the existing manager restart/peer-bound acquisition
// contract. It exposes no private source and is unavailable with the shipping
// runner until a genuine native Tor worker has been integrated.
func (m *Manager) TorChallenge(peer netip.Addr) (ExternalPacketChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.runner.(TorRunner); !ok || m.closed || len(m.cfg.TorExits) == 0 {
		return ExternalPacketChallenge{}, ErrUnavailable
	}
	challenge := ExternalPacketChallenge{Epoch: m.packetEpoch, Peer: PeerKey(peer), ExpiresAt: m.now().Add(packetAcquireLifetime).Unix()}
	if !peer.IsPrivate() || challenge.Validate() != nil {
		return ExternalPacketChallenge{}, ErrOwnership
	}
	return challenge, nil
}

func (m *Manager) torSourceLocked(q TorRequest) (TorExitSource, error) {
	for _, source := range m.cfg.TorExits {
		if source.ID == q.ExitID && source.Mode == q.ExitMode {
			if source.SourceSHA256 != q.SourceSHA256 || source.DNSPolicySHA256 != q.DNSPolicySHA256 {
				return TorExitSource{}, ErrOwnership
			}
			return source, nil
		}
	}
	return TorExitSource{}, ErrUnavailable
}

func torAttemptKey(peer netip.Addr, q TorRequest) string { return PeerKey(peer) + "/" + q.SessionID }

func (m *Manager) rememberTorAttemptLocked(peer netip.Addr, q TorRequest, retire bool) error {
	for key, old := range m.torAttempts {
		if !old.until.After(m.now()) {
			peerKey, _, _ := strings.Cut(key, "/")
			active := m.leases[peerKey]
			if active == nil || active.tor == nil || torAttemptKey(active.peer, active.tor.capture.Request) != key {
				delete(m.torAttempts, key)
			}
		}
	}
	key := torAttemptKey(peer, q)
	if q.AcquireExpiresAt <= m.now().Unix() {
		// A live lease may still renew or be deleted, but this request can no
		// longer acquire anything after its bounded tombstone is discarded.
		return nil
	}
	if q.AcquireExpiresAt > m.now().Add(packetAcquireLifetime).Unix() {
		return ErrOwnership
	}
	if old, exists := m.torAttempts[key]; exists {
		if old.request != q || old.retired && !retire {
			return ErrOwnership
		}
	} else if len(m.torAttempts) >= torAttemptLimit {
		return ErrUnavailable
	}
	m.torAttempts[key] = torAttempt{request: q, retired: retire, until: time.Unix(q.AcquireExpiresAt, 0)}
	return nil
}

func (m *Manager) torLeaseLocked(active *live) TorLease {
	o := active.tor
	o.mu.Lock()
	phase := o.phase
	o.mu.Unlock()
	c := o.capture
	return TorLease{Request: c.Request, NodeID: m.node, OwnerID: c.OwnerID, Host: c.Host, Port: c.Port, Username: c.Username, Password: c.Password,
		RegistrySHA256: c.RegistrySHA256, DNSPolicySHA256: c.Source.DNSPolicySHA256, Phase: phase, ExpiresAt: active.ExpiresAt, BootstrapDeadline: c.BootstrapDeadline}
}

// CreateTor reserves the same per-peer/port inventory as ordinary relays, but
// never holds Manager.mu while starting a Tor worker, bootstrapping a circuit,
// or reading native status. A runner without the explicit capability fails
// before reservation; no entry is advertised through Available().
func (m *Manager) CreateTor(ctx context.Context, peer netip.Addr, q TorRequest) (TorLease, error) {
	if err := ctx.Err(); err != nil {
		return TorLease{}, err
	}
	m.mu.Lock()
	if err := m.validateTorRequest(peer, q); err != nil {
		m.mu.Unlock()
		return TorLease{}, err
	}
	runner, capable := m.runner.(TorRunner)
	if m.closed || !capable {
		m.mu.Unlock()
		return TorLease{}, ErrUnavailable
	}
	source, err := m.torSourceLocked(q)
	if err == nil {
		err = m.reapLocked(ctx)
	}
	if err != nil || ctx.Err() != nil {
		m.mu.Unlock()
		if err != nil {
			return TorLease{}, err
		}
		return TorLease{}, ctx.Err()
	}
	key := PeerKey(peer)
	if active := m.leases[key]; active != nil {
		if active.tor == nil || active.tor.capture.Request != q || active.retired {
			m.mu.Unlock()
			return TorLease{}, ErrBusy
		}
		m.mu.Unlock()
		challenge, err := torSecret()
		if err != nil {
			return TorLease{}, err
		}
		status, err := m.torStatus(ctx, peer, q, challenge, true)
		return status.Lease, err
	}
	if q.AcquireExpiresAt <= m.now().Unix() || q.AcquireExpiresAt > m.now().Add(packetAcquireLifetime).Unix() {
		m.mu.Unlock()
		return TorLease{}, ErrOwnership
	}
	used := map[int]bool{}
	for _, active := range m.leases {
		used[active.Port] = true
	}
	port := q.Port
	if port != 0 && used[port] {
		m.mu.Unlock()
		return TorLease{}, ErrBusy
	}
	for candidate := m.cfg.FirstPort; port == 0 && candidate <= m.cfg.LastPort; candidate++ {
		if !used[candidate] {
			port = candidate
		}
	}
	if port == 0 {
		m.mu.Unlock()
		return TorLease{}, ErrUnavailable
	}
	username, err := secret()
	if err != nil {
		m.mu.Unlock()
		return TorLease{}, err
	}
	password, err := secret()
	if err != nil {
		m.mu.Unlock()
		return TorLease{}, err
	}
	if q.Port != 0 {
		username, password = q.Username, q.Password
	}
	ownerID, err := torSecret()
	if err != nil {
		m.mu.Unlock()
		return TorLease{}, err
	}
	if err := m.rememberTorAttemptLocked(peer, q, false); err != nil {
		m.mu.Unlock()
		return TorLease{}, err
	}
	capture := TorCapture{Schema: 1, Request: q, Source: source, RegistrySHA256: source.registrySHA256(m.node), OwnerID: ownerID, Peer: key,
		Host: m.cfg.ListenIP, Port: port, Username: username, Password: password, BootstrapDeadline: m.now().Add(TorBootstrapLimit)}
	owner := newTorOwnedProcess(capture, runner, m.now)
	active := &live{Lease: Lease{Request: q.request(), NodeID: m.node, Host: capture.Host, Port: port, Username: username, Password: password,
		ExpiresAt: m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)}, peer: peer, p: owner, tor: owner}
	m.leases[key] = active
	owner.launch()
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		_ = m.DeleteTor(context.Background(), peer, q)
		return TorLease{}, ctx.Err()
	case <-owner.started:
	}
	m.mu.Lock()
	current, sourceErr := m.torSourceLocked(q)
	valid := ctx.Err() == nil && !m.closed && m.leases[key] == active && !active.retired && active.ExpiresAt.After(m.now()) && sourceErr == nil && current == source && owner.usable()
	var lease TorLease
	if valid {
		lease = m.torLeaseLocked(active)
	}
	m.mu.Unlock()
	if !valid {
		_ = m.DeleteTor(context.Background(), peer, q)
		return TorLease{}, ErrUnavailable
	}
	return lease, nil
}

func (m *Manager) TorStatus(ctx context.Context, peer netip.Addr, q TorRequest, challenge string) (TorLeaseStatus, error) {
	return m.torStatus(ctx, peer, q, challenge, false)
}

func (m *Manager) torStatus(ctx context.Context, peer netip.Addr, q TorRequest, challenge string, renew bool) (TorLeaseStatus, error) {
	if ctx.Err() != nil || !proofID.MatchString(challenge) {
		return TorLeaseStatus{}, ErrOwnership
	}
	m.mu.Lock()
	if _, capable := m.runner.(TorRunner); !capable {
		m.mu.Unlock()
		return TorLeaseStatus{}, ErrUnavailable
	}
	if err := m.validateTorRequest(peer, q); err != nil {
		m.mu.Unlock()
		return TorLeaseStatus{}, err
	}
	active := m.leases[PeerKey(peer)]
	source, sourceErr := m.torSourceLocked(q)
	if active != nil && active.tor != nil && active.tor.capture.Request == q && (sourceErr != nil || active.tor.capture.Source != source) {
		active.tor.fail()
	}
	if m.closed || active == nil || active.tor == nil || active.tor.capture.Request != q || active.retired || !active.ExpiresAt.After(m.now()) || sourceErr != nil || active.tor.capture.Source != source {
		m.mu.Unlock()
		return TorLeaseStatus{}, ErrOwnership
	}
	owner := active.tor
	m.mu.Unlock()
	// The only native IPC read is outside the global lease lock. A delayed
	// response cannot stop another peer from creating, renewing or deleting.
	receipt, err := owner.snapshot(ctx, challenge)
	if err != nil {
		return TorLeaseStatus{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, sourceErr := m.torSourceLocked(q)
	if m.leases[PeerKey(peer)] == active && (sourceErr != nil || current != source) {
		owner.fail()
	}
	if ctx.Err() != nil || m.closed || m.leases[PeerKey(peer)] != active || active.retired || !active.ExpiresAt.After(m.now()) || sourceErr != nil || current != source ||
		ValidateTorReceipt(receipt, owner.capture, challenge, time.UnixMilli(receipt.HeartbeatAt), m.now()) != nil || !owner.adoptReceipt(receipt) {
		return TorLeaseStatus{}, ErrOwnership
	}
	if renew {
		active.ExpiresAt = m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)
	}
	return TorLeaseStatus{Lease: m.torLeaseLocked(active), Receipt: receipt}, nil
}

func (m *Manager) DeleteTor(ctx context.Context, peer netip.Addr, q TorRequest) error {
	m.mu.Lock()
	if _, capable := m.runner.(TorRunner); !capable {
		m.mu.Unlock()
		return ErrUnavailable
	}
	if err := m.validateTorRequest(peer, q); err != nil {
		m.mu.Unlock()
		return err
	}
	key := PeerKey(peer)
	active := m.leases[key]
	if active != nil && (active.tor == nil || active.tor.capture.Request != q) {
		m.mu.Unlock()
		return ErrOwnership
	}
	// A DELETE that overtakes PUT retires this exact attempt as well. The
	// bounded tombstone does not require the registry still to contain it.
	if err := m.rememberTorAttemptLocked(peer, q, true); err != nil {
		m.mu.Unlock()
		return err
	}
	if active == nil {
		m.mu.Unlock()
		return nil
	}
	active.retired = true
	owner := active.tor
	m.mu.Unlock()
	stopCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := owner.Stop(stopCtx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil || owner.Alive() {
		return errors.New("Tor teardown unverified; owned lease retained")
	}
	if m.leases[key] == active {
		delete(m.leases, key)
	}
	return nil
}
