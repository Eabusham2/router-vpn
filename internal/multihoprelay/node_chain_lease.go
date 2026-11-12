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
	NodeChainBootstrapLimit = 90 * time.Second
	nodeChainStartLimit     = 8 * time.Second
	nodeChainStatusLimit    = time.Second
	nodeChainAttemptLimit   = 1024
	// Discovery carries up to 64 public descriptors with seven suffix rows.
	// It is separate from the unchanged bounded mutation and IPC bodies.
	MaxNodeChainCapabilitiesBytes = 512 << 10
)

// NodeChainRunner is an explicit native capability, not a fallback to Runner.Start.
// StartChain resolves the exact private source, binds the authenticated private
// front with forwarding disabled, and returns promptly. It must not bootstrap
// a path or retain the HTTP request context. Its context belongs to the lease and
// remains live after successful startup, until retirement or native failure.
// The native runner supplies an isolated worker and authenticated control
// channel; the ordinary Runner.Start cannot substitute for this capability.
type NodeChainRunner interface {
	StartChain(context.Context, NodeChainCapture) (NodeChainProcess, error)
}

// NodeChainProcess owns the native front, ordered engine and control channel.
// Bootstrap must keep application forwarding closed until every suffix node,
// selected DNS and final public route is proved. Snapshot answers a fresh nonce through its
// authenticated native owner channel, not read an arbitrary caller path.
// Stop must join every owned child and listener; a failure retains the lease.
type NodeChainProcess interface {
	Process
	Bootstrap(context.Context) error
	Snapshot(context.Context, string) (NodeChainReceipt, error)
}

type nodeChainAttempt struct {
	request NodeChainRequest
	until   time.Time
	retired bool
}

type nodeChainOwnedProcess struct {
	mu             sync.Mutex
	capture        NodeChainCapture
	runner         NodeChainRunner
	now            func() time.Time
	ctx            context.Context
	cancel         context.CancelFunc
	started        chan struct{}
	done           chan struct{}
	startOnce      sync.Once
	stopGate       chan struct{}
	p              NodeChainProcess
	phase          NodeChainPhase
	frontReady     bool
	bootstrapped   bool
	drained        bool
	bootstrapTimer *time.Timer
	sequence       uint64
}

func nodeChainSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("NodeChain owner identity could not be generated")
	}
	return hex.EncodeToString(raw[:]), nil
}

func newNodeChainOwnedProcess(capture NodeChainCapture, runner NodeChainRunner, now func() time.Time) *nodeChainOwnedProcess {
	ctx, cancel := context.WithCancel(context.Background())
	return &nodeChainOwnedProcess{capture: capture.Clone(), runner: runner, now: now, ctx: ctx, cancel: cancel,
		started: make(chan struct{}), done: make(chan struct{}), stopGate: make(chan struct{}, 1), phase: NodeChainPending}
}

func (o *nodeChainOwnedProcess) launch() {
	o.mu.Lock()
	o.bootstrapTimer = time.AfterFunc(time.Until(o.capture.BootstrapDeadline), func() { o.expire(o.capture.BootstrapDeadline, false) })
	o.mu.Unlock()
	go o.run()
}

func (o *nodeChainOwnedProcess) signalStarted() { o.startOnce.Do(func() { close(o.started) }) }

func (o *nodeChainOwnedProcess) expire(deadline time.Time, startup bool) {
	o.mu.Lock()
	if o.phase != NodeChainPending || startup && o.frontReady || o.now().Before(deadline) {
		o.mu.Unlock()
		return
	}
	o.phase = NodeChainFailed
	o.cancel()
	o.mu.Unlock()
	go o.cleanup()
}

func (o *nodeChainOwnedProcess) fail() {
	o.mu.Lock()
	if o.phase == NodeChainRetired || o.phase == NodeChainFailed {
		o.mu.Unlock()
		return
	}
	o.phase = NodeChainFailed
	o.cancel()
	o.mu.Unlock()
	go o.cleanup()
}

func (o *nodeChainOwnedProcess) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = o.Stop(ctx)
}

func (o *nodeChainOwnedProcess) run() {
	defer func() {
		o.signalStarted()
		close(o.done)
		o.mu.Lock()
		failed := o.phase == NodeChainFailed || o.phase == NodeChainRetired || o.ctx.Err() != nil
		o.mu.Unlock()
		// A late StartChain result is still ours, even if an earlier bounded Stop
		// could not join it. Retry cleanup after that result is captured.
		if failed {
			go o.cleanup()
		}
	}()
	startupDeadline := o.now().Add(nodeChainStartLimit)
	startupTimer := time.AfterFunc(nodeChainStartLimit, func() { o.expire(startupDeadline, true) })
	defer startupTimer.Stop()
	p, err := o.runner.StartChain(o.ctx, o.capture.Clone())
	o.mu.Lock()
	o.p = p
	o.mu.Unlock()
	if err != nil || p == nil || !p.Alive() || o.ctx.Err() != nil || !o.now().Before(startupDeadline) {
		o.fail()
		return
	}
	receipt, err := o.read(p, "")
	if err != nil || receipt.Phase != NodeChainPending {
		o.fail()
		return
	}
	o.mu.Lock()
	if o.phase != NodeChainPending || o.ctx.Err() != nil || !o.now().Before(startupDeadline) {
		o.mu.Unlock()
		o.fail()
		return
	}
	o.frontReady = true
	o.mu.Unlock()
	startupTimer.Stop()
	o.signalStarted()

	// This call is outside Manager.mu and its context is owned by the lease.
	// Successful bootstrap does not cancel the context that owns native sockets.
	if err := p.Bootstrap(o.ctx); err != nil {
		o.fail()
		return
	}
	receipt, err = o.read(p, "")
	o.mu.Lock()
	if err != nil || receipt.Phase != NodeChainReady || o.phase != NodeChainPending || o.ctx.Err() != nil || !p.Alive() || !o.now().Before(o.capture.BootstrapDeadline) {
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

func (o *nodeChainOwnedProcess) read(p NodeChainProcess, challenge string) (NodeChainReceipt, error) {
	if challenge == "" {
		var err error
		challenge, err = nodeChainSecret()
		if err != nil {
			return NodeChainReceipt{}, err
		}
	}
	started := o.now()
	ctx, cancel := context.WithTimeout(o.ctx, nodeChainStatusLimit)
	defer cancel()
	receipt, err := p.Snapshot(ctx, challenge)
	receipt = receipt.Clone()
	if err != nil || ctx.Err() != nil || !p.Alive() || ValidateNodeChainReceipt(receipt, o.capture, challenge, started, o.now()) != nil {
		return NodeChainReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (o *nodeChainOwnedProcess) snapshot(ctx context.Context, challenge string) (NodeChainReceipt, error) {
	o.mu.Lock()
	p, phase, front := o.p, o.phase, o.frontReady
	o.mu.Unlock()
	if !front || p == nil || (phase != NodeChainPending && phase != NodeChainReady) || ctx.Err() != nil {
		return NodeChainReceipt{}, ErrUnavailable
	}
	started := o.now()
	readCtx, cancel := context.WithTimeout(ctx, nodeChainStatusLimit)
	stop := context.AfterFunc(o.ctx, cancel)
	defer func() { stop(); cancel() }()
	receipt, err := p.Snapshot(readCtx, challenge)
	receipt = receipt.Clone()
	if err != nil || readCtx.Err() != nil || !p.Alive() || ValidateNodeChainReceipt(receipt, o.capture, challenge, started, o.now()) != nil {
		if ctx.Err() == nil && o.ctx.Err() == nil {
			// A live caller observed a stale, unproved or unresponsive native
			// owner. Retire it; cancelling just this HTTP read does not do so.
			o.fail()
		}
		return NodeChainReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (o *nodeChainOwnedProcess) usableLocked() bool {
	if o.drained || !o.frontReady || o.ctx.Err() != nil || o.p == nil || !o.p.Alive() ||
		(o.phase != NodeChainPending && o.phase != NodeChainReady) || o.phase == NodeChainPending && !o.now().Before(o.capture.BootstrapDeadline) {
		return false
	}
	return true
}

func (o *nodeChainOwnedProcess) usable() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.usableLocked()
}

func (o *nodeChainOwnedProcess) adoptReceipt(receipt NodeChainReceipt) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.usableLocked() || receipt.Sequence <= o.sequence {
		return false
	}
	// Called only after the manager has rechecked its source/owner under lock.
	// A worker's early ready response cannot outrun completed bootstrap, and
	// an out-of-order pending read cannot overwrite an adopted Ready state.
	if receipt.Phase == NodeChainReady && o.bootstrapped {
		o.phase = NodeChainReady
		o.sequence = receipt.Sequence
		o.bootstrapTimer.Stop()
		return true
	}
	if receipt.Phase != o.phase {
		return false
	}
	o.sequence = receipt.Sequence
	return true
}

func (o *nodeChainOwnedProcess) terminal() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.phase == NodeChainFailed || o.phase == NodeChainRetired || o.ctx.Err() != nil ||
		o.phase == NodeChainPending && !o.now().Before(o.capture.BootstrapDeadline) || o.p != nil && !o.p.Alive()
}

// Alive retains ownership until a successful joined Stop, including a late
// process returned by a cancelled startup. Failure is not permission to reuse
// the port or delete an unjoined worker's private workspace.
func (o *nodeChainOwnedProcess) Alive() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.drained
}

func (o *nodeChainOwnedProcess) Stop(ctx context.Context) error {
	// Revocation is immediate even when a caller cancelled its cleanup wait.
	// The port still remains reserved until a later Stop confirms the join.
	o.mu.Lock()
	o.phase = NodeChainRetired
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
		return errors.New("NodeChain startup has not joined")
	}
	o.mu.Lock()
	p := o.p
	o.mu.Unlock()
	if p != nil {
		if err := p.Stop(ctx); err != nil || p.Alive() {
			return errors.New("NodeChain child teardown is unverified")
		}
	}
	select {
	case <-o.done:
	case <-ctx.Done():
		return errors.New("NodeChain bootstrap has not joined")
	}
	o.mu.Lock()
	o.drained = true
	o.mu.Unlock()
	return nil
}

func sameNodeChainRequest(a, b NodeChainRequest) bool {
	x, err := a.Digest()
	if err != nil {
		return false
	}
	y, err := b.Digest()
	return err == nil && x == y
}

func sameNodeChainSource(a, b NodeChainDescriptor) bool {
	x, err := a.Digest()
	if err != nil {
		return false
	}
	y, err := b.Digest()
	return err == nil && x == y
}

func (m *Manager) validateChainRequest(peer netip.Addr, q NodeChainRequest) error {
	if peer.Zone() != "" || !nodeChainPrivateAddress(PeerKey(peer)) || q.validateShape() != nil || q.EntryNodeID != m.node ||
		q.Epoch != m.packetEpoch || q.Peer != PeerKey(peer) || q.Port < m.cfg.FirstPort || q.Port > m.cfg.LastPort {
		return ErrOwnership
	}
	return nil
}

// ChainAvailable captures public descriptors and the actual caller challenge in
// one registry read. References alone never advertise a runtime capability.
func (m *Manager) ChainAvailable(peer netip.Addr) (ExternalPacketChallenge, []NodeChainDescriptor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, capable := m.runner.(NodeChainRunner); !capable || m.closed || len(m.cfg.NodeChains) == 0 {
		return ExternalPacketChallenge{}, nil, ErrUnavailable
	}
	challenge := ExternalPacketChallenge{Epoch: m.packetEpoch, Peer: PeerKey(peer), ExpiresAt: m.now().Add(packetAcquireLifetime).Unix()}
	if peer.Zone() != "" || !nodeChainPrivateAddress(challenge.Peer) || challenge.Validate() != nil {
		return ExternalPacketChallenge{}, nil, ErrOwnership
	}
	sources := make([]NodeChainDescriptor, len(m.cfg.NodeChains))
	for i, source := range m.cfg.NodeChains {
		sources[i] = source.Clone()
	}
	return challenge, sources, nil
}

// ChainPortRange exposes only the immutable configured proposal range to the
// authenticated caller. It reserves nothing and never changes a PUT's port.
func (m *Manager) ChainPortRange(peer netip.Addr) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, capable := m.runner.(NodeChainRunner); !capable || m.closed || len(m.cfg.NodeChains) == 0 {
		return 0, 0, ErrUnavailable
	}
	if peer.Zone() != "" || !nodeChainPrivateAddress(PeerKey(peer)) {
		return 0, 0, ErrOwnership
	}
	return m.cfg.FirstPort, m.cfg.LastPort, nil
}

func (m *Manager) chainSourceLocked(q NodeChainRequest) (NodeChainDescriptor, error) {
	for _, source := range m.cfg.NodeChains {
		if source.SourceSHA256 == q.SourceSHA256 {
			if q.Validate(source) != nil {
				return NodeChainDescriptor{}, ErrOwnership
			}
			return source.Clone(), nil
		}
	}
	return NodeChainDescriptor{}, ErrUnavailable
}

func nodeChainAttemptKey(peer netip.Addr, q NodeChainRequest) string {
	return PeerKey(peer) + "/" + q.SessionID
}

func (m *Manager) rememberChainAttemptLocked(peer netip.Addr, q NodeChainRequest, retire bool) error {
	for key, old := range m.chainAttempts {
		if !old.until.After(m.now()) {
			peerKey, _, _ := strings.Cut(key, "/")
			active := m.leases[peerKey]
			if active == nil || active.chain == nil || nodeChainAttemptKey(active.peer, active.chain.capture.Request) != key {
				delete(m.chainAttempts, key)
			}
		}
	}
	if q.AcquireExpiresAt <= m.now().Unix() {
		// Existing ownership may renew or retire after acquisition expires.
		// An expired request cannot start a new worker even without a tombstone.
		return nil
	}
	if q.AcquireExpiresAt > m.now().Add(packetAcquireLifetime).Unix() {
		return ErrOwnership
	}
	key := nodeChainAttemptKey(peer, q)
	if old, exists := m.chainAttempts[key]; exists {
		if !sameNodeChainRequest(old.request, q) || old.retired && !retire {
			return ErrOwnership
		}
	} else if len(m.chainAttempts) >= nodeChainAttemptLimit {
		return ErrUnavailable
	}
	m.chainAttempts[key] = nodeChainAttempt{request: q.Clone(), retired: retire, until: time.Unix(q.AcquireExpiresAt, 0)}
	return nil
}

// Packet identities are captured when a process is created, including partial
// starts and failed teardown. Never recompute an old owner's key from today's
// registry. A chain also pins its client's independent local packet identities.
func (m *Manager) validatePacketPinsLocked(pins []string) error {
	for _, active := range m.leases {
		for _, proposed := range pins {
			for _, captured := range active.packetPins {
				if proposed == captured {
					return errors.New("paired packet credentials already belong to an original relay owner")
				}
			}
			if active.chain != nil {
				for _, captured := range active.chain.capture.Request.LocalPacketPublicKeys {
					if proposed == captured {
						return errors.New("paired packet credentials already belong to an original local path")
					}
				}
			}
		}
	}
	return nil
}

func (m *Manager) chainLeaseLocked(active *live) NodeChainLease {
	o := active.chain
	o.mu.Lock()
	phase := o.phase
	o.mu.Unlock()
	c := o.capture
	return NodeChainLease{Request: c.Request.Clone(), NodeID: m.node, OwnerID: c.OwnerID, Host: c.Host, Port: c.Request.Port,
		Users: append([]NodeChainUser(nil), c.Request.Users...), RegistrySHA256: c.RegistrySHA256, DNSPolicySHA256: c.Source.DNSPolicySHA256,
		Phase: phase, ExpiresAt: active.ExpiresAt, BootstrapDeadline: c.BootstrapDeadline}
}

// CreateChain reserves the ordinary per-peer and port inventory before native
// startup. The original worker starts and bootstraps outside Manager.mu. It
// never falls back to an ordinary relay or modifies any global route.
func (m *Manager) CreateChain(ctx context.Context, peer netip.Addr, request NodeChainRequest) (NodeChainLease, error) {
	if err := ctx.Err(); err != nil {
		return NodeChainLease{}, err
	}
	q := request.Clone()
	m.mu.Lock()
	if err := m.validateChainRequest(peer, q); err != nil {
		m.mu.Unlock()
		return NodeChainLease{}, err
	}
	runner, capable := m.runner.(NodeChainRunner)
	if m.closed || !capable {
		m.mu.Unlock()
		return NodeChainLease{}, ErrUnavailable
	}
	source, err := m.chainSourceLocked(q)
	if err == nil {
		err = m.reapLocked(ctx)
	}
	if err != nil || ctx.Err() != nil {
		m.mu.Unlock()
		if err != nil {
			return NodeChainLease{}, err
		}
		return NodeChainLease{}, ctx.Err()
	}
	key := PeerKey(peer)
	if active := m.leases[key]; active != nil {
		if active.chain == nil || !sameNodeChainRequest(active.chain.capture.Request, q) || active.retired {
			m.mu.Unlock()
			return NodeChainLease{}, ErrBusy
		}
		m.mu.Unlock()
		challenge, err := nodeChainSecret()
		if err != nil {
			return NodeChainLease{}, err
		}
		status, err := m.chainStatus(ctx, peer, q, challenge, true)
		return status.Lease, err
	}
	if q.AcquireExpiresAt <= m.now().Unix() || q.AcquireExpiresAt > m.now().Add(packetAcquireLifetime).Unix() {
		m.mu.Unlock()
		return NodeChainLease{}, ErrOwnership
	}
	var packetPins []string
	for _, member := range source.Members {
		if member.ClientPublicKey != "" {
			packetPins = append(packetPins, member.ClientPublicKey)
		}
	}
	if err := m.validatePacketPinsLocked(append(append([]string(nil), packetPins...), q.LocalPacketPublicKeys...)); err != nil {
		m.mu.Unlock()
		return NodeChainLease{}, err
	}
	for _, active := range m.leases {
		if active.Port == q.Port {
			m.mu.Unlock()
			return NodeChainLease{}, ErrBusy
		}
	}
	ownerID, err := nodeChainSecret()
	if err != nil {
		m.mu.Unlock()
		return NodeChainLease{}, err
	}
	capture := NodeChainCapture{Schema: 1, Request: q.Clone(), Source: source.Clone(), RegistrySHA256: q.DescriptorSHA256,
		OwnerID: ownerID, Peer: key, Host: m.cfg.ListenIP, BootstrapDeadline: m.now().Add(NodeChainBootstrapLimit).UTC()}
	if capture.Validate() != nil {
		m.mu.Unlock()
		return NodeChainLease{}, ErrOwnership
	}
	if err := m.rememberChainAttemptLocked(peer, q, false); err != nil {
		m.mu.Unlock()
		return NodeChainLease{}, err
	}
	owner := newNodeChainOwnedProcess(capture, runner, m.now)
	active := &live{Lease: Lease{Request: Request{SessionID: q.SessionID, EntryNodeID: q.EntryNodeID, ExitID: q.SourceSHA256, ExitMode: "node-chain"},
		NodeID: m.node, Host: capture.Host, Port: q.Port, ExpiresAt: m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)},
		peer: peer, p: owner, chain: owner, packetPins: packetPins}
	m.leases[key] = active
	owner.launch()
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		_ = m.DeleteChain(context.Background(), peer, q)
		return NodeChainLease{}, ctx.Err()
	case <-owner.ctx.Done():
		// The original startup deadline also bounds this HTTP acquisition,
		// even if a native runner ignores cancellation. Its failed owner and
		// reservation remain captured until cleanup joins the late result.
		go func() { _ = m.DeleteChain(context.Background(), peer, q) }()
		return NodeChainLease{}, ErrUnavailable
	case <-owner.started:
	}
	m.mu.Lock()
	current, sourceErr := m.chainSourceLocked(q)
	valid := ctx.Err() == nil && !m.closed && m.leases[key] == active && !active.retired && active.ExpiresAt.After(m.now()) &&
		sourceErr == nil && sameNodeChainSource(current, source) && owner.usable()
	var lease NodeChainLease
	if valid {
		lease = m.chainLeaseLocked(active)
	}
	m.mu.Unlock()
	if !valid {
		_ = m.DeleteChain(context.Background(), peer, q)
		return NodeChainLease{}, ErrUnavailable
	}
	return lease, nil
}

func (m *Manager) ChainStatus(ctx context.Context, peer netip.Addr, q NodeChainRequest, challenge string) (NodeChainLeaseStatus, error) {
	return m.chainStatus(ctx, peer, q.Clone(), challenge, false)
}

func (m *Manager) chainStatus(ctx context.Context, peer netip.Addr, q NodeChainRequest, challenge string, renew bool) (NodeChainLeaseStatus, error) {
	if ctx.Err() != nil || !proofID.MatchString(challenge) {
		return NodeChainLeaseStatus{}, ErrOwnership
	}
	m.mu.Lock()
	if _, capable := m.runner.(NodeChainRunner); !capable {
		m.mu.Unlock()
		return NodeChainLeaseStatus{}, ErrUnavailable
	}
	if err := m.validateChainRequest(peer, q); err != nil {
		m.mu.Unlock()
		return NodeChainLeaseStatus{}, err
	}
	active := m.leases[PeerKey(peer)]
	source, sourceErr := m.chainSourceLocked(q)
	if active != nil && active.chain != nil && sameNodeChainRequest(active.chain.capture.Request, q) &&
		(sourceErr != nil || !sameNodeChainSource(active.chain.capture.Source, source)) {
		active.chain.fail()
	}
	if m.closed || active == nil || active.chain == nil || !sameNodeChainRequest(active.chain.capture.Request, q) || active.retired ||
		!active.ExpiresAt.After(m.now()) || sourceErr != nil || !sameNodeChainSource(active.chain.capture.Source, source) {
		m.mu.Unlock()
		return NodeChainLeaseStatus{}, ErrOwnership
	}
	owner := active.chain
	m.mu.Unlock()
	// A delayed native reply cannot block another peer's inventory operations.
	receipt, err := owner.snapshot(ctx, challenge)
	if err != nil {
		return NodeChainLeaseStatus{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, sourceErr := m.chainSourceLocked(q)
	if m.leases[PeerKey(peer)] == active && (sourceErr != nil || !sameNodeChainSource(current, source)) {
		owner.fail()
	}
	if ctx.Err() != nil || m.closed || m.leases[PeerKey(peer)] != active || active.retired || !active.ExpiresAt.After(m.now()) ||
		sourceErr != nil || !sameNodeChainSource(current, source) ||
		ValidateNodeChainReceipt(receipt, owner.capture, challenge, time.UnixMilli(receipt.HeartbeatAt), m.now()) != nil || !owner.adoptReceipt(receipt) {
		return NodeChainLeaseStatus{}, ErrOwnership
	}
	if renew {
		active.ExpiresAt = m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)
	}
	return NodeChainLeaseStatus{Lease: m.chainLeaseLocked(active), Receipt: receipt.Clone()}, nil
}

func (m *Manager) DeleteChain(ctx context.Context, peer netip.Addr, request NodeChainRequest) error {
	q := request.Clone()
	m.mu.Lock()
	if _, capable := m.runner.(NodeChainRunner); !capable {
		m.mu.Unlock()
		return ErrUnavailable
	}
	if err := m.validateChainRequest(peer, q); err != nil {
		m.mu.Unlock()
		return err
	}
	key := PeerKey(peer)
	active := m.leases[key]
	if active != nil && (active.chain == nil || !sameNodeChainRequest(active.chain.capture.Request, q)) {
		m.mu.Unlock()
		return ErrOwnership
	}
	// A DELETE which overtakes its PUT retires exactly that captured attempt.
	// Registry removal must not prevent retirement of an existing owner.
	if err := m.rememberChainAttemptLocked(peer, q, true); err != nil {
		m.mu.Unlock()
		return err
	}
	if active == nil {
		m.mu.Unlock()
		return nil
	}
	active.retired = true
	owner := active.chain
	m.mu.Unlock()
	stopCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := owner.Stop(stopCtx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil || owner.Alive() {
		return errors.New("ordered native teardown unverified; owned lease retained")
	}
	if m.leases[key] == active {
		delete(m.leases, key)
	}
	return nil
}
