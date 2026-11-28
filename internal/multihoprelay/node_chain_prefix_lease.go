package multihoprelay

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	NodeChainPrefixBootstrapLimit = 90 * time.Second
	nodeChainPrefixStartLimit     = 8 * time.Second
	nodeChainPrefixStatusLimit    = time.Second
	nodeChainPrefixAttemptLimit   = 1024
)

// NodeChainPrefixRunner is an explicit native capability, not a fallback to Runner.Start.
// StartPrefix resolves the exact private source, binds the authenticated private
// front with forwarding disabled, and returns promptly. It must not bootstrap
// a path or retain the HTTP request context. Its context belongs to the lease and
// remains live after successful startup, until retirement or native failure.
// The native runner supplies an isolated worker and authenticated control
// channel; the ordinary Runner.Start cannot substitute for this capability.
type NodeChainPrefixRunner interface {
	StartPrefix(context.Context, NodeChainPrefixCapture) (NodeChainPrefixProcess, error)
}

// NodeChainPrefixProcess owns the native front, ordered engine and control channel.
// PreparePrefix proves only the actual independently provisioned suffix.
// Application forwarding and DNS stay closed, including the genuine zero suffix. Snapshot answers a fresh nonce through its
// authenticated native owner channel, not read an arbitrary caller path.
// Stop must join every owned child and listener; a failure retains the lease.
type NodeChainPrefixProcess interface {
	Process
	PreparePrefix(context.Context) error
	SnapshotPrefix(context.Context, string) (NodeChainPrefixExecutionReceipt, error)
}

type nodeChainPrefixAttempt struct {
	request NodeChainPrefixRequest
	until   time.Time
	retired bool
}

type nodeChainPrefixOwnedProcess struct {
	mu                sync.Mutex
	capture           NodeChainPrefixCapture
	runner            NodeChainPrefixRunner
	now               func() time.Time
	ctx               context.Context
	cancel            context.CancelFunc
	started           chan struct{}
	done              chan struct{}
	startOnce         sync.Once
	stopGate          chan struct{}
	p                 NodeChainPrefixProcess
	phase             NodeChainPrefixPhase
	frontReady        bool
	bootstrapped      bool
	drained           bool
	bootstrapTimer    *time.Timer
	sequence          uint64
	candidate         *nodeChainPrefixCandidateOwned
	candidateAttempts map[string]NodeChainPrefixCandidateRequest
}

func newNodeChainPrefixOwnedProcess(capture NodeChainPrefixCapture, runner NodeChainPrefixRunner, now func() time.Time) *nodeChainPrefixOwnedProcess {
	ctx, cancel := context.WithCancel(context.Background())
	return &nodeChainPrefixOwnedProcess{capture: capture.Clone(), runner: runner, now: now, ctx: ctx, cancel: cancel,
		started: make(chan struct{}), done: make(chan struct{}), stopGate: make(chan struct{}, 1), phase: NodeChainPrefixPending}
}

func (o *nodeChainPrefixOwnedProcess) launch() {
	o.mu.Lock()
	o.bootstrapTimer = time.AfterFunc(time.Until(o.capture.BootstrapDeadline), func() { o.expire(o.capture.BootstrapDeadline, false) })
	o.mu.Unlock()
	go o.run()
}

func (o *nodeChainPrefixOwnedProcess) signalStarted() { o.startOnce.Do(func() { close(o.started) }) }

func (o *nodeChainPrefixOwnedProcess) expire(deadline time.Time, startup bool) {
	o.mu.Lock()
	if o.phase != NodeChainPrefixPending || startup && o.frontReady || o.now().Before(deadline) {
		o.mu.Unlock()
		return
	}
	o.phase = NodeChainPrefixFailed
	o.cancel()
	o.mu.Unlock()
	go o.cleanup()
}

func (o *nodeChainPrefixOwnedProcess) fail() {
	o.mu.Lock()
	if o.phase == NodeChainPrefixRetired || o.phase == NodeChainPrefixFailed {
		o.mu.Unlock()
		return
	}
	o.phase = NodeChainPrefixFailed
	o.cancel()
	o.mu.Unlock()
	go o.cleanup()
}

func (o *nodeChainPrefixOwnedProcess) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = o.Stop(ctx)
}

func (o *nodeChainPrefixOwnedProcess) run() {
	defer func() {
		o.signalStarted()
		close(o.done)
		o.mu.Lock()
		failed := o.phase == NodeChainPrefixFailed || o.phase == NodeChainPrefixRetired || o.ctx.Err() != nil
		o.mu.Unlock()
		// A late StartPrefix result is still ours, even if an earlier bounded Stop
		// could not join it. Retry cleanup after that result is captured.
		if failed {
			go o.cleanup()
		}
	}()
	startupDeadline := o.now().Add(nodeChainPrefixStartLimit)
	startupTimer := time.AfterFunc(nodeChainPrefixStartLimit, func() { o.expire(startupDeadline, true) })
	defer startupTimer.Stop()
	p, err := o.runner.StartPrefix(o.ctx, o.capture.Clone())
	o.mu.Lock()
	o.p = p
	o.mu.Unlock()
	if err != nil || p == nil || !p.Alive() || o.ctx.Err() != nil || !o.now().Before(startupDeadline) {
		o.fail()
		return
	}
	receipt, err := o.read(p, "")
	if err != nil || receipt.Phase != NodeChainPrefixPending {
		o.fail()
		return
	}
	o.mu.Lock()
	if o.phase != NodeChainPrefixPending || o.ctx.Err() != nil || !o.now().Before(startupDeadline) {
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
	if err := p.PreparePrefix(o.ctx); err != nil {
		o.fail()
		return
	}
	receipt, err = o.read(p, "")
	o.mu.Lock()
	if err != nil || receipt.Phase != NodeChainPrefixPrepared || o.phase != NodeChainPrefixPending || o.ctx.Err() != nil || !p.Alive() || !o.now().Before(o.capture.BootstrapDeadline) {
		o.mu.Unlock()
		o.fail()
		return
	}
	// The worker's proof is necessary but not authority to publish Prepared.
	// The manager adopts it only after a fresh status read and an exact
	// registry/peer/lease recheck under its lock. No native goroutine needs
	// that global lock to finish or join during Delete/Sweep/Close.
	o.bootstrapped = true
	o.mu.Unlock()
}

func (o *nodeChainPrefixOwnedProcess) read(p NodeChainPrefixProcess, challenge string) (NodeChainPrefixExecutionReceipt, error) {
	if challenge == "" {
		var err error
		challenge, err = nodeChainSecret()
		if err != nil {
			return NodeChainPrefixExecutionReceipt{}, err
		}
	}
	started := o.now()
	ctx, cancel := context.WithTimeout(o.ctx, nodeChainPrefixStatusLimit)
	defer cancel()
	receipt, err := p.SnapshotPrefix(ctx, challenge)
	receipt = receipt.Clone()
	if err != nil || ctx.Err() != nil || !p.Alive() || ValidateNodeChainPrefixExecutionReceipt(receipt, o.capture, challenge, started, o.now()) != nil {
		return NodeChainPrefixExecutionReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (o *nodeChainPrefixOwnedProcess) snapshot(ctx context.Context, challenge string) (NodeChainPrefixExecutionReceipt, error) {
	o.mu.Lock()
	p, phase, front := o.p, o.phase, o.frontReady
	o.mu.Unlock()
	if !front || p == nil || (phase != NodeChainPrefixPending && phase != NodeChainPrefixPrepared) || ctx.Err() != nil {
		return NodeChainPrefixExecutionReceipt{}, ErrUnavailable
	}
	started := o.now()
	readCtx, cancel := context.WithTimeout(ctx, nodeChainPrefixStatusLimit)
	stop := context.AfterFunc(o.ctx, cancel)
	defer func() { stop(); cancel() }()
	receipt, err := p.SnapshotPrefix(readCtx, challenge)
	receipt = receipt.Clone()
	if err != nil || readCtx.Err() != nil || !p.Alive() || ValidateNodeChainPrefixExecutionReceipt(receipt, o.capture, challenge, started, o.now()) != nil {
		if ctx.Err() == nil && o.ctx.Err() == nil {
			// A live caller observed a stale, unproved or unresponsive native
			// owner. Retire it; cancelling just this HTTP read does not do so.
			o.fail()
		}
		return NodeChainPrefixExecutionReceipt{}, ErrUnavailable
	}
	if receipt.Phase == NodeChainPrefixPrepared {
		// A challenged native status can observe Prepared while run is still
		// verifying the same worker's independent post-bootstrap receipt.
		// Keep the caller's nonce and original read deadline. Manager adoption
		// still checks the current registry, lease, sequence and bootstrapped
		// owner under lock, after both observations have finished.
		select {
		case <-o.done:
		case <-readCtx.Done():
			return NodeChainPrefixExecutionReceipt{}, ErrUnavailable
		}
		if readCtx.Err() != nil || o.ctx.Err() != nil {
			return NodeChainPrefixExecutionReceipt{}, ErrUnavailable
		}
	}
	return receipt, nil
}

func (o *nodeChainPrefixOwnedProcess) usableLocked() bool {
	if o.drained || !o.frontReady || o.ctx.Err() != nil || o.p == nil || !o.p.Alive() ||
		(o.phase != NodeChainPrefixPending && o.phase != NodeChainPrefixPrepared) || o.phase == NodeChainPrefixPending && !o.now().Before(o.capture.BootstrapDeadline) {
		return false
	}
	return true
}

func (o *nodeChainPrefixOwnedProcess) usable() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.usableLocked()
}

func (o *nodeChainPrefixOwnedProcess) adoptReceipt(receipt NodeChainPrefixExecutionReceipt) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.usableLocked() || receipt.Sequence <= o.sequence {
		return false
	}
	// Called only after the manager has rechecked its source/owner under lock.
	// A worker's early prepared response cannot outrun completed bootstrap, and
	// an out-of-order pending read cannot overwrite an adopted Prepared state.
	if receipt.Phase == NodeChainPrefixPrepared && o.bootstrapped {
		o.phase = NodeChainPrefixPrepared
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

func (o *nodeChainPrefixOwnedProcess) terminal() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.phase == NodeChainPrefixFailed || o.phase == NodeChainPrefixRetired || o.ctx.Err() != nil ||
		o.phase == NodeChainPrefixPending && !o.now().Before(o.capture.BootstrapDeadline) || o.p != nil && !o.p.Alive()
}

// Alive retains ownership until a successful joined Stop, including a late
// process returned by a cancelled startup. Failure is not permission to reuse
// the port or delete an unjoined worker's private workspace.
func (o *nodeChainPrefixOwnedProcess) Alive() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.drained
}

func (o *nodeChainPrefixOwnedProcess) Stop(ctx context.Context) error {
	// Revocation is immediate even when a caller cancelled its cleanup wait.
	// The port still remains reserved until a later Stop confirms the join.
	o.mu.Lock()
	o.phase = NodeChainPrefixRetired
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
		return errors.New("NodeChainPrefix startup has not joined")
	}
	o.mu.Lock()
	p, candidate := o.p, o.candidate
	o.mu.Unlock()
	if candidate != nil {
		if err := candidate.close(ctx); err != nil {
			return err
		}
	}
	if p != nil {
		if err := p.Stop(ctx); err != nil || p.Alive() {
			return errors.New("NodeChainPrefix child teardown is unverified")
		}
	}
	select {
	case <-o.done:
	case <-ctx.Done():
		return errors.New("NodeChainPrefix bootstrap has not joined")
	}
	o.mu.Lock()
	o.drained = true
	o.mu.Unlock()
	return nil
}

func (m *Manager) validatePrefixRequest(peer netip.Addr, q NodeChainPrefixRequest) error {
	if peer.Zone() != "" || !nodeChainPrivateAddress(PeerKey(peer)) || q.validateShape() != nil || q.EntryNodeID != m.node ||
		q.Epoch != m.packetEpoch || q.Peer != PeerKey(peer) || q.Port < m.cfg.FirstPort || q.Port > m.cfg.LastPort {
		return ErrOwnership
	}
	return nil
}

// PrefixAvailable captures public descriptors and the actual caller challenge in
// one registry read. References alone never advertise a runtime capability.
func (m *Manager) PrefixAvailable(peer netip.Addr) (ExternalPacketChallenge, []NodeChainPrefixDescriptor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, capable := m.runner.(NodeChainPrefixRunner); !capable || m.closed || len(m.cfg.NodeChainPrefixes) == 0 {
		return ExternalPacketChallenge{}, nil, ErrUnavailable
	}
	challenge := ExternalPacketChallenge{Epoch: m.packetEpoch, Peer: PeerKey(peer), ExpiresAt: m.now().Add(packetAcquireLifetime).Unix()}
	if peer.Zone() != "" || !nodeChainPrivateAddress(challenge.Peer) || challenge.Validate() != nil {
		return ExternalPacketChallenge{}, nil, ErrOwnership
	}
	sources := make([]NodeChainPrefixDescriptor, 0, len(m.cfg.NodeChainPrefixes))
	for _, source := range m.cfg.NodeChainPrefixes {
		if !slices.Contains(source.EntryPeerAddresses, challenge.Peer) {
			continue
		}
		sources = append(sources, source.Clone())
	}
	if len(sources) == 0 {
		return ExternalPacketChallenge{}, nil, ErrUnavailable
	}
	return challenge, sources, nil
}

// PrefixPortRange exposes only the immutable configured proposal range to the
// authenticated caller. It reserves nothing and never changes a PUT's port.
func (m *Manager) PrefixPortRange(peer netip.Addr) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, capable := m.runner.(NodeChainPrefixRunner); !capable || m.closed || len(m.cfg.NodeChainPrefixes) == 0 {
		return 0, 0, ErrUnavailable
	}
	if peer.Zone() != "" || !nodeChainPrivateAddress(PeerKey(peer)) {
		return 0, 0, ErrOwnership
	}
	return m.cfg.FirstPort, m.cfg.LastPort, nil
}

func (m *Manager) prefixSourceLocked(q NodeChainPrefixRequest) (NodeChainPrefixDescriptor, error) {
	for _, source := range m.cfg.NodeChainPrefixes {
		if source.SourceSHA256 == q.SourceSHA256 {
			if q.Validate(source) != nil {
				return NodeChainPrefixDescriptor{}, ErrOwnership
			}
			return source.Clone(), nil
		}
	}
	return NodeChainPrefixDescriptor{}, ErrUnavailable
}

func nodeChainPrefixAttemptKey(peer netip.Addr, q NodeChainPrefixRequest) string {
	return PeerKey(peer) + "/" + q.SessionID
}

func (m *Manager) rememberPrefixAttemptLocked(peer netip.Addr, q NodeChainPrefixRequest, retire bool) error {
	for key, old := range m.prefixAttempts {
		if !old.until.After(m.now()) {
			peerKey, _, _ := strings.Cut(key, "/")
			active := m.leases[peerKey]
			if active == nil || active.prefix == nil || nodeChainPrefixAttemptKey(active.peer, active.prefix.capture.Request) != key {
				delete(m.prefixAttempts, key)
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
	key := nodeChainPrefixAttemptKey(peer, q)
	if old, exists := m.prefixAttempts[key]; exists {
		if !sameNodeChainPrefixRequest(old.request, q) || old.retired && !retire {
			return ErrOwnership
		}
	} else if len(m.prefixAttempts) >= nodeChainPrefixAttemptLimit {
		return ErrUnavailable
	}
	m.prefixAttempts[key] = nodeChainPrefixAttempt{request: q.Clone(), retired: retire, until: time.Unix(q.AcquireExpiresAt, 0)}
	return nil
}

// Packet identities are captured when a process is created, including partial
// starts and failed teardown. Never recompute an old owner's key from today's
// registry. A chain also pins its client's independent local packet identities.
func (m *Manager) prefixLeaseLocked(active *live) NodeChainPrefixLease {
	o := active.prefix
	o.mu.Lock()
	phase := o.phase
	o.mu.Unlock()
	c := o.capture
	return NodeChainPrefixLease{Request: c.Request.Clone(), NodeID: m.node, OwnerID: c.OwnerID, Host: c.Host, Port: c.Request.Port,
		RegistrySHA256: c.RegistrySHA256, Phase: phase, ExpiresAt: active.ExpiresAt, BootstrapDeadline: c.BootstrapDeadline}
}

// CreatePrefix reserves the ordinary per-peer and port inventory before native
// startup. The original worker starts and bootstraps outside Manager.mu. It
// never falls back to an ordinary relay or modifies any global route.
func (m *Manager) CreatePrefix(ctx context.Context, peer netip.Addr, request NodeChainPrefixRequest) (NodeChainPrefixLease, error) {
	if err := ctx.Err(); err != nil {
		return NodeChainPrefixLease{}, err
	}
	q := request.Clone()
	m.mu.Lock()
	if err := m.validatePrefixRequest(peer, q); err != nil {
		m.mu.Unlock()
		return NodeChainPrefixLease{}, err
	}
	runner, capable := m.runner.(NodeChainPrefixRunner)
	if m.closed || !capable {
		m.mu.Unlock()
		return NodeChainPrefixLease{}, ErrUnavailable
	}
	source, err := m.prefixSourceLocked(q)

	if err == nil {
		err = m.reapLocked(ctx)
	}
	if err != nil || ctx.Err() != nil {
		m.mu.Unlock()
		if err != nil {
			return NodeChainPrefixLease{}, err
		}
		return NodeChainPrefixLease{}, ctx.Err()
	}
	key := PeerKey(peer)
	if active := m.leases[key]; active != nil {
		if active.prefix == nil || !sameNodeChainPrefixRequest(active.prefix.capture.Request, q) || active.retired {
			m.mu.Unlock()
			return NodeChainPrefixLease{}, ErrBusy
		}
		m.mu.Unlock()
		challenge, err := nodeChainSecret()
		if err != nil {
			return NodeChainPrefixLease{}, err
		}
		status, err := m.prefixStatus(ctx, peer, q, challenge, true)
		return status.Lease, err
	}
	if q.AcquireExpiresAt <= m.now().Unix() || q.AcquireExpiresAt > m.now().Add(packetAcquireLifetime).Unix() {
		m.mu.Unlock()
		return NodeChainPrefixLease{}, ErrOwnership
	}
	var packetPins []string
	for _, member := range source.Members {
		if nodeChainPacketMode(member.Mode) {
			packetPins = append(packetPins, member.ClientPublicKey)
		}
	}
	if err := m.validatePacketPinsLocked(append(append([]string(nil), packetPins...), q.LocalPacketPublicKeys...)); err != nil {
		m.mu.Unlock()
		return NodeChainPrefixLease{}, err
	}
	for _, active := range m.leases {
		if active.Port == q.Port {
			m.mu.Unlock()
			return NodeChainPrefixLease{}, ErrBusy
		}
	}
	ownerID, err := nodeChainSecret()
	if err != nil {
		m.mu.Unlock()
		return NodeChainPrefixLease{}, err
	}
	capture := NodeChainPrefixCapture{Schema: 1, Request: q.Clone(), Source: source.Clone(), RegistrySHA256: q.DescriptorSHA256,
		OwnerID: ownerID, Peer: key, Host: m.cfg.ListenIP, BootstrapDeadline: m.now().Add(NodeChainPrefixBootstrapLimit).UTC()}
	if capture.Validate() != nil {
		m.mu.Unlock()
		return NodeChainPrefixLease{}, ErrOwnership
	}
	if err := m.rememberPrefixAttemptLocked(peer, q, false); err != nil {
		m.mu.Unlock()
		return NodeChainPrefixLease{}, err
	}
	owner := newNodeChainPrefixOwnedProcess(capture, runner, m.now)
	active := &live{Lease: Lease{Request: Request{SessionID: q.SessionID, EntryNodeID: q.EntryNodeID, ExitID: q.SourceSHA256, ExitMode: "node-chain-prefix"},
		NodeID: m.node, Host: capture.Host, Port: q.Port, ExpiresAt: m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)},
		peer: peer, p: owner, prefix: owner, packetPins: packetPins}
	m.leases[key] = active
	owner.launch()
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		_ = m.DeletePrefix(context.Background(), peer, q)
		return NodeChainPrefixLease{}, ctx.Err()
	case <-owner.ctx.Done():
		// The original startup deadline also bounds this HTTP acquisition,
		// even if a native runner ignores cancellation. Its failed owner and
		// reservation remain captured until cleanup joins the late result.
		go func() { _ = m.DeletePrefix(context.Background(), peer, q) }()
		return NodeChainPrefixLease{}, ErrUnavailable
	case <-owner.started:
	}
	m.mu.Lock()
	current, sourceErr := m.prefixSourceLocked(q)
	valid := ctx.Err() == nil && !m.closed && m.leases[key] == active && !active.retired && active.ExpiresAt.After(m.now()) &&
		sourceErr == nil && sameNodeChainPrefixSource(current, source) && owner.usable()
	var lease NodeChainPrefixLease
	if valid {
		lease = m.prefixLeaseLocked(active)
	}
	m.mu.Unlock()
	if !valid {
		_ = m.DeletePrefix(context.Background(), peer, q)
		return NodeChainPrefixLease{}, ErrUnavailable
	}
	return lease, nil
}

func (m *Manager) PrefixStatus(ctx context.Context, peer netip.Addr, q NodeChainPrefixRequest, challenge string) (NodeChainPrefixLeaseStatus, error) {
	return m.prefixStatus(ctx, peer, q.Clone(), challenge, false)
}

func (m *Manager) prefixStatus(ctx context.Context, peer netip.Addr, q NodeChainPrefixRequest, challenge string, renew bool) (NodeChainPrefixLeaseStatus, error) {
	if ctx.Err() != nil || !proofID.MatchString(challenge) {
		return NodeChainPrefixLeaseStatus{}, ErrOwnership
	}
	m.mu.Lock()
	if _, capable := m.runner.(NodeChainPrefixRunner); !capable {
		m.mu.Unlock()
		return NodeChainPrefixLeaseStatus{}, ErrUnavailable
	}
	if err := m.validatePrefixRequest(peer, q); err != nil {
		m.mu.Unlock()
		return NodeChainPrefixLeaseStatus{}, err
	}
	active := m.leases[PeerKey(peer)]
	source, sourceErr := m.prefixSourceLocked(q)
	if active != nil && active.prefix != nil && sameNodeChainPrefixRequest(active.prefix.capture.Request, q) &&
		(sourceErr != nil || !sameNodeChainPrefixSource(active.prefix.capture.Source, source)) {
		active.prefix.fail()
	}
	if m.closed || active == nil || active.prefix == nil || !sameNodeChainPrefixRequest(active.prefix.capture.Request, q) || active.retired ||
		!active.ExpiresAt.After(m.now()) || sourceErr != nil || !sameNodeChainPrefixSource(active.prefix.capture.Source, source) {
		m.mu.Unlock()
		return NodeChainPrefixLeaseStatus{}, ErrOwnership
	}
	owner := active.prefix
	m.mu.Unlock()
	// A delayed native reply cannot block another peer's inventory operations.
	receipt, err := owner.snapshot(ctx, challenge)
	if err != nil {
		return NodeChainPrefixLeaseStatus{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, sourceErr := m.prefixSourceLocked(q)
	if m.leases[PeerKey(peer)] == active && (sourceErr != nil || !sameNodeChainPrefixSource(current, source)) {
		owner.fail()
	}
	if ctx.Err() != nil || m.closed || m.leases[PeerKey(peer)] != active || active.retired || !active.ExpiresAt.After(m.now()) ||
		sourceErr != nil || !sameNodeChainPrefixSource(current, source) ||
		ValidateNodeChainPrefixExecutionReceipt(receipt, owner.capture, challenge, receipt.ObservedAt, m.now()) != nil || !owner.adoptReceipt(receipt) {
		return NodeChainPrefixLeaseStatus{}, ErrOwnership
	}
	if renew {
		active.ExpiresAt = m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)
	}
	return NodeChainPrefixLeaseStatus{Lease: m.prefixLeaseLocked(active), Receipt: receipt.Clone()}, nil
}

func (m *Manager) DeletePrefix(ctx context.Context, peer netip.Addr, request NodeChainPrefixRequest) error {
	q := request.Clone()
	m.mu.Lock()
	if _, capable := m.runner.(NodeChainPrefixRunner); !capable {
		m.mu.Unlock()
		return ErrUnavailable
	}
	if err := m.validatePrefixRequest(peer, q); err != nil {
		m.mu.Unlock()
		return err
	}
	key := PeerKey(peer)
	active := m.leases[key]
	if active != nil && (active.prefix == nil || !sameNodeChainPrefixRequest(active.prefix.capture.Request, q)) {
		m.mu.Unlock()
		return ErrOwnership
	}
	// A DELETE which overtakes its PUT retires exactly that captured attempt.
	// Registry removal must not prevent retirement of an existing owner.
	if active == nil && q.AcquireExpiresAt > m.now().Unix() {
		previous, known := m.prefixAttempts[nodeChainPrefixAttemptKey(peer, q)]
		if !known || !sameNodeChainPrefixRequest(previous.request, q) {
			if _, err := m.prefixSourceLocked(q); err != nil {
				m.mu.Unlock()
				return err
			}
		}
	}
	if err := m.rememberPrefixAttemptLocked(peer, q, true); err != nil {
		m.mu.Unlock()
		return err
	}
	if active == nil {
		m.mu.Unlock()
		return nil
	}
	active.retired = true
	owner := active.prefix
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
