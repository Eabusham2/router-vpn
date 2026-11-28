package multihoprelay

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"
)

// A selection owns only immutable private source data. It never impersonates a
// lease or reserves packet keys, a listener, a worker, or a measurement result.
type nodeChainPrefixSelectionAttempt struct {
	peer, nonce, digest, catalogSHA, generationSHA string
	until                                          time.Time
	request                                        NodeChainPrefixSelectionRequest
	ctx                                            context.Context
	cancel                                         context.CancelFunc
	done                                           chan struct{}
	closeGate                                      chan struct{}
	previous                                       *nodeChainPrefixSelectionAttempt
	source                                         NodeChainPrefixSelectionSource
	descriptor                                     NodeChainPrefixDescriptor
	sourceSHA, descriptorSHA                       string
	admitted, published, retired, drained          bool
	retirementOnly                                 bool
}

func newPrefixSelectionAttempt(ctx context.Context, peer string, q NodeChainPrefixSelectionRequest, digest string) *nodeChainPrefixSelectionAttempt {
	lifetime, cancel := context.WithCancel(ctx)
	return &nodeChainPrefixSelectionAttempt{
		peer: peer, nonce: q.Nonce, digest: digest, catalogSHA: q.CatalogSHA256,
		generationSHA: q.CatalogGenerationSHA256, until: time.Unix(q.AcquireExpiresAt, 0),
		request: q.Clone(), ctx: lifetime, cancel: cancel,
		done: make(chan struct{}), closeGate: make(chan struct{}, 1),
	}
}

func prefixSelectionAttemptKey(peer, nonce string) string { return peer + "/" + nonce }

func prefixSelectionCallJoined(a *nodeChainPrefixSelectionAttempt) bool {
	select {
	case <-a.done:
		return true
	default:
		return false
	}
}

func (m *Manager) initializePrefixSelection() error {
	m.prefixSelections = make(map[string]*nodeChainPrefixSelectionAttempt)
	m.prefixSelectionPending = make(map[string]*nodeChainPrefixSelectionAttempt)
	m.prefixSelectionAttempts = make(map[string]*nodeChainPrefixSelectionAttempt)
	if m.cfg.NodeChainPrefixCatalog == nil {
		return nil
	}
	reference := *m.cfg.NodeChainPrefixCatalog
	runner, ok := m.runner.(NodeChainPrefixSelectionRunner)
	if !ok || reference.Validate() != nil || reference.EntryNodeID != m.node {
		return ErrUnavailable
	}
	catalog := runner.PrefixSelectionCatalog()
	if catalog == nil || catalog.Reference() != reference || !proofID.MatchString(catalog.GenerationSHA256()) {
		return ErrOwnership
	}
	peers := catalog.EntryPeerAddresses()
	if len(peers) == 0 {
		return ErrOwnership
	}
	seen := make(map[string]bool, len(peers))
	for _, peer := range peers {
		if !nodeChainPrivateAddress(peer) || seen[peer] {
			return ErrOwnership
		}
		seen[peer] = true
	}
	m.prefixSelectionRunner, m.prefixSelectionCatalog = runner, catalog
	return nil
}

func (m *Manager) prefixSelectionVisibleLocked(peer string) bool {
	a := m.prefixSelections[peer]
	return a != nil && a.published && !a.retired && !a.drained && a.source != nil
}

func (m *Manager) prefixSelectionBusyLocked(peer string) bool {
	if m.prefixSelectionPending[peer] != nil {
		return true
	}
	previous := m.prefixSelections[peer]
	return previous != nil && previous.retired && !previous.drained
}

func (m *Manager) prefixSelectionSlotsLocked() int {
	count := len(m.cfg.Exits) + len(m.cfg.TorExits) + len(m.cfg.NodeChains) + len(m.cfg.NodeChainPrefixes) + len(m.prefixSelections)
	for peer := range m.prefixSelectionPending {
		if m.prefixSelections[peer] == nil {
			count++
		}
	}
	return count
}

// Only expired, genuinely joined retirement records are forgettable. A late
// callback or failed source Close keeps both its nonce and its original owner.
func (m *Manager) sweepPrefixSelectionAttemptsLocked() {
	for key, a := range m.prefixSelectionAttempts {
		if a.retired && a.drained && prefixSelectionCallJoined(a) && !a.until.After(m.now()) &&
			m.prefixSelections[a.peer] != a && m.prefixSelectionPending[a.peer] != a {
			delete(m.prefixSelectionAttempts, key)
		}
	}
}

func (m *Manager) validatePrefixSelectionIdentityLocked(peer netip.Addr, q NodeChainPrefixSelectionRequest, acquiring bool) error {
	key := PeerKey(peer)
	if peer.Zone() != "" || !nodeChainPrivateAddress(key) || q.Validate() != nil ||
		q.Peer != key || q.EntryNodeID != m.node || q.Epoch != m.packetEpoch {
		return ErrOwnership
	}
	if !acquiring {
		return nil
	}
	catalog := m.prefixSelectionCatalog
	if m.closed || catalog == nil || m.prefixSelectionRunner == nil {
		return ErrUnavailable
	}
	reference := catalog.Reference()
	if q.CatalogSHA256 != reference.SourceSHA256 || q.CatalogGenerationSHA256 != catalog.GenerationSHA256() ||
		reference.EntryNodeID != m.node || !slices.Contains(catalog.EntryPeerAddresses(), key) ||
		q.AcquireExpiresAt <= m.now().Unix() || q.AcquireExpiresAt > m.now().Add(packetAcquireLifetime).Unix() {
		return ErrOwnership
	}
	return nil
}

func (m *Manager) PrefixSelectionAvailable(ctx context.Context, peer netip.Addr) (NodeChainPrefixSelectionDiscovery, error) {
	if ctx == nil || ctx.Err() != nil {
		return NodeChainPrefixSelectionDiscovery{}, ErrUnavailable
	}
	key := PeerKey(peer)
	m.mu.Lock()
	if m.closed || peer.Zone() != "" || !nodeChainPrivateAddress(key) {
		m.mu.Unlock()
		return NodeChainPrefixSelectionDiscovery{}, ErrOwnership
	}
	result := NodeChainPrefixSelectionDiscovery{Schema: 1, Purpose: NodeChainPrefixSelectionPurpose, NodeID: m.node,
		StaticPrefixes: make([]NodeChainPrefixDescriptor, 0)}
	if _, capable := m.runner.(NodeChainPrefixRunner); capable {
		for _, source := range m.cfg.NodeChainPrefixes {
			if slices.Contains(source.EntryPeerAddresses, key) {
				result.StaticPrefixes = append(result.StaticPrefixes, source.Clone())
			}
		}
	}
	catalog := m.prefixSelectionCatalog
	m.mu.Unlock()
	// Currentness can read the captured private file; never wait for that work
	// while holding the Manager gate used by unrelated leases.
	if catalog != nil && slices.Contains(catalog.EntryPeerAddresses(), key) {
		if err := catalog.CurrentContext(ctx); err == nil {
			m.mu.Lock()
			if !m.closed && ctx.Err() == nil {
				capability := NodeChainPrefixSelectionCapability{Reference: catalog.Reference(),
					GenerationSHA256: catalog.GenerationSHA256(),
					Challenge:        ExternalPacketChallenge{Epoch: m.packetEpoch, Peer: key, ExpiresAt: m.now().Add(packetAcquireLifetime).Unix()}}
				result.Catalog = &capability
			}
			m.mu.Unlock()
		} else if ctx.Err() != nil {
			return NodeChainPrefixSelectionDiscovery{}, ctx.Err()
		}
	}
	m.mu.Lock()
	valid := !m.closed && ctx.Err() == nil
	m.mu.Unlock()
	if !valid || result.Validate() != nil {
		return NodeChainPrefixSelectionDiscovery{}, ErrUnavailable
	}
	return result, nil
}

// Any common eligible candidate could make a later legitimate subset request
// ambiguous. Static subset/superset intersections cannot be shadowed.
func (m *Manager) prefixSelectionOverlapsLocked(peer string, q NodeChainPrefixSelectionRequest, replaced *nodeChainPrefixSelectionAttempt) bool {
	for _, source := range m.cfg.NodeChainPrefixes {
		if slices.Contains(source.EntryPeerAddresses, peer) && q.OverlapsDescriptor(source) {
			return true
		}
	}
	// Dynamic registrations are visible only to their original authenticated peer.
	if active := m.prefixSelections[peer]; active != nil && active != replaced && active.published && !active.retired &&
		q.OverlapsDescriptor(active.descriptor) {
		return true
	}
	return false
}

func prefixSelectionReceipt(a *nodeChainPrefixSelectionAttempt, phase string) NodeChainPrefixSelectionReceipt {
	result := NodeChainPrefixSelectionReceipt{Schema: 1, Purpose: NodeChainPrefixSelectionPurpose,
		RequestSHA256: a.digest, CatalogSHA256: a.catalogSHA, CatalogGenerationSHA256: a.generationSHA,
		Phase: phase, Publication: a.published}
	if a.published {
		result.SourceSHA256, result.DescriptorSHA256 = a.sourceSHA, a.descriptorSHA
	}
	return result
}

func (m *Manager) SelectPrefix(ctx context.Context, peer netip.Addr, request NodeChainPrefixSelectionRequest) (NodeChainPrefixSelectionReceipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return NodeChainPrefixSelectionReceipt{}, ErrUnavailable
	}
	q := request.Clone()
	digest, err := q.Digest()
	if err != nil {
		return NodeChainPrefixSelectionReceipt{}, ErrOwnership
	}
	key := PeerKey(peer)
	m.mu.Lock()
	if err = m.validatePrefixSelectionIdentityLocked(peer, q, true); err != nil {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, err
	}
	m.sweepPrefixSelectionAttemptsLocked()
	if old := m.prefixSelectionAttempts[prefixSelectionAttemptKey(key, q.Nonce)]; old != nil {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, ErrOwnership
	}
	if m.leases[key] != nil || m.prefixSelectionBusyLocked(key) {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, ErrBusy
	}
	previous := m.prefixSelections[key]
	if len(m.prefixSelectionAttempts) >= nodeChainPrefixAttemptLimit ||
		previous == nil && m.prefixSelectionSlotsLocked() >= MaxPairedExits {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, ErrUnavailable
	}
	if m.prefixSelectionOverlapsLocked(key, q, previous) {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, ErrOwnership
	}
	a := newPrefixSelectionAttempt(ctx, key, q, digest)
	a.admitted, a.previous = true, previous
	m.prefixSelectionAttempts[prefixSelectionAttemptKey(key, q.Nonce)] = a
	m.prefixSelectionPending[key] = a
	catalog := m.prefixSelectionCatalog
	m.mu.Unlock()
	// A DELETE waits for this exact original invocation, not an inferred result.
	defer close(a.done)
	defer a.cancel()
	var source NodeChainPrefixSelectionSource
	err = catalog.CurrentContext(a.ctx)
	if err == nil {
		source, err = catalog.SelectContext(a.ctx, q.Clone())
	}
	// A nonnil late result is owned before its error or cancellation is inspected.
	m.mu.Lock()
	a.source = source
	m.mu.Unlock()
	var descriptor NodeChainPrefixDescriptor
	var descriptorSHA string
	if err == nil {
		if source == nil {
			err = ErrUnavailable
		} else {
			actualRequest, requestErr := source.Request().Digest()
			descriptor = source.Descriptor()
			descriptorSHA, err = descriptor.Digest()
			if requestErr != nil || actualRequest != digest || err != nil ||
				source.CatalogSHA256() != q.CatalogSHA256 || source.GenerationSHA256() != q.CatalogGenerationSHA256 ||
				!q.MatchesSelectedDescriptor(descriptor) {
				err = ErrOwnership
			}
		}
	}
	if err == nil {
		err = source.CurrentContext(a.ctx)
	}
	if err == nil && previous != nil {
		m.mu.Lock()
		valid := !m.closed && a.ctx.Err() == nil && !a.retired && m.prefixSelectionPending[key] == a &&
			m.leases[key] == nil && m.prefixSelections[key] == previous
		if valid {
			previous.retired = true
			previous.cancel()
		}
		m.mu.Unlock()
		if !valid {
			err = ErrOwnership
		} else {
			err = m.finishPrefixSelection(a.ctx, previous)
		}
	}
	if err == nil {
		err = source.CurrentContext(a.ctx)
	}
	m.mu.Lock()
	valid := err == nil && a.ctx.Err() == nil && !m.closed && !a.retired &&
		m.prefixSelectionPending[key] == a && m.leases[key] == nil && m.prefixSelections[key] == nil &&
		m.prefixSelectionSlotsLocked() <= MaxPairedExits && !m.prefixSelectionOverlapsLocked(key, q, nil)
	if valid {
		a.descriptor, a.sourceSHA, a.descriptorSHA = descriptor.Clone(), descriptor.SourceSHA256, descriptorSHA
		a.published = true
		m.prefixSelections[key] = a
		delete(m.prefixSelectionPending, key)
		receipt := prefixSelectionReceipt(a, "published")
		m.mu.Unlock()
		return receipt, nil
	}
	a.retired = true
	a.cancel()
	m.mu.Unlock()
	if err == nil {
		err = errors.Join(a.ctx.Err(), ErrOwnership)
	}
	// The failed pending owner remains fenced until its real callback/source
	// retirement joins through DELETE, Sweep, or the original Manager.Close.
	return NodeChainPrefixSelectionReceipt{}, err
}

func (m *Manager) selectedPrefixSourceLocked(q NodeChainPrefixRequest) (NodeChainPrefixDescriptor, error) {
	a := m.prefixSelections[q.Peer]
	if a == nil || a.retired || a.drained || !a.published || a.source == nil ||
		q.SelectionSHA256 != a.digest || !a.request.MatchesLease(q, a.descriptor) {
		return NodeChainPrefixDescriptor{}, ErrOwnership
	}
	return a.descriptor.Clone(), nil
}

type selectedNodeChainPrefixRunner struct {
	runner  NodeChainPrefixSelectionRunner
	source  NodeChainPrefixSelectionSource
	request NodeChainPrefixSelectionRequest
}

func (r selectedNodeChainPrefixRunner) StartPrefix(ctx context.Context, capture NodeChainPrefixCapture) (NodeChainPrefixProcess, error) {
	if r.runner == nil || r.source == nil || !r.request.MatchesLease(capture.Request, capture.Source) {
		return nil, ErrOwnership
	}
	return r.runner.StartSelectedPrefix(ctx, capture, r.source)
}

func (m *Manager) prefixRunnerLocked(q NodeChainPrefixRequest, original NodeChainPrefixRunner) (NodeChainPrefixRunner, error) {
	if q.SelectionSHA256 == "" {
		return original, nil
	}
	a := m.prefixSelections[q.Peer]
	if _, err := m.selectedPrefixSourceLocked(q); err != nil || a == nil || m.prefixSelectionRunner == nil {
		return nil, ErrOwnership
	}
	return selectedNodeChainPrefixRunner{runner: m.prefixSelectionRunner, source: a.source, request: a.request.Clone()}, nil
}
