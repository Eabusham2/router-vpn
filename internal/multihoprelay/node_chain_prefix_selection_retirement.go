package multihoprelay

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// finishPrefixSelection joins the original Select callback and its actual data
// owner. It never starts a worker and never waits while holding Manager.mu.
func (m *Manager) finishPrefixSelection(ctx context.Context, a *nodeChainPrefixSelectionAttempt) error {
	if ctx == nil || a == nil {
		return ErrOwnership
	}
	m.mu.Lock()
	if a.drained {
		m.mu.Unlock()
		return ctx.Err()
	}
	if m.leases[a.peer] != nil {
		m.mu.Unlock()
		return ErrBusy
	}
	a.retired = true
	if !a.retirementOnly {
		a.cancel()
	}
	m.mu.Unlock()
	select {
	case a.closeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-a.closeGate }()
	select {
	case <-a.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	m.mu.Lock()
	if a.drained {
		m.mu.Unlock()
		return ctx.Err()
	}
	if m.leases[a.peer] != nil {
		m.mu.Unlock()
		return ErrBusy
	}
	previous := a.previous
	if previous != nil && (!previous.retired || previous.drained) {
		previous = nil
	}
	source := a.source
	m.mu.Unlock()
	// If this replacement began retiring its predecessor, its own retirement
	// cannot hide a still-unjoined predecessor. An untouched predecessor stays.
	if previous != nil {
		if err := m.finishPrefixSelection(ctx, previous); err != nil {
			return err
		}
	}
	if source != nil {
		if err := source.CloseContext(ctx); err != nil {
			return err
		}
	}
	m.mu.Lock()
	a.drained = true
	a.source, a.previous = nil, nil
	a.request = NodeChainPrefixSelectionRequest{}
	a.descriptor = NodeChainPrefixDescriptor{}
	if m.prefixSelections[a.peer] == a {
		delete(m.prefixSelections, a.peer)
	}
	if m.prefixSelectionPending[a.peer] == a {
		delete(m.prefixSelectionPending, a.peer)
	}
	m.mu.Unlock()
	return ctx.Err()
}

func (m *Manager) DeletePrefixSelection(ctx context.Context, peer netip.Addr, request NodeChainPrefixSelectionRequest) (NodeChainPrefixSelectionReceipt, error) {
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
	if err = m.validatePrefixSelectionIdentityLocked(peer, q, false); err != nil {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, err
	}
	a := m.prefixSelectionAttempts[prefixSelectionAttemptKey(key, q.Nonce)]
	if a != nil {
		if a.digest != digest {
			m.mu.Unlock()
			return NodeChainPrefixSelectionReceipt{}, ErrOwnership
		}
		m.mu.Unlock()
		// Known-owner cleanup deliberately does not require a fresh catalog,
		// unexpired acquisition challenge, or an open Manager.
		if err = m.finishPrefixSelection(ctx, a); err != nil {
			return NodeChainPrefixSelectionReceipt{}, err
		}
		m.mu.Lock()
		admitted := a.admitted && a.drained && prefixSelectionCallJoined(a)
		receipt := prefixSelectionReceipt(a, "retired")
		m.mu.Unlock()
		if !admitted || receipt.Validate(q) != nil {
			return NodeChainPrefixSelectionReceipt{}, ErrOwnership
		}
		return receipt, nil
	}
	// An early DELETE can race a POST before it reaches this Manager. Reserve
	// that exact nonce before the currentness read so the later POST cannot
	// acquire; an unknown old epoch or expired request cannot obtain a receipt.
	if err = m.validatePrefixSelectionIdentityLocked(peer, q, true); err != nil {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, err
	}
	m.sweepPrefixSelectionAttemptsLocked()
	if m.leases[key] != nil || m.prefixSelectionPending[key] != nil || m.prefixSelections[key] != nil {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, ErrBusy
	}
	if len(m.prefixSelectionAttempts) >= nodeChainPrefixAttemptLimit || m.prefixSelectionSlotsLocked() >= MaxPairedExits {
		m.mu.Unlock()
		return NodeChainPrefixSelectionReceipt{}, ErrUnavailable
	}
	a = newPrefixSelectionAttempt(ctx, key, q, digest)
	a.retirementOnly, a.retired = true, true
	m.prefixSelectionAttempts[prefixSelectionAttemptKey(key, q.Nonce)] = a
	m.prefixSelectionPending[key] = a
	catalog := m.prefixSelectionCatalog
	m.mu.Unlock()
	err = catalog.CurrentContext(a.ctx)
	m.mu.Lock()
	a.admitted = err == nil && a.ctx.Err() == nil && !m.closed &&
		m.prefixSelectionPending[key] == a
	a.retired = true
	a.cancel()
	m.mu.Unlock()
	// This is the actual end of the original currentness invocation. No
	// Select callback or source was started on this early-retirement path.
	close(a.done)
	if closeErr := m.finishPrefixSelection(ctx, a); closeErr != nil {
		return NodeChainPrefixSelectionReceipt{}, errors.Join(err, closeErr)
	}
	m.mu.Lock()
	admitted := a.admitted && a.drained
	receipt := prefixSelectionReceipt(a, "retired")
	m.mu.Unlock()
	if err != nil || !admitted || receipt.Validate(q) != nil {
		return NodeChainPrefixSelectionReceipt{}, errors.Join(err, ErrOwnership)
	}
	return receipt, nil
}

// Called outside Manager.mu after the ordinary lease sweep. A failed callback
// remains counted and fences its peer until its real source close succeeds.
func (m *Manager) sweepPrefixSelections(ctx context.Context) error {
	m.mu.Lock()
	attempts := make([]*nodeChainPrefixSelectionAttempt, 0, len(m.prefixSelectionPending)+len(m.prefixSelections))
	seen := make(map[*nodeChainPrefixSelectionAttempt]bool)
	for _, a := range m.prefixSelectionPending {
		if (a.retired || a.ctx.Err() != nil) && !seen[a] {
			a.retired = true
			if !a.retirementOnly {
				a.cancel()
			}
			attempts = append(attempts, a)
			seen[a] = true
		}
	}
	for _, a := range m.prefixSelections {
		if a.retired && !seen[a] {
			attempts = append(attempts, a)
			seen[a] = true
		}
	}
	m.mu.Unlock()
	var result error
	for _, a := range attempts {
		if ctx.Err() != nil {
			result = errors.Join(result, ctx.Err())
			break
		}
		// This cap can only shorten the caller's existing cleanup deadline.
		closeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		result = errors.Join(result, m.finishPrefixSelection(closeCtx, a))
		cancel()
	}
	m.mu.Lock()
	m.sweepPrefixSelectionAttemptsLocked()
	m.mu.Unlock()
	return result
}

// closePrefixSelections uses the original Manager.Close context after its
// leases have had their original stop/join attempt.
func (m *Manager) closePrefixSelections(ctx context.Context) error {
	m.mu.Lock()
	attempts := make([]*nodeChainPrefixSelectionAttempt, 0, len(m.prefixSelectionPending)+len(m.prefixSelections))
	seen := make(map[*nodeChainPrefixSelectionAttempt]bool)
	for _, entries := range []map[string]*nodeChainPrefixSelectionAttempt{m.prefixSelectionPending, m.prefixSelections} {
		for _, a := range entries {
			if !seen[a] {
				if m.leases[a.peer] == nil {
					a.retired = true
					a.cancel()
				}
				attempts = append(attempts, a)
				seen[a] = true
			}
		}
	}
	catalog := m.prefixSelectionCatalog
	m.mu.Unlock()
	if len(attempts) == 0 && catalog == nil {
		return nil
	}
	var result error
	for _, a := range attempts {
		result = errors.Join(result, m.finishPrefixSelection(ctx, a))
	}
	m.mu.Lock()
	joined := len(m.leases) == 0 && len(m.prefixSelectionPending) == 0 && len(m.prefixSelections) == 0
	m.sweepPrefixSelectionAttemptsLocked()
	m.mu.Unlock()
	if !joined {
		return errors.Join(result, ErrOwnership)
	}
	if catalog != nil {
		result = errors.Join(result, catalog.CloseContext(ctx))
	}
	return errors.Join(result, ctx.Err())
}
