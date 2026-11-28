package main

import "router-vpn/internal/multihoprelay"

// These reservations use the original runner ledger. Existing base-worker
// sharing is unchanged; an original packet candidate cannot overlap any prefix
// reservation, including a failed prefix cleanup awaiting its terminal proof.
func (r *relayNodeChainPacketKeyLedger) reservePrefix(p *relayNodeChainPrefixProcess, keys []string) (*relayNodeChainPacketKeyReservation, error) {
	if r == nil || p == nil || p.self != p || p.packetKeys != r {
		return nil, multihoprelay.ErrOwnership
	}
	unique := map[string]bool{}
	for _, key := range keys {
		if key == "" || unique[key] {
			return nil, multihoprelay.ErrOwnership
		}
		unique[key] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owners == nil {
		r.owners = make(map[*relayNodeChainPacketKeyReservation]bool)
	}
	for original := range r.owners {
		if original.prefix == p {
			return nil, multihoprelay.ErrBusy
		}
		if original.operation == nil && original.prefixOperation == nil {
			continue
		}
		for _, key := range original.keys {
			if unique[key] {
				return nil, multihoprelay.ErrBusy
			}
		}
	}
	owner := &relayNodeChainPacketKeyReservation{ledger: r, prefix: p, keys: append([]string(nil), keys...)}
	owner.self = owner
	r.owners[owner] = true
	return owner, nil
}
func (r *relayNodeChainPacketKeyLedger) releasePrefix(owner *relayNodeChainPacketKeyReservation, p *relayNodeChainPrefixProcess) error {
	if r == nil || p == nil || p.self != p || owner == nil || owner.self != owner || owner.ledger != r || owner.prefix != p || owner.process != nil || owner.operation != nil || owner.prefixOperation != nil {
		return multihoprelay.ErrOwnership
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.owners[owner] {
		return multihoprelay.ErrOwnership
	}
	delete(r.owners, owner)
	return nil
}
