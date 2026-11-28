package main

import "router-vpn/internal/multihoprelay"

// Packet NEXT reservations share the original runner ledger with complete
// workers, complete candidates and unfinished prefixes. The original process
// and candidate handles, not a public key lookup, own their eventual release.
func (r *relayNodeChainPacketKeyLedger) reservePrefixCandidate(p *relayNodeChainPrefixProcess, op *relayNodeChainPrefixCandidateOperation, keys []string) (*relayNodeChainPacketKeyReservation, error) {
	if r == nil || p == nil || p.self != p || p.packetKeys != r ||
		op == nil || op.self != op || op.process != p || !op.capture.Request.IsPacket() {
		return nil, multihoprelay.ErrOwnership
	}
	pair, err := op.capture.PacketPair()
	if err != nil || len(keys) != 3 || keys[0] != pair.ServerClientPublicKey ||
		keys[1] != pair.PeerPublicKey || keys[2] != pair.LocalClientPublicKey {
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
	if r.owners == nil || p.packetBase == nil || !r.owners[p.packetBase] ||
		p.packetBase.prefix != p || p.packetBase.process != nil || p.packetBase.operation != nil || p.packetBase.prefixOperation != nil {
		return nil, multihoprelay.ErrOwnership
	}
	for original := range r.owners {
		if original.prefix == p && original.prefixOperation == op {
			return nil, multihoprelay.ErrBusy
		}
		for _, key := range original.keys {
			if unique[key] {
				return nil, multihoprelay.ErrBusy
			}
		}
	}
	owner := &relayNodeChainPacketKeyReservation{ledger: r, prefix: p, prefixOperation: op, keys: append([]string(nil), keys...)}
	owner.self = owner
	r.owners[owner] = true
	return owner, nil
}

func (r *relayNodeChainPacketKeyLedger) ownsPrefixCandidate(owner *relayNodeChainPacketKeyReservation, p *relayNodeChainPrefixProcess, op *relayNodeChainPrefixCandidateOperation) bool {
	if r == nil || p == nil || p.self != p || p.packetKeys != r || op == nil || op.self != op || op.process != p ||
		owner == nil || owner.self != owner || owner.ledger != r || owner.prefix != p || owner.prefixOperation != op ||
		owner.process != nil || owner.operation != nil || op.packetKeys != owner {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.owners[owner]
}

// The caller holds the original process gate after no publication was possible,
// or after the exact native candidate drain / whole-worker joined proof.
func (r *relayNodeChainPacketKeyLedger) releasePrefixCandidate(owner *relayNodeChainPacketKeyReservation, p *relayNodeChainPrefixProcess, op *relayNodeChainPrefixCandidateOperation) error {
	if r == nil || p == nil || p.self != p || p.packetKeys != r || op == nil || op.self != op || op.process != p ||
		owner == nil || owner.self != owner || owner.ledger != r || owner.prefix != p || owner.prefixOperation != op ||
		owner.process != nil || owner.operation != nil || op.packetKeys != owner {
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

// Called only with the original process gate, which serializes publication,
// status and release. Construction attached this exact immutable pair before
// any candidate Prepare; cleanup never replaces its reservation.
func (op *relayNodeChainPrefixCandidateOperation) packetCurrent() bool {
	if op == nil || op.self != op || op.process == nil {
		return false
	}
	if !op.capture.Request.IsPacket() {
		return op.packetKeys == nil && op.pairing == ""
	}
	return op.packetKeys != nil && op.pairing != "" && op.process.packetKeys != nil &&
		op.process.packetKeys.ownsPrefixCandidate(op.packetKeys, op.process, op)
}

func (op *relayNodeChainPrefixCandidateOperation) packetReceiptCurrent(receipt *multihoprelay.NodeChainPrefixCandidateReceipt) bool {
	return receipt != nil && op.packetCurrent() && receipt.PairingSHA256 == op.pairing
}
