package main

import (
	"errors"

	"router-vpn/internal/multihoprelay"
)

type desktopServerPeerIdentity struct {
	packet, pq string
}

// Comparison reacquires its winner after closing trial sessions. Keep the
// first independently paired public identities for the entire captured round;
// final proof must not silently select newly linked Server credentials.
func (d *desktopExecutionDriver) serverPeerSelection(sel multihopSelection) multihopSelection {
	d.peerMu.Lock()
	defer d.peerMu.Unlock()
	if peer, ok := d.peers[sel.ExitMode]; ok {
		sel.serverPacketPublic, sel.serverPQIdentity = peer.packet, peer.pq
	}
	return sel
}

func (d *desktopExecutionDriver) captureServerPeer(owner *desktopRelayOwner) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	mode := owner.request.ExitMode
	if !nativeMultihopPacketExitMode(mode) {
		return nil
	}
	bad := errors.New("Server peer changed during the captured comparison")
	if !owner.packetCapabilityReady || owner.request.EntryNodeID != d.selection.Entry.NodeProofID || owner.request.ExitID != d.selection.Exit.ID ||
		owner.expected.ExitNodeID != d.selection.Exit.NodeProofID || owner.expected.Request != owner.request || owner.serverPacketPublic == "" ||
		owner.localPacketPublic == "" || owner.localPacketPublic == owner.serverPacketPublic || owner.request.ExpectedPacketPublicKey != owner.serverPacketPublic ||
		!owner.validPQPin() || multihoprelay.ValidateIdentityPins(mode, owner.serverPacketPublic, owner.serverPQIdentity) != nil {
		return bad
	}
	peer := desktopServerPeerIdentity{owner.serverPacketPublic, owner.serverPQIdentity}
	d.peerMu.Lock()
	defer d.peerMu.Unlock()
	if retained, found := d.peers[mode]; found {
		if retained != peer {
			return bad
		}
		return nil
	}
	if d.peers == nil {
		d.peers = make(map[string]desktopServerPeerIdentity)
	}
	d.peers[mode] = peer
	return nil
}
