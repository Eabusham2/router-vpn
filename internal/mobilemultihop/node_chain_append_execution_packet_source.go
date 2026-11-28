package mobilemultihop

import (
	"encoding/json"
	"reflect"

	"router-vpn/internal/multihoprelay"
)

// Packet NEXT has its own unfinished-prefix commitment. No complete Server
// policy, route projection or selected-route owner is created by these helpers.
func nodeChainAppendExecutionPacketMode(mode string) bool {
	return mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong"
}

type nodeChainAppendExecutionPacketIdentity struct {
	Position                                                                               int
	ProfileID, NodeID, Mode, SourceSHA256, ClientPublicKey, PeerPublicKey, TransportSHA256 string
}

func nodeChainPrefixPacketTransport(node *NodeProfile) (string, error) {
	if node == nil || !nodeChainAppendExecutionPacketMode(node.mode) ||
		!packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
		return "", errNodeChainAppendExecution
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil || !nodeChainFinalClosure(node, closure) {
		return "", errNodeChainAppendExecution
	}
	var graph map[string]any
	if exactJSON([]byte(node.Config()), &graph, 4<<20) != nil {
		return "", errNodeChainAppendExecution
	}
	rows, ok := graph["endpoints"].([]any)
	if !ok || len(rows) != 1 {
		return "", errNodeChainAppendExecution
	}
	endpoint, ok := rows[0].(map[string]any)
	if !ok {
		return "", errNodeChainAppendExecution
	}
	peers, ok := endpoint["peers"].([]any)
	if !ok || len(peers) != 1 {
		return "", errNodeChainAppendExecution
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return "", errNodeChainAppendExecution
	}
	// These are exactly the client-specific removals used by the original
	// nodeChainPlanTransportEqual; peer, literal endpoint, MTU and options stay.
	delete(endpoint, "private_key")
	delete(endpoint, "address")
	delete(peer, "pre_shared_key")
	return nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-packet-transport-v1", []any{node.mode, graph})
}

func nodeChainAppendExecutionPacketIdentityFromNode(position int, node *NodeProfile) (nodeChainAppendExecutionPacketIdentity, error) {
	var empty nodeChainAppendExecutionPacketIdentity
	if position < 1 || position > multihoprelay.NodeChainPrefixMaximumMembers || node == nil {
		return empty, errNodeChainAppendExecution
	}
	client, peer, err := nodeChainPacketKeys(node)
	transport, other := nodeChainPrefixPacketTransport(node)
	if err != nil || other != nil {
		return empty, errNodeChainAppendExecution
	}
	return nodeChainAppendExecutionPacketIdentity{Position: position,
		ProfileID: predecessorText(node.profile, "id"), NodeID: predecessorText(node.profile, "node_proof_id"),
		Mode: node.mode, SourceSHA256: node.source, ClientPublicKey: client, PeerPublicKey: peer, TransportSHA256: transport}, nil
}

func (v nodeChainAppendExecutionPacketIdentity) matches(pair multihoprelay.NodeChainPrefixPacketCandidatePair) bool {
	return pair.Validate() == nil && pair.Position == v.Position && pair.ProfileID == v.ProfileID &&
		pair.NodeID == v.NodeID && pair.Mode == v.Mode && pair.LocalSourceSHA256 == v.SourceSHA256 &&
		pair.LocalClientPublicKey == v.ClientPublicKey && pair.PeerPublicKey == v.PeerPublicKey &&
		pair.TransportSHA256 == v.TransportSHA256
}

func nodeChainPrefixPacketPair(position int, local, server *NodeProfile) (multihoprelay.NodeChainPrefixPacketCandidatePair, error) {
	var empty multihoprelay.NodeChainPrefixPacketCandidatePair
	// The existing pure projection checks the genuine independently captured
	// client keys/addresses and exact common transport before a pair is emitted.
	original, err := nodeChainPacketCandidatePair(position, local, server)
	localTransport, localErr := nodeChainPrefixPacketTransport(local)
	serverTransport, serverErr := nodeChainPrefixPacketTransport(server)
	if err != nil || localErr != nil || serverErr != nil || localTransport != serverTransport {
		return empty, errNodeChainAppendExecution
	}
	pair := multihoprelay.NodeChainPrefixPacketCandidatePair{Position: original.Position,
		ProfileID: original.ProfileID, NodeID: original.NodeID, Mode: original.Mode,
		LocalSourceSHA256: original.LocalSourceSHA256, LocalClientPublicKey: original.LocalClientPublicKey,
		ServerSourceSHA256: original.ServerSourceSHA256, ServerClientPublicKey: original.ServerClientPublicKey,
		PeerPublicKey: original.PeerPublicKey, TransportSHA256: localTransport}
	return pair, pair.Validate()
}

func nodeChainPrefixPacketServerMatches(pair multihoprelay.NodeChainPrefixPacketCandidatePair, server *NodeProfile) bool {
	if pair.Validate() != nil || server == nil || pair.ServerSourceSHA256 != server.source ||
		pair.ProfileID != predecessorText(server.profile, "id") || pair.NodeID != predecessorText(server.profile, "node_proof_id") ||
		pair.Mode != server.mode {
		return false
	}
	client, peer, err := nodeChainPacketKeys(server)
	transport, other := nodeChainPrefixPacketTransport(server)
	return err == nil && other == nil && client == pair.ServerClientPublicKey &&
		peer == pair.PeerPublicKey && transport == pair.TransportSHA256
}

// PacketCandidateRuntimeKeys is identity-only readback for the original shared
// process/key ledger. It cannot construct or authorize a packet endpoint.
func (p *NodeChainServerPrefixPolicy) PacketCandidateRuntimeKeys(c multihoprelay.NodeChainPrefixCandidateCapture) ([]string, string, error) {
	if p == nil || p.validate() != nil || !nodeChainPrefixHasPacketCandidates(p.record) || p.BindCapture(c.Lease) != nil {
		return nil, "", errNodeChainAppendExecution
	}
	pair, err := c.PacketPair()
	if err != nil {
		return nil, "", err
	}
	for i, original := range p.record.PacketCandidatePairs {
		if original != pair || i >= len(p.candidates) || !nodeChainPrefixPacketServerMatches(pair, p.candidates[i]) {
			continue
		}
		if _, err = p.candidate(c); err != nil {
			return nil, "", err
		}
		digest, err := pair.Digest()
		if err != nil {
			return nil, "", err
		}
		return []string{pair.ServerClientPublicKey, pair.PeerPublicKey, pair.LocalClientPublicKey}, digest, nil
	}
	return nil, "", errNodeChainAppendExecution
}

func nodeChainPrefixPacketResponseEqual(a, b candidateResponseSource) bool {
	a.PacketOptions, b.PacketOptions = "", ""
	return reflect.DeepEqual(a, b)
}

// The exact source options remain the only input. No invented endpoint address,
// synthetic final node, or complete-route owner enters the packet projection.
func nodeChainPrefixPacketOptions(node *NodeProfile, carrier *NodeChainServerCarrier) (string, error) {
	if node == nil || carrier == nil || !carrier.sealed() || !nodeChainAppendExecutionPacketMode(node.mode) {
		return "", errNodeChainAppendExecution
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil {
		return "", err
	}
	// This newly acquired candidate has no retained endpoint to resize. Use
	// the original physical carrier's envelope/MTU calculation, including its
	// unchanged fixed-MTU refusal, and seal the resulting exact options.
	if !nodeChainFinalClosure(node, closure) || carrier.apply(node, closure) != nil {
		return "", errNodeChainAppendExecution
	}
	raw, err := json.Marshal(closure.final)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
