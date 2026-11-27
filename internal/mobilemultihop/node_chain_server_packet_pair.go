package mobilemultihop

import (
	"encoding/json"
	"reflect"

	"router-vpn/internal/multihoprelay"
)

// This operator-owned record is produced from the actual Local and independent
// Server bundle compilers. It contains no Local private key or launch input.
type NodeChainPacketCandidatePair struct {
	Position              int    `json:"position"`
	ProfileID             string `json:"profile_id"`
	NodeID                string `json:"node_id"`
	Mode                  string `json:"mode"`
	LocalSourceSHA256     string `json:"local_source_sha256"`
	LocalClientPublicKey  string `json:"local_client_public_key"`
	ServerSourceSHA256    string `json:"server_source_sha256"`
	ServerClientPublicKey string `json:"server_client_public_key"`
	PeerPublicKey         string `json:"peer_public_key"`
}

func nodeChainPacketCandidatePair(position int, local, server *NodeProfile) (NodeChainPacketCandidatePair, error) {
	var empty NodeChainPacketCandidatePair
	if local == nil || server == nil || local.mode != server.mode || !NodeChainPrefixMode(local.mode) ||
		!packetPairLayerOff(local) || !packetPairLayerOff(server) ||
		!nodeChainPlanTransportEqual(local, server) {
		return empty, nodeChainServerError
	}
	localKey, peer, err := nodeChainPacketKeys(local)
	serverKey, serverPeer, other := nodeChainPacketKeys(server)
	if err != nil || other != nil || localKey == serverKey || peer != serverPeer ||
		predecessorText(local.profile, "id") != predecessorText(server.profile, "id") ||
		predecessorText(local.profile, "node_proof_id") != predecessorText(server.profile, "node_proof_id") {
		return empty, nodeChainServerError
	}
	pair := NodeChainPacketCandidatePair{position, predecessorText(local.profile, "id"), predecessorText(local.profile, "node_proof_id"), local.mode,
		local.source, localKey, server.source, serverKey, peer}
	return pair, pair.validateServer(server)
}
func (p NodeChainPacketCandidatePair) validateServer(server *NodeProfile) error {
	if server == nil || p.Position < 1 || p.Position > multihoprelay.NodeChainExtendedMaximumMembers ||
		!NodeChainPrefixMode(p.Mode) || p.Mode != server.mode || p.ProfileID != predecessorText(server.profile, "id") ||
		p.NodeID != predecessorText(server.profile, "node_proof_id") || !proofID.MatchString(p.LocalSourceSHA256) ||
		p.ServerSourceSHA256 != server.source || p.ServerSourceSHA256 == p.LocalSourceSHA256 ||
		!packetPairLayerOff(server) {
		return nodeChainServerError
	}
	client, peer, err := nodeChainPacketKeys(server)
	if err != nil || client != p.ServerClientPublicKey || peer != p.PeerPublicKey || p.LocalClientPublicKey == client ||
		p.LocalClientPublicKey == peer || !canonicalPacketPublic(p.LocalClientPublicKey) {
		return nodeChainServerError
	}
	return nil
}
func canonicalPacketPublic(key string) bool {
	return nodeChainCanonicalPeer(key)
}
func validateNodeChainPacketCandidatePairs(source NodeChainServerSource, nodes []*NodeProfile) error {
	if len(source.PacketCandidatePairs) > len(nodes) {
		return nodeChainServerError
	}
	positions, localSources, locals := map[int]bool{}, map[string]bool{}, map[string]bool{}
	native := map[string]bool{}
	for _, node := range nodes {
		if node == nil || !NodeChainPrefixMode(node.mode) {
			continue
		}
		client, peer, err := nodeChainPacketKeys(node)
		if err != nil {
			return nodeChainServerError
		}
		native[client], native[peer] = true, true
	}
	for _, pair := range source.PacketCandidatePairs {
		i := pair.Position - 1
		if i < 0 || i >= len(nodes) || positions[i] || localSources[pair.LocalSourceSHA256] || locals[pair.LocalClientPublicKey] ||
			pair.validateServer(nodes[i]) != nil || native[pair.LocalClientPublicKey] {
			return nodeChainServerError
		}
		positions[i], localSources[pair.LocalSourceSHA256], locals[pair.LocalClientPublicKey] = true, true, true
	}
	return nil
}

type nodeChainServerPacketCandidateInput struct {
	Schema             int                          `json:"schema"`
	RegistrationSHA256 string                       `json:"registration_sha256"`
	Pair               NodeChainPacketCandidatePair `json:"pair"`
	Input              string                       `json:"input"`
	IdentitySource     string                       `json:"identity_source"`
}

func (v nodeChainServerPacketCandidateInput) digest() string {
	raw, _ := json.Marshal([]any{"routervpn-operator-packet-candidate-pair-v1", v.RegistrationSHA256, v.Pair})
	defer clear(raw)
	return externalDigest(raw)
}

// CandidatePacketResponseInput resolves only an exact protected registration;
// the requester supplies a Local commitment and public key, never Server keys.
func (p *NodeChainServerPolicy) CandidatePacketResponseInput(c multihoprelay.NodeChainCandidateCapture) (string, error) {
	if p == nil || p.validateCapture() != nil || c.Validate() != nil || !c.Request.IsPacketResponse() ||
		p.descriptor.EntryNodeID != c.Lease.Source.EntryNodeID {
		return "", nodeChainServerError
	}
	var original NodeChainServerSource
	if exactJSON([]byte(p.sourceJSON), &original, NodeChainInputLimit) != nil {
		return "", nodeChainServerError
	}
	for _, pair := range original.PacketCandidatePairs {
		if pair.ProfileID != c.Request.CandidateID || pair.Mode != c.Request.CandidateMode ||
			pair.LocalSourceSHA256 != c.Request.CandidateSourceSHA256 || pair.LocalClientPublicKey != c.Request.CandidateClientPublicKey {
			continue
		}
		i := pair.Position - 1
		if i < 0 || i >= len(p.nodes) || pair.validateServer(p.nodes[i]) != nil {
			return "", nodeChainServerError
		}
		input, err := p.nodes[i].LaunchInput()
		if err != nil {
			return "", err
		}
		value := nodeChainServerPacketCandidateInput{1, p.sourceSHA, pair, input, original.IdentitySources[i]}
		raw, err := json.Marshal(value)
		if err != nil || len(raw) > NodeChainInputLimit {
			return "", nodeChainServerError
		}
		defer clear(raw)
		if _, err = NewNodeChainServerPacketCandidateResponder(c, string(raw)); err != nil {
			return "", err
		}
		return string(raw), nil
	}
	return "", nodeChainServerError
}

// PacketRuntimeKeys is public identity readback for the original process/key
// ledger. It does not return a dialer or any private transport credentials.
func (p *NodeChainServerPolicy) PacketRuntimeKeys() ([]string, error) {
	if p == nil || p.validateCapture() != nil {
		return nil, nodeChainServerError
	}
	var keys []string
	for _, node := range p.nodes {
		if node == nil || !NodeChainPrefixMode(node.mode) {
			continue
		}
		client, peer, err := nodeChainPacketKeys(node)
		if err != nil {
			return nil, err
		}
		keys = append(keys, client, peer)
	}
	return keys, nil
}

// Only one paired suffix is replaced. This pure compilation can reuse the
// original physical bound because its exact first source and target stay fixed.
func sameServerPacketReplacement(original *NodeChainServerPolicy, source NodeChainServerSource, position int) bool {
	return position > 0 && sameServerPacketReplacementAt(original, source, position)
}

func sameServerPacketReplacementAt(original *NodeChainServerPolicy, source NodeChainServerSource, position int) bool {
	if original == nil || original.validateCapture() != nil || position < 0 || position >= len(original.nodes)-1 {
		return false
	}
	var before NodeChainServerSource
	if exactJSON([]byte(original.sourceJSON), &before, NodeChainInputLimit) != nil ||
		len(source.Nodes) != len(before.Nodes) || len(source.IdentitySources) != len(before.IdentitySources) {
		return false
	}
	candidate, err := ParseNodeLaunchInput(source.Nodes[position])
	if err != nil || original.nodes[position] == nil || candidate.mode != original.nodes[position].mode ||
		!NodeChainPrefixMode(candidate.mode) || !packetPairLayerOff(candidate) {
		return false
	}
	var beforePairs, afterPairs []NodeChainPacketCandidatePair
	for _, pair := range before.PacketCandidatePairs {
		if pair.Position != position+1 {
			beforePairs = append(beforePairs, pair)
		}
	}
	replaced := false
	for _, pair := range source.PacketCandidatePairs {
		if pair.Position == position+1 {
			if replaced || pair.validateServer(candidate) != nil {
				return false
			}
			replaced = true
		} else {
			afterPairs = append(afterPairs, pair)
		}
	}
	if !replaced || !reflect.DeepEqual(beforePairs, afterPairs) {
		return false
	}
	copySource := source
	copySource.Nodes = append([]string(nil), source.Nodes...)
	copySource.IdentitySources = append([]string(nil), source.IdentitySources...)
	copySource.Nodes[position] = before.Nodes[position]
	copySource.IdentitySources[position] = before.IdentitySources[position]
	copySource.PacketCandidatePairs = before.PacketCandidatePairs
	return reflect.DeepEqual(copySource, before)
}

func packetPairLayerOff(node *NodeProfile) bool {
	if node == nil {
		return false
	}
	layer, _ := node.profile["start_layer"].(string)
	return layer == "" || layer == "off"
}
