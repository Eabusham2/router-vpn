package mobilemultihop

import (
	"reflect"
	"router-vpn/internal/multihoprelay"
)

// HY2 has its own unfinished-prefix source commitment. A genuine packet
// companion identifies the paired node; it is not a selected HY2 packet key.
type nodeChainAppendExecutionHysteriaIdentity struct {
	Position                                                            int
	ProfileID, NodeID, Mode, SourceSHA256, TransportSHA256              string
	CompanionSHA256, CompanionClientPublicKey, CompanionServerPublicKey string
}

func nodeChainPrefixHysteriaSchemas(nodes []*NodeProfile, nextMode string) (int, int, error) {
	if len(nodes) < 1 || len(nodes) > multihoprelay.NodeChainPrefixMaximumMembers || nodes[0] == nil ||
		!NodeChainPrefixMode(nodes[0].mode) || nextMode != "hysteria2" && nextMode != "shadowsocks" {
		return 0, 0, errNodeChainAppendExecution
	}
	local, hysteria := 1, false
	for _, node := range nodes {
		if node == nil || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
			return 0, 0, errNodeChainAppendExecution
		}
		if NodeChainPrefixMode(node.mode) {
			if hysteria {
				return 0, 0, errNodeChainAppendExecution
			}
			continue
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil {
			return 0, 0, errNodeChainAppendExecution
		}
		switch node.mode {
		case "shadowsocks":
			if !nodeChainCapturedSSClosure(closure) {
				return 0, 0, errNodeChainAppendExecution
			}
		case "hysteria2":
			if !nodeChainCapturedHysteriaClosure(node, closure) {
				return 0, 0, errNodeChainAppendExecution
			}
			hysteria = true
		default:
			return 0, 0, errNodeChainAppendExecution
		}
		local = 2
	}
	if !hysteria && nextMode != "hysteria2" {
		return 0, 0, errNodeChainAppendExecution
	}
	return local, 5, nil
}

func nodeChainPrefixHasHysteriaCandidates(source NodeChainServerPrefixSource) bool {
	return source.Schema == 5 && source.HysteriaCandidatePairs != nil
}

func nodeChainPrefixHysteriaTransport(node *NodeProfile) (string, error) {
	if node == nil || node.mode != "hysteria2" || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
		return "", errNodeChainAppendExecution
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil || !nodeChainCapturedHysteriaClosure(node, closure) {
		return "", errNodeChainAppendExecution
	}
	var graph map[string]any
	if exactJSON([]byte(node.Config()), &graph, 4<<20) != nil {
		return "", errNodeChainAppendExecution
	}
	// No client, TLS, credential, QUIC, address or configured MTU field is
	// removed. Both genuine selected transports must be exactly the same.
	return nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-hysteria-transport-v1", []any{node.mode, graph})
}

func nodeChainPrefixHysteriaIdentity(position int, node *NodeProfile, identity string) (nodeChainAppendExecutionHysteriaIdentity, error) {
	var empty nodeChainAppendExecutionHysteriaIdentity
	if position < 1 || position > multihoprelay.NodeChainPrefixMaximumMembers || node == nil ||
		validateNodeChainIdentity(identity, node) != nil {
		return empty, errNodeChainAppendExecution
	}
	transport, err := nodeChainPrefixHysteriaTransport(node)
	if err != nil {
		return empty, err
	}
	assets, err := nodeProfileAssets(identity)
	if err != nil {
		return empty, err
	}
	defer clearNodeChainIdentityAssets(assets)
	companion, err := nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-hysteria-companion-v1", assets)
	if err != nil {
		return empty, err
	}
	client, server, err := chainCompanionKeys(identity, node.profile)
	if err != nil || client == server {
		return empty, errNodeChainAppendExecution
	}
	return nodeChainAppendExecutionHysteriaIdentity{Position: position,
		ProfileID: predecessorText(node.profile, "id"), NodeID: predecessorText(node.profile, "node_proof_id"),
		Mode: node.mode, SourceSHA256: node.source, TransportSHA256: transport,
		CompanionSHA256: companion, CompanionClientPublicKey: client, CompanionServerPublicKey: server}, nil
}

func nodeChainPrefixHysteriaMember(node *NodeProfile, identity string, position int) (multihoprelay.NodeChainPrefixMember, error) {
	v, err := nodeChainPrefixHysteriaIdentity(position, node, identity)
	if err != nil {
		return multihoprelay.NodeChainPrefixMember{}, err
	}
	return multihoprelay.NodeChainPrefixMember{Position: v.Position, ProfileID: v.ProfileID, NodeID: v.NodeID,
		Mode: v.Mode, StartLayer: "off", SourceSHA256: v.SourceSHA256, TransportSHA256: v.TransportSHA256,
		CompanionSHA256: v.CompanionSHA256, CompanionClientPublicKey: v.CompanionClientPublicKey,
		CompanionServerPublicKey: v.CompanionServerPublicKey}, nil
}

func (v nodeChainAppendExecutionHysteriaIdentity) matches(pair multihoprelay.NodeChainPrefixHysteriaCandidatePair) bool {
	return pair.Validate() == nil && pair.Position == v.Position && pair.ProfileID == v.ProfileID &&
		pair.NodeID == v.NodeID && pair.Mode == v.Mode && pair.LocalSourceSHA256 == v.SourceSHA256 &&
		pair.TransportSHA256 == v.TransportSHA256 && pair.LocalCompanionSHA256 == v.CompanionSHA256 &&
		pair.LocalCompanionClientPublicKey == v.CompanionClientPublicKey && pair.CompanionServerPublicKey == v.CompanionServerPublicKey
}

func nodeChainPrefixHysteriaPair(position int, local *NodeProfile, localIdentity string, server *NodeProfile, serverIdentity string) (multihoprelay.NodeChainPrefixHysteriaCandidatePair, error) {
	var empty multihoprelay.NodeChainPrefixHysteriaCandidatePair
	a, err := nodeChainPrefixHysteriaIdentity(position, local, localIdentity)
	b, other := nodeChainPrefixHysteriaIdentity(position, server, serverIdentity)
	if err != nil || other != nil || a.ProfileID != b.ProfileID || a.NodeID != b.NodeID || a.Mode != b.Mode ||
		a.TransportSHA256 != b.TransportSHA256 || a.CompanionServerPublicKey != b.CompanionServerPublicKey ||
		a.CompanionSHA256 == b.CompanionSHA256 || a.CompanionClientPublicKey == b.CompanionClientPublicKey {
		return empty, errNodeChainAppendExecution
	}
	pair := multihoprelay.NodeChainPrefixHysteriaCandidatePair{Position: position, ProfileID: a.ProfileID, NodeID: a.NodeID, Mode: a.Mode,
		LocalSourceSHA256: a.SourceSHA256, ServerSourceSHA256: b.SourceSHA256, TransportSHA256: a.TransportSHA256,
		LocalCompanionSHA256: a.CompanionSHA256, ServerCompanionSHA256: b.CompanionSHA256,
		LocalCompanionClientPublicKey: a.CompanionClientPublicKey, ServerCompanionClientPublicKey: b.CompanionClientPublicKey,
		CompanionServerPublicKey: a.CompanionServerPublicKey}
	return pair, pair.Validate()
}

func nodeChainPrefixHysteriaServerMatches(pair multihoprelay.NodeChainPrefixHysteriaCandidatePair, node *NodeProfile, identity string) bool {
	if pair.Validate() != nil {
		return false
	}
	v, err := nodeChainPrefixHysteriaIdentity(pair.Position, node, identity)
	return err == nil && pair.ProfileID == v.ProfileID && pair.NodeID == v.NodeID && pair.Mode == v.Mode &&
		pair.ServerSourceSHA256 == v.SourceSHA256 && pair.TransportSHA256 == v.TransportSHA256 &&
		pair.ServerCompanionSHA256 == v.CompanionSHA256 && pair.ServerCompanionClientPublicKey == v.CompanionClientPublicKey &&
		pair.CompanionServerPublicKey == v.CompanionServerPublicKey
}

// HysteriaCandidateRuntimeIdentity is original captured identity only. It
// cannot create a QUIC client or turn a companion into a packet reservation.
func (p *NodeChainServerPrefixPolicy) HysteriaCandidateRuntimeIdentity(c multihoprelay.NodeChainPrefixCandidateCapture) (string, error) {
	if p == nil || p.validate() != nil || p.record.Schema != 5 || p.BindCapture(c.Lease) != nil {
		return "", errNodeChainAppendExecution
	}
	pair, err := c.HysteriaPair()
	if err != nil {
		return "", err
	}
	for i, original := range p.record.HysteriaCandidatePairs {
		if original != pair || i >= len(p.candidates) || i >= len(p.record.CandidateIdentitySources) ||
			!nodeChainPrefixHysteriaServerMatches(pair, p.candidates[i], p.record.CandidateIdentitySources[i]) {
			continue
		}
		if _, err := p.candidate(c); err != nil {
			return "", err
		}
		return pair.Digest()
	}
	return "", errNodeChainAppendExecution
}

// Only a genuine paired HY2 append inventory may carry companions. The full
// original inventory string is still captured and sealed by the old plan.
func validateNodeChainAppendHysteriaInventory(source *NodeChainCandidateAppendSource, record NodeChainCandidateInventory, transportKeys map[string]bool) error {
	if record.IdentitySources == nil {
		return nil
	}
	if source == nil || source.record.NextKind != "" || source.record.NextMode != "hysteria2" || record.ResponseMode != "hysteria2" ||
		len(record.Inputs) < 1 || len(record.Inputs) > multihoprelay.NodeChainPrefixMaximumCandidates || len(record.IdentitySources) != len(record.Inputs) {
		return errNodeChainAppendExecution
	}
	keys, companions := make(map[string]bool), make(map[string]bool)
	for key := range transportKeys {
		keys[key] = true
	}
	for i, node := range source.nodes {
		if node == nil || source.imports[i] != nil || !packetPairLayerOff(node) {
			return errNodeChainAppendExecution
		}
		if NodeChainPrefixMode(node.mode) {
			continue
		}
		identity := source.record.IdentitySources[i]
		if validateNodeChainIdentity(identity, node) != nil {
			return errNodeChainAppendExecution
		}
		client, server, err := chainCompanionKeys(identity, node.profile)
		if err != nil || keys[client] || keys[server] {
			return errNodeChainAppendExecution
		}
		keys[client], keys[server] = true, true
		assets, err := nodeProfileAssets(identity)
		if err != nil {
			return err
		}
		digest, err := nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-hysteria-companion-v1", assets)
		clearNodeChainIdentityAssets(assets)
		if err != nil || companions[digest] {
			return errNodeChainAppendExecution
		}
		companions[digest] = true
	}
	for i, input := range record.Inputs {
		node, err := ParseNodeLaunchInput(input)
		if err != nil {
			return errNodeChainAppendExecution
		}
		v, err := nodeChainPrefixHysteriaIdentity(len(source.nodes), node, record.IdentitySources[i])
		if err != nil || keys[v.CompanionClientPublicKey] || keys[v.CompanionServerPublicKey] || companions[v.CompanionSHA256] {
			return errNodeChainAppendExecution
		}
		keys[v.CompanionClientPublicKey], keys[v.CompanionServerPublicKey], companions[v.CompanionSHA256] = true, true, true
	}
	return nil
}

// The six-key operator keeps genuine selected Local and independent Server
// bundles. This helper derives a HY2 pair; it accepts no public digest input.
func nodeChainPrefixHysteriaPlanPair(row map[string]any, position int) (*nodeChainPlanNode, *nodeChainPlanNode, multihoprelay.NodeChainPrefixHysteriaCandidatePair, error) {
	var empty multihoprelay.NodeChainPrefixHysteriaCandidatePair
	fail := func() (*nodeChainPlanNode, *nodeChainPlanNode, multihoprelay.NodeChainPrefixHysteriaCandidatePair, error) {
		return nil, nil, empty, errNodeChainAppendExecution
	}
	if !nodeChainPlanKeys(row, []string{"paired", "server_peer"}, nil) {
		return fail()
	}
	pairedRaw, a := row["paired"].(map[string]any)
	peerRaw, b := row["server_peer"].(map[string]any)
	if !a || !b || !nodeChainPlanKeys(peerRaw, []string{"bundle", "profile_id"}, nil) {
		return fail()
	}
	paired, err := nodeChainPlanCapture(pairedRaw)
	if err != nil || paired.mode != "hysteria2" || !packetPairLayerOff(paired.node) {
		return fail()
	}
	bundle, profile, err := nodeChainPlanSelectedBundle(peerRaw["bundle"], peerRaw["profile_id"])
	if err != nil {
		return fail()
	}
	for _, key := range []string{"node_proof_id", "endpoint", "router_api"} {
		if !reflect.DeepEqual(paired.profile[key], profile[key]) {
			return fail()
		}
	}
	server, err := nodeChainPlanNodeFromBundle(bundle, paired.profile, paired.mode, paired.bootstrap)
	if err != nil || paired.identityKey == server.identityKey || !nodeChainPlanTransportEqual(paired.node, server.node) {
		return fail()
	}
	pair, err := nodeChainPrefixHysteriaPair(position, paired.node, paired.identity, server.node, server.identity)
	if err != nil {
		return fail()
	}
	return paired, server, pair, nil
}
