package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"slices"

	"router-vpn/internal/multihoprelay"
)

const nodeChainPrefixSelectionCatalogKind = "routervpn-node-chain-prefix-selection-catalog"

type nodeChainPrefixSelectionCatalogRecord struct {
	Schema int               `json:"schema"`
	Kind   string            `json:"kind"`
	Entry  json.RawMessage   `json:"entry"`
	Pairs  []json.RawMessage `json:"pairs"`
}
type nodeChainPrefixSelectionCatalogPair struct {
	raw       json.RawMessage
	paired    json.RawMessage
	node      *NodeProfile
	member    multihoprelay.NodeChainPrefixMember
	candidate multihoprelay.NodeChainPrefixSelectionCandidate
}

// NodeChainServerPrefixCatalog holds only actually captured private plan rows.
// Selection never accepts a caller-authored descriptor or a Server source.
type NodeChainServerPrefixCatalog struct {
	self              *NodeChainServerPrefixCatalog
	source, sourceSHA string
	record            nodeChainPrefixSelectionCatalogRecord
	entry             *NodeProfile
	entryMember       multihoprelay.NodeChainPrefixMember
	peers             []string
	pairs             []nodeChainPrefixSelectionCatalogPair
}

func NewNodeChainServerPrefixCatalog(input string) (*NodeChainServerPrefixCatalog, error) {
	var root map[string]any
	if exactJSON([]byte(input), &root, NodeChainInputLimit) != nil ||
		!nodeChainPlanKeys(root, []string{"schema", "kind", "entry", "pairs"}, nil) ||
		(root["schema"] != float64(1) && root["schema"] != float64(2)) || root["kind"] != nodeChainPrefixSelectionCatalogKind {
		return nil, errNodeChainAppendExecution
	}
	entryRaw, entryOK := root["entry"].(map[string]any)
	pairsRaw, pairsOK := root["pairs"].([]any)
	if !entryOK || !pairsOK || len(pairsRaw) < 1 ||
		len(pairsRaw) > multihoprelay.NodeChainPrefixMaximumMembers-1+multihoprelay.NodeChainPrefixMaximumCandidates {
		return nil, errNodeChainAppendExecution
	}
	proxyEntry := root["schema"] == float64(2)
	entry, err := nodeChainPlanCapture(entryRaw)
	if err != nil {
		return nil, errNodeChainAppendExecution
	}
	member, peers, err := nodeChainPrefixPlanEntry(entry, proxyEntry)
	if err != nil || len(peers) == 0 {
		return nil, errNodeChainAppendExecution
	}
	entryJSON, err := json.Marshal(entryRaw)
	if err != nil {
		return nil, err
	}
	catalog := &NodeChainServerPrefixCatalog{entry: entry.node, entryMember: member, peers: slices.Clone(peers)}
	catalog.self = catalog
	catalog.record = nodeChainPrefixSelectionCatalogRecord{Schema: int(root["schema"].(float64)), Kind: nodeChainPrefixSelectionCatalogKind, Entry: entryJSON, Pairs: make([]json.RawMessage, 0, len(pairsRaw))}
	for _, value := range pairsRaw {
		row, ok := value.(map[string]any)
		if !ok || !nodeChainPlanKeys(row, []string{"paired", "server_peer"}, nil) {
			return nil, errNodeChainAppendExecution
		}
		pairedRaw, a := row["paired"].(map[string]any)
		peerRaw, b := row["server_peer"].(map[string]any)
		if !a || !b || !nodeChainPlanKeys(peerRaw, []string{"bundle", "profile_id"}, nil) {
			return nil, errNodeChainAppendExecution
		}
		paired, err := nodeChainPlanCapture(pairedRaw)
		if err != nil || paired.node == nil || !packetPairLayerOff(paired.node) || proxyEntry && paired.mode != "shadowsocks" ||
			!NodeChainPrefixMode(paired.mode) && paired.mode != "shadowsocks" && paired.mode != "hysteria2" {
			return nil, errNodeChainAppendExecution
		}
		bundle, profile, err := nodeChainPlanSelectedBundle(peerRaw["bundle"], peerRaw["profile_id"])
		if err != nil {
			return nil, err
		}
		for _, key := range []string{"node_proof_id", "endpoint", "router_api"} {
			if !reflect.DeepEqual(paired.profile[key], profile[key]) {
				return nil, errNodeChainAppendExecution
			}
		}
		server, err := nodeChainPlanNodeFromBundle(bundle, paired.profile, paired.mode, paired.bootstrap)
		if err != nil || server.node == nil || paired.identityKey == server.identityKey ||
			!nodeChainPlanTransportEqual(paired.node, server.node) {
			return nil, errNodeChainAppendExecution
		}
		localMember, err := nodeChainPrefixCapturedMember(paired.node, paired.identity, 1, 5)
		if err != nil {
			return nil, err
		}
		serverMember, err := nodeChainPrefixCapturedMember(server.node, server.identity, 1, 5)
		if err != nil || localMember.ProfileID == member.ProfileID || localMember.NodeID == member.NodeID ||
			localMember.ProfileID != serverMember.ProfileID || localMember.NodeID != serverMember.NodeID || localMember.Mode != serverMember.Mode {
			return nil, errNodeChainAppendExecution
		}
		selected := multihoprelay.NodeChainPrefixSelectionCandidate{ProfileID: localMember.ProfileID, NodeID: localMember.NodeID, Mode: localMember.Mode, StartLayer: "off", SourceSHA256: localMember.SourceSHA256}
		if NodeChainPrefixMode(paired.mode) {
			pair, err := nodeChainPrefixPacketPair(1, paired.node, server.node)
			if err != nil {
				return nil, err
			}
			selected.TransportSHA256, selected.ClientPublicKey, selected.ServerPublicKey = pair.TransportSHA256, pair.LocalClientPublicKey, pair.PeerPublicKey
		} else {
			if localMember.TransportSHA256 == "" || localMember.TransportSHA256 != serverMember.TransportSHA256 ||
				localMember.CompanionSHA256 == "" || serverMember.CompanionSHA256 == "" ||
				localMember.CompanionSHA256 == serverMember.CompanionSHA256 ||
				localMember.CompanionClientPublicKey == serverMember.CompanionClientPublicKey ||
				localMember.CompanionServerPublicKey != serverMember.CompanionServerPublicKey {
				return nil, errNodeChainAppendExecution
			}
			if paired.mode == "hysteria2" {
				selected.TransportSHA256, selected.CompanionSHA256 = localMember.TransportSHA256, localMember.CompanionSHA256
				selected.CompanionClientPublicKey, selected.CompanionServerPublicKey = localMember.CompanionClientPublicKey, localMember.CompanionServerPublicKey
			}
		}
		// Alternative modes may be cataloged for the same actual node. An identical
		// Local selector may never choose between two independent private owners.
		for _, previous := range catalog.pairs {
			if previous.member == localMember || previous.candidate == selected {
				return nil, errNodeChainAppendExecution
			}
		}
		raw, err := json.Marshal(row)
		if err != nil {
			return nil, err
		}
		localRaw, err := json.Marshal(pairedRaw)
		if err != nil {
			return nil, err
		}
		catalog.record.Pairs = append(catalog.record.Pairs, raw)
		catalog.pairs = append(catalog.pairs, nodeChainPrefixSelectionCatalogPair{raw: raw, paired: localRaw, node: paired.node, member: localMember, candidate: selected})
	}
	raw, err := json.Marshal(catalog.record)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, errNodeChainAppendExecution
	}
	catalog.source = string(raw)
	catalog.sourceSHA, err = nodeChainAppendExecutionDigest(nodeChainPrefixCatalogDomain(catalog.record.Schema), catalog.record)
	if err != nil {
		return nil, err
	}
	return catalog, nil
}
func (c *NodeChainServerPrefixCatalog) valid() bool {
	if c == nil || c.self != c || c.entry == nil || c.source == "" || c.sourceSHA == "" || c.record.Schema != 1 && c.record.Schema != 2 ||
		len(c.pairs) != len(c.record.Pairs) || len(c.pairs) == 0 {
		return false
	}
	raw, err := json.Marshal(c.record)
	if err != nil || string(raw) != c.source {
		return false
	}
	if c.record.Schema == 2 {
		peers, err := nodeChainPrefixProxyEntryPeers(c.entry)
		if err != nil || len(c.peers) != 1 || c.peers[0] != peers[0] || c.entryMember.Mode != "shadowsocks" {
			return false
		}
	}
	digest, err := nodeChainAppendExecutionDigest(nodeChainPrefixCatalogDomain(c.record.Schema), c.record)
	return err == nil && digest == c.sourceSHA
}
func (c *NodeChainServerPrefixCatalog) Source() string {
	if !c.valid() {
		return ""
	}
	return c.source
}
func (c *NodeChainServerPrefixCatalog) SourceSHA256() string {
	if !c.valid() {
		return ""
	}
	return c.sourceSHA
}
func (c *NodeChainServerPrefixCatalog) Reference() multihoprelay.NodeChainPrefixCatalogReference {
	if !c.valid() {
		return multihoprelay.NodeChainPrefixCatalogReference{}
	}
	return multihoprelay.NodeChainPrefixCatalogReference{Schema: 1, EntryNodeID: c.entryMember.NodeID, SourceSHA256: c.sourceSHA}
}
func (c *NodeChainServerPrefixCatalog) EntryNodeID() string {
	if !c.valid() {
		return ""
	}
	return c.entryMember.NodeID
}
func (c *NodeChainServerPrefixCatalog) EntryPeerAddresses() []string {
	if !c.valid() {
		return nil
	}
	return slices.Clone(c.peers)
}

func (c *NodeChainServerPrefixCatalog) Select(q multihoprelay.NodeChainPrefixSelectionRequest) (*NodeChainServerPrefixPolicy, error) {
	q = q.Clone()
	if !c.valid() || q.Validate() != nil || q.Schema != c.record.Schema || q.CatalogSHA256 != c.sourceSHA ||
		q.EntryNodeID != c.entryMember.NodeID || q.LocalPrefix[0] != c.entryMember ||
		!slices.Contains(c.peers, q.Peer) {
		return nil, errNodeChainAppendExecution
	}
	nodes := []*NodeProfile{c.entry}
	members := make([]json.RawMessage, 0, len(q.LocalPrefix)-1)
	candidates := make([]json.RawMessage, 0, len(q.Candidates))
	for position, wanted := range q.LocalPrefix[1:] {
		matches := 0
		for _, pair := range c.pairs {
			actual := pair.member
			actual.Position = position + 1
			if actual != wanted {
				continue
			}
			matches++
			members = append(members, append(json.RawMessage(nil), pair.raw...))
			nodes = append(nodes, pair.node)
		}
		if matches != 1 {
			return nil, errNodeChainAppendExecution
		}
	}
	for _, wanted := range q.Candidates {
		matches := 0
		for _, pair := range c.pairs {
			if pair.candidate != wanted {
				continue
			}
			matches++
			row := pair.raw
			if wanted.Mode == "shadowsocks" {
				row = pair.paired
			}
			candidates = append(candidates, append(json.RawMessage(nil), row...))
		}
		if matches != 1 {
			return nil, errNodeChainAppendExecution
		}
	}
	_, schema, err := nodeChainPrefixExecutionSchemas(nodes, q.Candidates[0].Mode)
	if err != nil {
		return nil, err
	}
	plan := struct {
		Schema      int               `json:"schema"`
		Purpose     string            `json:"purpose"`
		EntryNodeID string            `json:"entry_node_id"`
		Entry       json.RawMessage   `json:"entry"`
		Members     []json.RawMessage `json:"members"`
		Candidates  []json.RawMessage `json:"candidates"`
	}{schema, multihoprelay.NodeChainPrefixPurpose, c.entryMember.NodeID, append(json.RawMessage(nil), c.record.Entry...), members, candidates}
	raw, err := json.Marshal(plan)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, errNodeChainAppendExecution
	}
	policy, err := NewNodeChainServerPrefixPlan(string(raw))
	if err != nil {
		return nil, err
	}
	descriptor, err := policy.Descriptor()
	if err != nil || !q.MatchesSelectedDescriptor(descriptor) {
		return nil, errNodeChainAppendExecution
	}
	return policy, nil
}
