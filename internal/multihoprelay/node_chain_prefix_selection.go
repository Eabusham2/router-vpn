package multihoprelay

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
)

const NodeChainPrefixSelectionPurpose = "draft-prefix-append-selection"
const NodeChainPrefixSelectionMaximumBytes = 256 << 10

type NodeChainPrefixCatalogReference struct {
	Schema       int    `json:"schema"`
	EntryNodeID  string `json:"entry_node_id"`
	SourceSHA256 string `json:"source_sha256"`
}
type NodeChainPrefixSelectionCapability struct {
	Reference        NodeChainPrefixCatalogReference `json:"reference"`
	GenerationSHA256 string                          `json:"generation_sha256"`
	Challenge        ExternalPacketChallenge         `json:"challenge"`
}
type NodeChainPrefixSelectionDiscovery struct {
	Schema         int                                 `json:"schema"`
	Purpose        string                              `json:"purpose"`
	NodeID         string                              `json:"node_id"`
	StaticPrefixes []NodeChainPrefixDescriptor         `json:"static_prefixes"`
	Catalog        *NodeChainPrefixSelectionCapability `json:"catalog,omitempty"`
}
type NodeChainPrefixSelectionCandidate struct {
	ProfileID                string `json:"profile_id"`
	NodeID                   string `json:"node_id"`
	Mode                     string `json:"mode"`
	StartLayer               string `json:"start_layer"`
	SourceSHA256             string `json:"source_sha256"`
	TransportSHA256          string `json:"transport_sha256,omitempty"`
	ClientPublicKey          string `json:"client_public_key,omitempty"`
	ServerPublicKey          string `json:"server_public_key,omitempty"`
	CompanionSHA256          string `json:"companion_sha256,omitempty"`
	CompanionClientPublicKey string `json:"companion_client_public_key,omitempty"`
	CompanionServerPublicKey string `json:"companion_server_public_key,omitempty"`
}
type NodeChainPrefixSelectionRequest struct {
	Schema                  int                                 `json:"schema"`
	Purpose                 string                              `json:"purpose"`
	EntryNodeID             string                              `json:"entry_node_id"`
	CatalogSHA256           string                              `json:"catalog_sha256"`
	CatalogGenerationSHA256 string                              `json:"catalog_generation_sha256"`
	Peer                    string                              `json:"peer"`
	Epoch                   string                              `json:"epoch"`
	AcquireExpiresAt        int64                               `json:"acquire_expires_at"`
	Nonce                   string                              `json:"nonce"`
	ExecutionSourceSHA256   string                              `json:"execution_source_sha256"`
	OriginalSourceSHA256    string                              `json:"original_source_sha256"`
	InventorySHA256         string                              `json:"inventory_sha256"`
	AppendPosition          int                                 `json:"append_position"`
	LocalPrefix             []NodeChainPrefixMember             `json:"local_prefix"`
	Candidates              []NodeChainPrefixSelectionCandidate `json:"candidates"`
}
type NodeChainPrefixSelectionReceipt struct {
	Schema                  int    `json:"schema"`
	Purpose                 string `json:"purpose"`
	RequestSHA256           string `json:"request_sha256"`
	CatalogSHA256           string `json:"catalog_sha256"`
	CatalogGenerationSHA256 string `json:"catalog_generation_sha256"`
	Phase                   string `json:"phase"`
	Publication             bool   `json:"publication"`
	SourceSHA256            string `json:"source_sha256,omitempty"`
	DescriptorSHA256        string `json:"descriptor_sha256,omitempty"`
}
type NodeChainPrefixSelectionSource interface {
	Request() NodeChainPrefixSelectionRequest
	Descriptor() NodeChainPrefixDescriptor
	CatalogSHA256() string
	GenerationSHA256() string
	CurrentContext(context.Context) error
	CloseContext(context.Context) error
}
type NodeChainPrefixSelectionCatalog interface {
	Reference() NodeChainPrefixCatalogReference
	GenerationSHA256() string
	EntryPeerAddresses() []string
	CurrentContext(context.Context) error
	SelectContext(context.Context, NodeChainPrefixSelectionRequest) (NodeChainPrefixSelectionSource, error)
	CloseContext(context.Context) error
}
type NodeChainPrefixSelectionRunner interface {
	NodeChainPrefixRunner
	PrefixSelectionCatalog() NodeChainPrefixSelectionCatalog
	StartSelectedPrefix(context.Context, NodeChainPrefixCapture, NodeChainPrefixSelectionSource) (NodeChainPrefixProcess, error)
}

func (r NodeChainPrefixCatalogReference) Validate() error {
	if r.Schema != 1 || !proofID.MatchString(r.EntryNodeID) || !proofID.MatchString(r.SourceSHA256) {
		return errNodeChainPrefix
	}
	return nil
}
func (r NodeChainPrefixCatalogReference) Clone() NodeChainPrefixCatalogReference { return r }
func (r *NodeChainPrefixCatalogReference) UnmarshalJSON(raw []byte) error {
	if r == nil {
		return errNodeChainPrefix
	}
	type value NodeChainPrefixCatalogReference
	var v value
	if decodeNodeChainPrefixSelectionJSON(raw, &v, NodeChainPrefixSelectionMaximumBytes) != nil {
		return errNodeChainPrefix
	}
	result := NodeChainPrefixCatalogReference(v)
	if result.Validate() != nil {
		return errNodeChainPrefix
	}
	*r = result
	return nil
}
func NodeChainPrefixSelectionGeneration(catalogSHA256, nonce string) (string, error) {
	if !proofID.MatchString(catalogSHA256) || !proofID.MatchString(nonce) {
		return "", errNodeChainPrefix
	}
	return nodeChainDigest("routervpn-node-chain-prefix-selection-catalog-generation-v1", struct {
		CatalogSHA256 string `json:"catalog_sha256"`
		Nonce         string `json:"nonce"`
	}{catalogSHA256, nonce})
}
func (c NodeChainPrefixSelectionCapability) Validate() error {
	if c.Reference.Validate() != nil || !proofID.MatchString(c.GenerationSHA256) ||
		c.Challenge.Validate() != nil || !nodeChainPrivateAddress(c.Challenge.Peer) {
		return errNodeChainPrefix
	}
	return nil
}
func (c NodeChainPrefixSelectionCapability) Clone() NodeChainPrefixSelectionCapability { return c }
func (d NodeChainPrefixSelectionDiscovery) Validate() error {
	if d.Schema != 1 || d.Purpose != NodeChainPrefixSelectionPurpose || !proofID.MatchString(d.NodeID) ||
		d.StaticPrefixes == nil || len(d.StaticPrefixes) > MaxPairedExits {
		return errNodeChainPrefix
	}
	if d.Catalog != nil && (d.Catalog.Validate() != nil || d.Catalog.Reference.EntryNodeID != d.NodeID) {
		return errNodeChainPrefix
	}
	seen := map[string]bool{}
	for _, descriptor := range d.StaticPrefixes {
		digest, err := descriptor.Digest()
		if err != nil || descriptor.EntryNodeID != d.NodeID || seen[digest] || seen[descriptor.SourceSHA256] {
			return errNodeChainPrefix
		}
		seen[digest], seen[descriptor.SourceSHA256] = true, true
	}
	return nil
}
func (d NodeChainPrefixSelectionDiscovery) Clone() NodeChainPrefixSelectionDiscovery {
	if d.StaticPrefixes != nil {
		result := make([]NodeChainPrefixDescriptor, len(d.StaticPrefixes))
		for i, descriptor := range d.StaticPrefixes {
			result[i] = descriptor.Clone()
		}
		d.StaticPrefixes = result
	}
	if d.Catalog != nil {
		c := d.Catalog.Clone()
		d.Catalog = &c
	}
	return d
}
func (c NodeChainPrefixSelectionCandidate) valid(mode string) bool {
	if !prefixProfileID(c.ProfileID) || !proofID.MatchString(c.NodeID) || c.Mode != mode ||
		c.StartLayer != "off" || !proofID.MatchString(c.SourceSHA256) {
		return false
	}
	switch {
	case mode == "shadowsocks":
		return c.TransportSHA256 == "" && c.ClientPublicKey == "" && c.ServerPublicKey == "" &&
			c.CompanionSHA256 == "" && c.CompanionClientPublicKey == "" && c.CompanionServerPublicKey == ""
	case nodeChainPacketMode(mode):
		return proofID.MatchString(c.TransportSHA256) && nodeChainPacketPublic(c.ClientPublicKey) &&
			nodeChainPacketPublic(c.ServerPublicKey) && c.ClientPublicKey != c.ServerPublicKey &&
			c.CompanionSHA256 == "" && c.CompanionClientPublicKey == "" && c.CompanionServerPublicKey == ""
	case mode == "hysteria2":
		return proofID.MatchString(c.TransportSHA256) && proofID.MatchString(c.CompanionSHA256) &&
			nodeChainPacketPublic(c.CompanionClientPublicKey) && nodeChainPacketPublic(c.CompanionServerPublicKey) &&
			c.CompanionClientPublicKey != c.CompanionServerPublicKey && c.ClientPublicKey == "" && c.ServerPublicKey == ""
	}
	return false
}
func (q NodeChainPrefixSelectionRequest) Validate() error {
	challenge := ExternalPacketChallenge{Epoch: q.Epoch, Peer: q.Peer, ExpiresAt: q.AcquireExpiresAt}
	if q.Schema != 1 || q.Purpose != NodeChainPrefixSelectionPurpose || !proofID.MatchString(q.EntryNodeID) ||
		!proofID.MatchString(q.CatalogSHA256) || !proofID.MatchString(q.CatalogGenerationSHA256) ||
		!proofID.MatchString(q.Nonce) || !proofID.MatchString(q.ExecutionSourceSHA256) ||
		!proofID.MatchString(q.OriginalSourceSHA256) || !proofID.MatchString(q.InventorySHA256) ||
		challenge.Validate() != nil || !nodeChainPrivateAddress(q.Peer) ||
		len(q.LocalPrefix) < 1 || len(q.LocalPrefix) > NodeChainPrefixMaximumMembers || q.AppendPosition != len(q.LocalPrefix) ||
		len(q.Candidates) < 1 || len(q.Candidates) > NodeChainPrefixMaximumCandidates ||
		!q.LocalPrefix[0].valid(0) || q.LocalPrefix[0].NodeID != q.EntryNodeID {
		return errNodeChainPrefix
	}
	ids, nodes, sources, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	companions, transports := map[string]bool{}, map[string]bool{}
	hysteria := false
	for i, member := range q.LocalPrefix {
		if nodeChainPacketMode(member.Mode) {
			if hysteria || !member.valid(i) {
				return errNodeChainPrefix
			}
		} else {
			if !member.validHysteriaStream(i) || companions[member.CompanionSHA256] || transports[member.TransportSHA256] {
				return errNodeChainPrefix
			}
			hysteria = hysteria || member.Mode == "hysteria2"
			companions[member.CompanionSHA256], transports[member.TransportSHA256] = true, true
		}
		client, server := member.hysteriaIdentityKeys()
		if ids[member.ProfileID] || nodes[member.NodeID] || sources[member.SourceSHA256] || keys[client] || keys[server] {
			return errNodeChainPrefix
		}
		ids[member.ProfileID], nodes[member.NodeID], sources[member.SourceSHA256] = true, true, true
		keys[client], keys[server] = true, true
	}
	mode := q.Candidates[0].Mode
	if hysteria && nodeChainPacketMode(mode) {
		return errNodeChainPrefix
	}
	for _, candidate := range q.Candidates {
		if !candidate.valid(mode) || ids[candidate.ProfileID] || nodes[candidate.NodeID] || sources[candidate.SourceSHA256] {
			return errNodeChainPrefix
		}
		ids[candidate.ProfileID], nodes[candidate.NodeID], sources[candidate.SourceSHA256] = true, true, true
		if mode == "shadowsocks" {
			continue
		}
		client, server := candidate.ClientPublicKey, candidate.ServerPublicKey
		if mode == "hysteria2" {
			if companions[candidate.CompanionSHA256] {
				return errNodeChainPrefix
			}
			companions[candidate.CompanionSHA256] = true
			client, server = candidate.CompanionClientPublicKey, candidate.CompanionServerPublicKey
		}
		if transports[candidate.TransportSHA256] || keys[client] || keys[server] {
			return errNodeChainPrefix
		}
		transports[candidate.TransportSHA256], keys[client], keys[server] = true, true, true
	}
	return nil
}
func (q NodeChainPrefixSelectionRequest) Clone() NodeChainPrefixSelectionRequest {
	q.LocalPrefix = slices.Clone(q.LocalPrefix)
	q.Candidates = slices.Clone(q.Candidates)
	return q
}
func (q NodeChainPrefixSelectionRequest) Digest() (string, error) {
	if q.Validate() != nil {
		return "", errNodeChainPrefix
	}
	return nodeChainDigest("routervpn-node-chain-prefix-selection-request-v1", q)
}
func (q NodeChainPrefixSelectionRequest) MatchesCapability(c NodeChainPrefixSelectionCapability) bool {
	return q.Validate() == nil && c.Validate() == nil &&
		q.EntryNodeID == c.Reference.EntryNodeID && q.CatalogSHA256 == c.Reference.SourceSHA256 &&
		q.CatalogGenerationSHA256 == c.GenerationSHA256 && q.Peer == c.Challenge.Peer &&
		q.Epoch == c.Challenge.Epoch && q.AcquireExpiresAt == c.Challenge.ExpiresAt
}
func prefixSelectionLocalDescriptor(q NodeChainPrefixSelectionRequest, d NodeChainPrefixDescriptor) bool {
	return q.Validate() == nil && d.Validate() == nil && d.EntryNodeID == q.EntryNodeID &&
		slices.Contains(d.EntryPeerAddresses, q.Peer) && slices.Equal(d.LocalPrefix, q.LocalPrefix)
}
func prefixSelectionCandidateMatches(selected NodeChainPrefixSelectionCandidate, d NodeChainPrefixDescriptor, i int) bool {
	c := d.Candidates[i]
	if c.ProfileID != selected.ProfileID || c.NodeID != selected.NodeID || c.Mode != selected.Mode ||
		c.StartLayer != selected.StartLayer || c.SourceSHA256 != selected.SourceSHA256 {
		return false
	}
	if nodeChainPacketMode(c.Mode) {
		if len(d.PacketCandidatePairs) != len(d.Candidates) {
			return false
		}
		pair := d.PacketCandidatePairs[i]
		return pair.Position == len(d.LocalPrefix) && pair.LocalSourceSHA256 == selected.SourceSHA256 &&
			pair.LocalClientPublicKey == selected.ClientPublicKey && pair.PeerPublicKey == selected.ServerPublicKey &&
			pair.TransportSHA256 == selected.TransportSHA256
	}
	if c.Mode == "hysteria2" {
		if len(d.HysteriaCandidatePairs) != len(d.Candidates) {
			return false
		}
		pair := d.HysteriaCandidatePairs[i]
		return pair.Position == len(d.LocalPrefix) && pair.LocalSourceSHA256 == selected.SourceSHA256 &&
			pair.TransportSHA256 == selected.TransportSHA256 && pair.LocalCompanionSHA256 == selected.CompanionSHA256 &&
			pair.LocalCompanionClientPublicKey == selected.CompanionClientPublicKey &&
			pair.CompanionServerPublicKey == selected.CompanionServerPublicKey
	}
	return c.Mode == "shadowsocks"
}

// MatchesDescriptor preserves legacy static eligibility: every originally
// requested candidate must occur exactly once, irrespective of registry order.
func (q NodeChainPrefixSelectionRequest) MatchesDescriptor(d NodeChainPrefixDescriptor) bool {
	if !prefixSelectionLocalDescriptor(q, d) {
		return false
	}
	for _, selected := range q.Candidates {
		count := 0
		for i := range d.Candidates {
			if prefixSelectionCandidateMatches(selected, d, i) {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}

// MatchesSelectedDescriptor is the stronger publication and selected-lease
// identity: the real compiler must produce exactly the requested ordered rows.
func (q NodeChainPrefixSelectionRequest) MatchesSelectedDescriptor(d NodeChainPrefixDescriptor) bool {
	if !prefixSelectionLocalDescriptor(q, d) || len(q.Candidates) != len(d.Candidates) {
		return false
	}
	for i, selected := range q.Candidates {
		if !prefixSelectionCandidateMatches(selected, d, i) {
			return false
		}
	}
	return true
}

// OverlapsDescriptor detects an ambiguous future subset request as well as an
// existing full match. It is only a refusal predicate, never an admission.
func (q NodeChainPrefixSelectionRequest) OverlapsDescriptor(d NodeChainPrefixDescriptor) bool {
	if !prefixSelectionLocalDescriptor(q, d) {
		return false
	}
	for _, selected := range q.Candidates {
		for i := range d.Candidates {
			if prefixSelectionCandidateMatches(selected, d, i) {
				return true
			}
		}
	}
	return false
}
func (q NodeChainPrefixSelectionRequest) MatchesLease(lease NodeChainPrefixRequest, descriptor NodeChainPrefixDescriptor) bool {
	digest, err := q.Digest()
	if err != nil || !q.MatchesSelectedDescriptor(descriptor) || lease.Validate(descriptor) != nil ||
		lease.SelectionSHA256 != digest || lease.LocalSourceSHA256 != q.OriginalSourceSHA256 ||
		lease.InventorySHA256 != q.InventorySHA256 || lease.EntryNodeID != q.EntryNodeID ||
		lease.Peer != q.Peer || lease.Epoch != q.Epoch || lease.ActualPrefixCount() != q.AppendPosition {
		return false
	}
	position := 0
	for _, member := range q.LocalPrefix {
		if !nodeChainPacketMode(member.Mode) {
			continue
		}
		if position >= len(lease.LocalPacketPublicKeys) || lease.LocalPacketPublicKeys[position] != member.ClientPublicKey {
			return false
		}
		position++
	}
	return position == len(lease.LocalPacketPublicKeys)
}
func (r NodeChainPrefixSelectionReceipt) validShape() bool {
	if r.Schema != 1 || r.Purpose != NodeChainPrefixSelectionPurpose || !proofID.MatchString(r.RequestSHA256) ||
		!proofID.MatchString(r.CatalogSHA256) || !proofID.MatchString(r.CatalogGenerationSHA256) ||
		r.Phase != "published" && r.Phase != "retired" {
		return false
	}
	if r.Publication {
		return proofID.MatchString(r.SourceSHA256) && proofID.MatchString(r.DescriptorSHA256)
	}
	return r.Phase == "retired" && r.SourceSHA256 == "" && r.DescriptorSHA256 == ""
}
func (r NodeChainPrefixSelectionReceipt) Validate(q NodeChainPrefixSelectionRequest) error {
	digest, err := q.Digest()
	if err != nil || !r.validShape() || r.RequestSHA256 != digest || r.CatalogSHA256 != q.CatalogSHA256 ||
		r.CatalogGenerationSHA256 != q.CatalogGenerationSHA256 {
		return errNodeChainPrefix
	}
	return nil
}

// The existing bounded walker rejects duplicate, unknown and missing fields.
// Comparing the canonical value's shape also refuses explicit null or empty
// optional commitments that would otherwise disappear from a request digest.
func decodeNodeChainPrefixSelectionJSON(raw []byte, target any, maximum int) error {
	if decodeNodeChainPrefixJSON(raw, target, maximum) != nil {
		return errNodeChainPrefix
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return errNodeChainPrefix
	}
	var original, encoded any
	for i, body := range [][]byte{raw, canonical} {
		d := json.NewDecoder(bytes.NewReader(body))
		d.UseNumber()
		if i == 0 {
			err = d.Decode(&original)
		} else {
			err = d.Decode(&encoded)
		}
		if err != nil {
			return errNodeChainPrefix
		}
	}
	if !reflect.DeepEqual(original, encoded) {
		return errNodeChainPrefix
	}
	return nil
}
func DecodeNodeChainPrefixSelectionDiscovery(raw []byte) (NodeChainPrefixSelectionDiscovery, error) {
	var d NodeChainPrefixSelectionDiscovery
	if decodeNodeChainPrefixSelectionJSON(raw, &d, MaxNodeChainPrefixCapabilitiesBytes) != nil || d.Validate() != nil {
		return NodeChainPrefixSelectionDiscovery{}, errNodeChainPrefix
	}
	return d.Clone(), nil
}
func DecodeNodeChainPrefixSelectionRequest(raw []byte) (NodeChainPrefixSelectionRequest, error) {
	var q NodeChainPrefixSelectionRequest
	if decodeNodeChainPrefixSelectionJSON(raw, &q, NodeChainPrefixSelectionMaximumBytes) != nil || q.Validate() != nil {
		return NodeChainPrefixSelectionRequest{}, errNodeChainPrefix
	}
	return q.Clone(), nil
}
func DecodeNodeChainPrefixSelectionReceipt(raw []byte) (NodeChainPrefixSelectionReceipt, error) {
	var r NodeChainPrefixSelectionReceipt
	if decodeNodeChainPrefixSelectionJSON(raw, &r, NodeChainPrefixSelectionMaximumBytes) != nil || !r.validShape() {
		return NodeChainPrefixSelectionReceipt{}, errNodeChainPrefix
	}
	return r, nil
}
