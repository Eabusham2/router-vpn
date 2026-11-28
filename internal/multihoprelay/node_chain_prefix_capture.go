package multihoprelay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"time"
)

const NodeChainPrefixPurpose = "draft-prefix-append-execution"
const NodeChainPrefixMaximumMembers = 95
const NodeChainPrefixMaximumCandidates = 50
const NodeChainPrefixMaximumRequestBytes = 16 << 10
const MaxNodeChainPrefixCapabilitiesBytes = 8 << 20

var errNodeChainPrefix = errors.New("invalid original server prefix execution capture")

type NodeChainPrefixMember struct {
	Position                 int    `json:"position"`
	ProfileID                string `json:"profile_id"`
	NodeID                   string `json:"node_id"`
	Mode                     string `json:"mode"`
	StartLayer               string `json:"start_layer"`
	SourceSHA256             string `json:"source_sha256"`
	ClientPublicKey          string `json:"client_public_key"`
	ServerPublicKey          string `json:"server_public_key"`
	TransportSHA256          string `json:"transport_sha256,omitempty"`
	CompanionSHA256          string `json:"companion_sha256,omitempty"`
	CompanionClientPublicKey string `json:"companion_client_public_key,omitempty"`
	CompanionServerPublicKey string `json:"companion_server_public_key,omitempty"`
}

type NodeChainPrefixCandidate struct {
	ProfileID    string `json:"profile_id"`
	NodeID       string `json:"node_id"`
	Mode         string `json:"mode"`
	StartLayer   string `json:"start_layer"`
	SourceSHA256 string `json:"source_sha256"`
}

// This descriptor contains only public commitments. Members is the actual
// independently provisioned suffix; an entry-only prefix has an empty slice.
// Neither it nor Prepared represents a complete path or application/DNS ingress.
type NodeChainPrefixDescriptor struct {
	Schema               int                                  `json:"schema"`
	Purpose              string                               `json:"purpose"`
	SourceSHA256         string                               `json:"source_sha256"`
	EntryNodeID          string                               `json:"entry_node_id"`
	EntryPeerAddresses   []string                             `json:"entry_peer_addresses"`
	LocalPrefix          []NodeChainPrefixMember              `json:"local_prefix"`
	Members              []NodeChainPrefixMember              `json:"members"`
	Candidates           []NodeChainPrefixCandidate           `json:"candidates"`
	PacketCandidatePairs []NodeChainPrefixPacketCandidatePair `json:"packet_candidate_pairs,omitempty"`
}

func prefixProfileID(v string) bool {
	if len(v) < 1 || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if c < 'a' || c > 'z' {
			if c < 'A' || c > 'Z' {
				if c < '0' || c > '9' {
					if c != '_' && c != '-' {
						return false
					}
				}
			}
		}
	}
	return true
}

func (m NodeChainPrefixMember) valid(position int) bool {
	return m.Position == position && prefixProfileID(m.ProfileID) && proofID.MatchString(m.NodeID) &&
		nodeChainPacketMode(m.Mode) && m.StartLayer == "off" && proofID.MatchString(m.SourceSHA256) &&
		nodeChainPacketPublic(m.ClientPublicKey) && nodeChainPacketPublic(m.ServerPublicKey) && m.ClientPublicKey != m.ServerPublicKey &&
		m.TransportSHA256 == "" && m.CompanionSHA256 == "" && m.CompanionClientPublicKey == "" && m.CompanionServerPublicKey == ""
}
func (m NodeChainPrefixCandidate) valid() bool {
	return prefixProfileID(m.ProfileID) && proofID.MatchString(m.NodeID) && m.Mode == "shadowsocks" &&
		m.StartLayer == "off" && proofID.MatchString(m.SourceSHA256)
}

func (s NodeChainPrefixDescriptor) Validate() error {
	if s.Schema == 3 {
		return s.validatePacketCandidates()
	}
	if s.PacketCandidatePairs != nil {
		return errNodeChainPrefix
	}
	if s.Schema == 2 {
		return s.validateRetainedSS()
	}
	if s.Schema != 1 || s.Purpose != NodeChainPrefixPurpose || !proofID.MatchString(s.SourceSHA256) ||
		!proofID.MatchString(s.EntryNodeID) || len(s.LocalPrefix) < 1 || len(s.LocalPrefix) > NodeChainPrefixMaximumMembers ||
		s.Members == nil || len(s.Members) != len(s.LocalPrefix)-1 || len(s.Candidates) < 1 || len(s.Candidates) > NodeChainPrefixMaximumCandidates ||
		len(s.EntryPeerAddresses) < 1 || len(s.EntryPeerAddresses) > 64 || s.LocalPrefix[0].NodeID != s.EntryNodeID {
		return errNodeChainPrefix
	}
	for i, address := range s.EntryPeerAddresses {
		if !nodeChainPrivateAddress(address) || i > 0 && s.EntryPeerAddresses[i-1] >= address {
			return errNodeChainPrefix
		}
	}
	ids, nodes, sources, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, member := range s.LocalPrefix {
		if !member.valid(i) || ids[member.ProfileID] || nodes[member.NodeID] || sources[member.SourceSHA256] ||
			keys[member.ClientPublicKey] || keys[member.ServerPublicKey] {
			return errNodeChainPrefix
		}
		ids[member.ProfileID], nodes[member.NodeID], sources[member.SourceSHA256] = true, true, true
		keys[member.ClientPublicKey], keys[member.ServerPublicKey] = true, true
	}
	// The logical paired destination and its server public key are shared with
	// Local. Its independently provisioned server-side client identity is not.
	serverSources, serverKeys := map[string]bool{}, map[string]bool{}
	for i, member := range s.Members {
		local := s.LocalPrefix[i+1]
		if !member.valid(i+1) || member.ProfileID != local.ProfileID || member.NodeID != local.NodeID || member.Mode != local.Mode ||
			member.ServerPublicKey != local.ServerPublicKey || keys[member.ClientPublicKey] || serverKeys[member.ClientPublicKey] ||
			sources[member.SourceSHA256] || serverSources[member.SourceSHA256] {
			return errNodeChainPrefix
		}
		serverSources[member.SourceSHA256], serverKeys[member.ClientPublicKey] = true, true
	}
	for _, candidate := range s.Candidates {
		if !candidate.valid() || ids[candidate.ProfileID] || nodes[candidate.NodeID] || sources[candidate.SourceSHA256] || serverSources[candidate.SourceSHA256] {
			return errNodeChainPrefix
		}
		ids[candidate.ProfileID], nodes[candidate.NodeID], sources[candidate.SourceSHA256] = true, true, true
	}
	return nil
}

// Retained SS has a real selected stream and a separately captured paired
// identity. Companion keys are never selected packet transport reservations.
func (m NodeChainPrefixMember) validRetainedSS(position int) bool {
	return position > 0 && m.Position == position && prefixProfileID(m.ProfileID) && proofID.MatchString(m.NodeID) &&
		m.Mode == "shadowsocks" && m.StartLayer == "off" && proofID.MatchString(m.SourceSHA256) &&
		m.ClientPublicKey == "" && m.ServerPublicKey == "" && proofID.MatchString(m.TransportSHA256) && proofID.MatchString(m.CompanionSHA256) &&
		nodeChainPacketPublic(m.CompanionClientPublicKey) && nodeChainPacketPublic(m.CompanionServerPublicKey) && m.CompanionClientPublicKey != m.CompanionServerPublicKey
}
func (m NodeChainPrefixMember) identityKeys() (string, string) {
	if m.Mode == "shadowsocks" {
		return m.CompanionClientPublicKey, m.CompanionServerPublicKey
	}
	return m.ClientPublicKey, m.ServerPublicKey
}
func (s NodeChainPrefixDescriptor) validateRetainedSS() error {
	if s.Schema != 2 || s.Purpose != NodeChainPrefixPurpose || !proofID.MatchString(s.SourceSHA256) || !proofID.MatchString(s.EntryNodeID) ||
		len(s.LocalPrefix) < 2 || len(s.LocalPrefix) > NodeChainPrefixMaximumMembers || s.Members == nil || len(s.Members) != len(s.LocalPrefix)-1 ||
		len(s.Candidates) < 1 || len(s.Candidates) > NodeChainPrefixMaximumCandidates || len(s.EntryPeerAddresses) < 1 || len(s.EntryPeerAddresses) > 64 ||
		s.LocalPrefix[0].NodeID != s.EntryNodeID {
		return errNodeChainPrefix
	}
	for i, address := range s.EntryPeerAddresses {
		if !nodeChainPrivateAddress(address) || i > 0 && s.EntryPeerAddresses[i-1] >= address {
			return errNodeChainPrefix
		}
	}
	ids, nodes, sources, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	companions, transports := map[string]bool{}, map[string]bool{}
	stream := false
	for i, member := range s.LocalPrefix {
		if nodeChainPacketMode(member.Mode) {
			if stream || !member.valid(i) {
				return errNodeChainPrefix
			}
		} else if !member.validRetainedSS(i) {
			return errNodeChainPrefix
		} else {
			stream = true
			if companions[member.CompanionSHA256] || transports[member.TransportSHA256] {
				return errNodeChainPrefix
			}
			companions[member.CompanionSHA256], transports[member.TransportSHA256] = true, true
		}
		client, server := member.identityKeys()
		if ids[member.ProfileID] || nodes[member.NodeID] || sources[member.SourceSHA256] || keys[client] || keys[server] {
			return errNodeChainPrefix
		}
		ids[member.ProfileID], nodes[member.NodeID], sources[member.SourceSHA256] = true, true, true
		keys[client], keys[server] = true, true
	}
	if !stream {
		return errNodeChainPrefix
	}
	serverSources, serverKeys, serverCompanions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, member := range s.Members {
		local := s.LocalPrefix[i+1]
		if member.ProfileID != local.ProfileID || member.NodeID != local.NodeID || member.Mode != local.Mode || serverSources[member.SourceSHA256] {
			return errNodeChainPrefix
		}
		client, server := member.identityKeys()
		_, localServer := local.identityKeys()
		if server != localServer || keys[client] || serverKeys[client] {
			return errNodeChainPrefix
		}
		if nodeChainPacketMode(member.Mode) {
			if !member.valid(i+1) || sources[member.SourceSHA256] {
				return errNodeChainPrefix
			}
		} else if !member.validRetainedSS(i+1) || member.TransportSHA256 != local.TransportSHA256 ||
			companions[member.CompanionSHA256] || serverCompanions[member.CompanionSHA256] ||
			sources[member.SourceSHA256] && member.SourceSHA256 != local.SourceSHA256 {
			return errNodeChainPrefix
		} else {
			serverCompanions[member.CompanionSHA256] = true
		}
		serverSources[member.SourceSHA256], serverKeys[client] = true, true
	}
	for _, candidate := range s.Candidates {
		if !candidate.valid() || ids[candidate.ProfileID] || nodes[candidate.NodeID] || sources[candidate.SourceSHA256] || serverSources[candidate.SourceSHA256] {
			return errNodeChainPrefix
		}
		ids[candidate.ProfileID], nodes[candidate.NodeID], sources[candidate.SourceSHA256] = true, true, true
	}
	return nil
}
func (s NodeChainPrefixDescriptor) Clone() NodeChainPrefixDescriptor {
	s.EntryPeerAddresses = slices.Clone(s.EntryPeerAddresses)
	s.LocalPrefix, s.Members, s.Candidates = slices.Clone(s.LocalPrefix), slices.Clone(s.Members), slices.Clone(s.Candidates)
	s.PacketCandidatePairs = slices.Clone(s.PacketCandidatePairs)
	return s
}
func (s NodeChainPrefixDescriptor) Digest() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	domain := "routervpn-node-chain-prefix-descriptor-v1"
	if s.Schema == 2 {
		domain = "routervpn-node-chain-prefix-descriptor-v2"
	} else if s.Schema == 3 {
		domain = "routervpn-node-chain-prefix-descriptor-v3"
	}
	return nodeChainDigest(domain, s)
}

// FrontSeed stays in the private launch/control capture. Public result metadata
// contains only digests. No caller-selected native source, graph or tag occurs.
type NodeChainPrefixRequest struct {
	Schema                int      `json:"schema"`
	Purpose               string   `json:"purpose"`
	SessionID             string   `json:"session_id"`
	EntryNodeID           string   `json:"entry_node_id"`
	SourceSHA256          string   `json:"source_sha256"`
	DescriptorSHA256      string   `json:"descriptor_sha256"`
	LocalSourceSHA256     string   `json:"local_source_sha256"`
	InventorySHA256       string   `json:"inventory_sha256"`
	Epoch                 string   `json:"epoch"`
	Peer                  string   `json:"peer"`
	AcquireExpiresAt      int64    `json:"acquire_expires_at"`
	LocalPacketPublicKeys []string `json:"local_packet_public_keys"`
	PrefixCount           int      `json:"prefix_count,omitempty"`
	Port                  int      `json:"listen_port"`
	FrontSeed             string   `json:"front_seed"`
}

func (q NodeChainPrefixRequest) validateShape() error {
	if q.Schema != 1 && q.Schema != 2 && q.Schema != 3 || q.Purpose != NodeChainPrefixPurpose || !nonce.MatchString(q.SessionID) || !proofID.MatchString(q.EntryNodeID) ||
		!proofID.MatchString(q.SourceSHA256) || !proofID.MatchString(q.DescriptorSHA256) || !proofID.MatchString(q.LocalSourceSHA256) ||
		!proofID.MatchString(q.InventorySHA256) || !proofID.MatchString(q.Epoch) || !proofID.MatchString(q.FrontSeed) ||
		!nodeChainPrivateAddress(q.Peer) || q.AcquireExpiresAt <= 0 || q.Port < 1024 || q.Port > 65535 ||
		len(q.LocalPacketPublicKeys) < 1 || len(q.LocalPacketPublicKeys) > NodeChainPrefixMaximumMembers {
		return errNodeChainPrefix
	}
	if (q.Schema == 1 || q.Schema == 3) && q.PrefixCount != 0 || q.Schema == 2 && (q.PrefixCount < 2 || q.PrefixCount > NodeChainPrefixMaximumMembers || q.PrefixCount <= len(q.LocalPacketPublicKeys)) {
		return errNodeChainPrefix
	}
	seen := map[string]bool{}
	for _, key := range q.LocalPacketPublicKeys {
		if !nodeChainPacketPublic(key) || seen[key] {
			return errNodeChainPrefix
		}
		seen[key] = true
	}
	return nil
}
func (q NodeChainPrefixRequest) Validate(s NodeChainPrefixDescriptor) error {
	digest, err := s.Digest()
	if err != nil || q.validateShape() != nil || q.EntryNodeID != s.EntryNodeID || q.SourceSHA256 != s.SourceSHA256 ||
		q.Schema != s.Schema || q.DescriptorSHA256 != digest || q.ActualPrefixCount() != len(s.LocalPrefix) || !slices.Contains(s.EntryPeerAddresses, q.Peer) {
		return errNodeChainPrefix
	}
	packetPosition := 0
	for _, member := range s.LocalPrefix {
		if !nodeChainPacketMode(member.Mode) {
			continue
		}
		if packetPosition >= len(q.LocalPacketPublicKeys) || q.LocalPacketPublicKeys[packetPosition] != member.ClientPublicKey {
			return errNodeChainPrefix
		}
		packetPosition++
	}
	if packetPosition != len(q.LocalPacketPublicKeys) {
		return errNodeChainPrefix
	}
	return nil
}

// ActualPrefixCount is descriptive readback of the validated request. Packet
// pins are only transport reservations, not a surrogate ordered member count.
func (q NodeChainPrefixRequest) ActualPrefixCount() int {
	if q.validateShape() != nil {
		return 0
	}
	if q.Schema == 1 || q.Schema == 3 {
		return len(q.LocalPacketPublicKeys)
	}
	return q.PrefixCount
}
func (q NodeChainPrefixRequest) Clone() NodeChainPrefixRequest {
	q.LocalPacketPublicKeys = slices.Clone(q.LocalPacketPublicKeys)
	return q
}
func (q NodeChainPrefixRequest) Digest() (string, error) {
	if err := q.validateShape(); err != nil {
		return "", err
	}
	domain := "routervpn-node-chain-prefix-request-v1"
	if q.Schema == 2 {
		domain = "routervpn-node-chain-prefix-request-v2"
	} else if q.Schema == 3 {
		domain = "routervpn-node-chain-prefix-request-v3"
	}
	return nodeChainDigest(domain, q)
}
func sameNodeChainPrefixRequest(a, b NodeChainPrefixRequest) bool {
	x, e := a.Digest()
	y, f := b.Digest()
	return e == nil && f == nil && x == y
}
func sameNodeChainPrefixSource(a, b NodeChainPrefixDescriptor) bool {
	x, e := a.Digest()
	y, f := b.Digest()
	return e == nil && f == nil && x == y
}

type NodeChainPrefixCapture struct {
	Schema            int                       `json:"schema"`
	Request           NodeChainPrefixRequest    `json:"request"`
	Source            NodeChainPrefixDescriptor `json:"source"`
	RegistrySHA256    string                    `json:"registry_sha256"`
	OwnerID           string                    `json:"owner_id"`
	Peer              string                    `json:"peer"`
	Host              string                    `json:"host"`
	BootstrapDeadline time.Time                 `json:"bootstrap_deadline"`
}

func (c NodeChainPrefixCapture) Validate() error {
	digest, err := c.Source.Digest()
	_, offset := c.BootstrapDeadline.Zone()
	if err != nil || c.Schema != 1 || c.Request.Validate(c.Source) != nil || c.RegistrySHA256 != digest ||
		!proofID.MatchString(c.OwnerID) || c.Peer != c.Request.Peer || !nodeChainPrivateAddress(c.Host) ||
		c.BootstrapDeadline.IsZero() || c.BootstrapDeadline.UnixMilli() <= 0 || offset != 0 {
		return errNodeChainPrefix
	}
	return nil
}
func (c NodeChainPrefixCapture) Clone() NodeChainPrefixCapture {
	c.Request, c.Source = c.Request.Clone(), c.Source.Clone()
	return c
}
func (c NodeChainPrefixCapture) Digest() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return nodeChainDigest("routervpn-node-chain-prefix-capture-v1", c)
}

type NodeChainPrefixPhase string

const (
	NodeChainPrefixPending  NodeChainPrefixPhase = "prefix-pending"
	NodeChainPrefixPrepared NodeChainPrefixPhase = "prefix-prepared"
	NodeChainPrefixFailed   NodeChainPrefixPhase = "prefix-failed"
	NodeChainPrefixRetired  NodeChainPrefixPhase = "prefix-retired"
)

type NodeChainPrefixLease struct {
	Request           NodeChainPrefixRequest `json:"request"`
	NodeID            string                 `json:"node_id"`
	OwnerID           string                 `json:"owner_id"`
	Host              string                 `json:"host"`
	Port              int                    `json:"port"`
	RegistrySHA256    string                 `json:"registry_sha256"`
	Phase             NodeChainPrefixPhase   `json:"phase"`
	ExpiresAt         time.Time              `json:"expires_at"`
	BootstrapDeadline time.Time              `json:"bootstrap_deadline"`
}

type NodeChainPrefixExecutionReceipt struct {
	Schema          int                  `json:"schema"`
	Purpose         string               `json:"purpose"`
	CaptureSHA256   string               `json:"capture_sha256"`
	OwnerID         string               `json:"owner_id"`
	SessionID       string               `json:"session_id"`
	SourceSHA256    string               `json:"source_sha256"`
	RequestSHA256   string               `json:"request_sha256"`
	Peer            string               `json:"peer"`
	Sequence        uint64               `json:"sequence"`
	Nonce           string               `json:"nonce"`
	Phase           NodeChainPrefixPhase `json:"phase"`
	PrefixCount     int                  `json:"prefix_count"`
	ProvenSuffix    []int                `json:"proven_suffix"`
	FrontReady      bool                 `json:"front_ready"`
	ApplicationOpen bool                 `json:"application_open"`
	DNSOpen         bool                 `json:"dns_open"`
	Drained         bool                 `json:"drained"`
	ObservedAt      time.Time            `json:"observed_at"`
}

func (r NodeChainPrefixExecutionReceipt) Clone() NodeChainPrefixExecutionReceipt {
	r.ProvenSuffix = slices.Clone(r.ProvenSuffix)
	return r
}
func ValidateNodeChainPrefixExecutionReceipt(r NodeChainPrefixExecutionReceipt, c NodeChainPrefixCapture, challenge string, started, now time.Time) error {
	capture, e := c.Digest()
	request, f := c.Request.Digest()
	_, offset := r.ObservedAt.Zone()
	if e != nil || f != nil || r.Schema != 1 || r.Purpose != NodeChainPrefixPurpose || r.CaptureSHA256 != capture || r.OwnerID != c.OwnerID ||
		r.SessionID != c.Request.SessionID || r.SourceSHA256 != c.Source.SourceSHA256 || r.RequestSHA256 != request || r.Peer != c.Peer ||
		r.Sequence == 0 || !proofID.MatchString(challenge) || r.Nonce != challenge || r.PrefixCount != len(c.Source.LocalPrefix) ||
		r.ApplicationOpen || r.DNSOpen || r.ProvenSuffix == nil || offset != 0 || r.ObservedAt.Before(started) || r.ObservedAt.After(now) {
		return errNodeChainPrefix
	}
	if r.Phase != NodeChainPrefixPending && r.Phase != NodeChainPrefixPrepared && r.Phase != NodeChainPrefixFailed && r.Phase != NodeChainPrefixRetired {
		return errNodeChainPrefix
	}
	if r.Drained && r.Phase != NodeChainPrefixRetired && r.Phase != NodeChainPrefixFailed ||
		r.Phase == NodeChainPrefixPrepared && (!r.FrontReady || r.Drained || len(r.ProvenSuffix) != len(c.Source.Members)) ||
		len(r.ProvenSuffix) > len(c.Source.Members) {
		return errNodeChainPrefix
	}
	for i, position := range r.ProvenSuffix {
		if position != i+1 {
			return errNodeChainPrefix
		}
	}
	return nil
}

type NodeChainPrefixLeaseStatus struct {
	Lease   NodeChainPrefixLease            `json:"lease"`
	Receipt NodeChainPrefixExecutionReceipt `json:"receipt"`
}
type NodeChainPrefixDiscovery struct {
	NodeID    string                      `json:"node_id"`
	Challenge ExternalPacketChallenge     `json:"challenge"`
	FirstPort int                         `json:"first_port"`
	LastPort  int                         `json:"last_port"`
	Prefixes  []NodeChainPrefixDescriptor `json:"prefixes"`
}

func (d NodeChainPrefixDiscovery) Validate() error {
	if !proofID.MatchString(d.NodeID) || d.Challenge.Validate() != nil || d.FirstPort < 1024 || d.LastPort > 65535 || d.LastPort < d.FirstPort || d.LastPort-d.FirstPort > 63 ||
		len(d.Prefixes) < 1 || len(d.Prefixes) > MaxPairedExits {
		return errNodeChainPrefix
	}
	seen := map[string]bool{}
	for _, s := range d.Prefixes {
		if s.Validate() != nil || s.EntryNodeID != d.NodeID || !slices.Contains(s.EntryPeerAddresses, d.Challenge.Peer) || seen[s.SourceSHA256] {
			return errNodeChainPrefix
		}
		seen[s.SourceSHA256] = true
	}
	return nil
}

// Keep the existing complete-path decoder unchanged. Only these new exact
// prefix types have up to 95 actual positions; their array bound is 96.
func walkNodeChainPrefixJSON(d *json.Decoder, kind reflect.Type, depth int) error {
	if depth > 16 {
		return errNodeChainPrefix
	}
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	token, err := d.Token()
	if err != nil || token == nil {
		return errNodeChainPrefix
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		if kind.Kind() != reflect.Struct {
			return errNodeChainPrefix
		}
		fields, seen := nodeChainJSONFields(kind), map[string]bool{}
		for d.More() {
			token, err := d.Token()
			key, ok := token.(string)
			child, known := fields[key]
			if err != nil || !ok || !known || seen[key] || len(seen) >= 64 {
				return errNodeChainPrefix
			}
			seen[key] = true
			if err := walkNodeChainPrefixJSON(d, child, depth+1); err != nil {
				return err
			}
		}
		for name, required := range nodeChainJSONRequired(kind) {
			if required && !seen[name] {
				return errNodeChainPrefix
			}
		}
	case '[':
		if kind.Kind() != reflect.Slice && kind.Kind() != reflect.Array {
			return errNodeChainPrefix
		}
		count := 0
		for d.More() {
			if count >= 96 {
				return errNodeChainPrefix
			}
			count++
			if err := walkNodeChainPrefixJSON(d, kind.Elem(), depth+1); err != nil {
				return err
			}
		}
	default:
		return errNodeChainPrefix
	}
	end, err := d.Token()
	if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
		return errNodeChainPrefix
	}
	return nil
}
func decodeNodeChainPrefixJSON(raw []byte, target any, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum || reflect.TypeOf(target) == nil {
		return errNodeChainPrefix
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if walkNodeChainPrefixJSON(d, reflect.TypeOf(target), 0) != nil {
		return errNodeChainPrefix
	}
	if _, err := d.Token(); err != io.EOF {
		return errNodeChainPrefix
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return errNodeChainPrefix
	}
	return nil
}
func DecodeNodeChainPrefixRequest(raw []byte, status bool) (NodeChainPrefixRequest, string, error) {
	if status {
		var v struct {
			Request NodeChainPrefixRequest `json:"request"`
			Nonce   string                 `json:"nonce"`
		}
		if decodeNodeChainPrefixJSON(raw, &v, NodeChainPrefixMaximumRequestBytes) == nil && v.Request.validateShape() == nil && proofID.MatchString(v.Nonce) {
			return v.Request.Clone(), v.Nonce, nil
		}
		return NodeChainPrefixRequest{}, "", errNodeChainPrefix
	}
	var q NodeChainPrefixRequest
	if decodeNodeChainPrefixJSON(raw, &q, NodeChainPrefixMaximumRequestBytes) != nil || q.validateShape() != nil {
		return NodeChainPrefixRequest{}, "", errNodeChainPrefix
	}
	return q.Clone(), "", nil
}
func DecodeNodeChainPrefixCapture(raw []byte) (NodeChainPrefixCapture, error) {
	var c NodeChainPrefixCapture
	if decodeNodeChainPrefixJSON(raw, &c, MaxNodeChainPrefixCapabilitiesBytes) != nil || c.Validate() != nil {
		return NodeChainPrefixCapture{}, errNodeChainPrefix
	}
	return c.Clone(), nil
}
func DecodeNodeChainPrefixDiscovery(raw []byte) (NodeChainPrefixDiscovery, error) {
	var d NodeChainPrefixDiscovery
	if decodeNodeChainPrefixJSON(raw, &d, MaxNodeChainPrefixCapabilitiesBytes) != nil || d.Validate() != nil {
		return NodeChainPrefixDiscovery{}, errNodeChainPrefix
	}
	return d, nil
}
func validNodeChainPrefixPeer(peer netip.Addr) bool {
	return peer.Zone() == "" && nodeChainPrivateAddress(PeerKey(peer))
}
