package multihoprelay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"router-vpn/internal/hopmeasure"
)

const NodeChainMaximumMembers = 7

// A longer schema-six suffix has one distinct imported SS provider at each
// interior position. Native physical traversal includes the omitted WG entry.
const NodeChainExtendedMaximumMembers = hopmeasure.PhysicalTraversalDepth - 1

func validMemberCount(schema, count int) bool {
	return count >= 1 && (count <= NodeChainMaximumMembers || (schema == 6 || schema == 8) && count <= NodeChainExtendedMaximumMembers)
}

var nodeChainCaptureError = errors.New("invalid captured ordered server path")

// NodeChainMember is the public identity of one operator-owned suffix member.
// Position starts at one: position zero is the client's captured entry node.
// Neither this descriptor nor a client request contains private source bytes.
type NodeChainMember struct {
	Position        int    `json:"position"`
	ProfileID       string `json:"profile_id"`
	NodeID          string `json:"node_id"`
	Mode            string `json:"mode"`
	StartLayer      string `json:"start_layer"`
	ClientPublicKey string `json:"client_public_key,omitempty"`
	ServerPublicKey string `json:"server_public_key,omitempty"`
	// Versions 2 (SS) and 4 (CONNECT) record an original imported member without manufacturing
	// a Router identity or packet key. SourceSHA256 binds its private captured
	// member input; it grants no authority outside the operator registry.
	NodeKind             string `json:"node_kind,omitempty"`
	ProofKind            string `json:"proof_kind,omitempty"`
	SourceSHA256         string `json:"source_sha256,omitempty"`
	ExpectedPublicIP     string `json:"expected_public_ip,omitempty"`
	OpenVPNPairSHA256    string `json:"openvpn_pair_sha256,omitempty"`
	StreamIdentitySHA256 string `json:"stream_identity_sha256,omitempty"`
}

// Only public commitments cross from the original client entry into the
// independently provisioned operator suffix. The local final source includes
// private predecessor material and is never a server worker input.
type NodeChainExternalFinalBinding struct {
	EntrySourceSHA256      string   `json:"entry_source_sha256"`
	EntryStartLayer        string   `json:"entry_start_layer"`
	EntryClientPublicKey   string   `json:"entry_client_public_key"`
	EntryPeerAddresses     []string `json:"entry_peer_addresses"`
	DNSOwner               string   `json:"dns_owner"`
	LocalFinalSourceSHA256 string   `json:"local_final_source_sha256"`
	FinalTransportSHA256   string   `json:"final_transport_sha256"`
}

type NodeChainDescriptor struct {
	Schema          int                            `json:"schema"`
	EntryID         string                         `json:"entry_id"`
	EntryNodeID     string                         `json:"entry_node_id"`
	EntryMode       string                         `json:"entry_mode"`
	SourceSHA256    string                         `json:"source_sha256"`
	DNSPolicySHA256 string                         `json:"dns_policy_sha256"`
	Members         []NodeChainMember              `json:"members"`
	ExternalFinal   *NodeChainExternalFinalBinding `json:"external_final,omitempty"`
}

type NodeChainUser struct {
	Position int    `json:"position"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Every positional credential and the listener port is proposed before the
// client graph is captured. No omitted proposal may allocate a different front.
// All local packet keys are pinned, including the entry and each middle node.
type NodeChainRequest struct {
	Schema                int      `json:"schema"`
	SessionID             string   `json:"session_id"`
	EntryNodeID           string   `json:"entry_node_id"`
	SourceSHA256          string   `json:"source_sha256"`
	DescriptorSHA256      string   `json:"descriptor_sha256"`
	DNSPolicySHA256       string   `json:"dns_policy_sha256"`
	Epoch                 string   `json:"epoch"`
	Peer                  string   `json:"peer"`
	AcquireExpiresAt      int64    `json:"acquire_expires_at"`
	LocalPacketPublicKeys []string `json:"local_packet_public_keys"`
	// Version 1 implicitly has packet positions 0..len(Users)-1. Version 2
	// names only actual packet positions; version 4 retains the same single
	// original client-entry key. Neither imported transport has a packet key.
	LocalPacketPositions []int              `json:"local_packet_positions,omitempty"`
	Port                 int                `json:"listen_port"`
	Users                []NodeChainUser    `json:"users"`
	FrontSeed            nodeChainFrontSeed `json:"front_seed,omitempty"`
	PrivateFrontSeed     nodeChainFrontSeed `json:"private_front_seed,omitempty"`
}

// NodeChainCapture is delivered only to the separately owned native worker.
// RegistrySHA256 is exactly the complete descriptor digest. The absolute
// bootstrap bound belongs to the original lease, not to a later status caller.
type NodeChainCapture struct {
	Schema            int                 `json:"schema"`
	Request           NodeChainRequest    `json:"request"`
	Source            NodeChainDescriptor `json:"source"`
	RegistrySHA256    string              `json:"registry_sha256"`
	OwnerID           string              `json:"owner_id"`
	Peer              string              `json:"peer"`
	Host              string              `json:"host"`
	BootstrapDeadline time.Time           `json:"bootstrap_deadline"`
}

func nodeChainPacketMode(mode string) bool {
	return mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong"
}

func nodeChainPrivateAddress(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Zone() == "" && ip.String() == value && !ip.Is4In6() &&
		ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func nodeChainDigest(domain string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", nodeChainCaptureError
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain + "\x00"))
	_, _ = hash.Write(raw)
	clear(raw)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// The independently provisioned WG identity companion is an identity proof.
// Return the first paired stream in a qualified layout. Each such stream has
// its own identity and has no packet endpoint or positional packet key.
func (s NodeChainDescriptor) PrivateStreamPosition() int {
	n := len(s.Members)
	if s.Schema != 6 || !nodeChainPacketMode(s.EntryMode) || n < 3 || n > NodeChainExtendedMaximumMembers {
		return 0
	}
	paired := 0
	for i, m := range s.Members {
		if m.Position != i+1 || m.Mode != "shadowsocks" || m.StartLayer != "off" {
			return 0
		}
		switch {
		case i == n-1:
			if m.NodeKind != "" || m.ProofKind != "" {
				return 0
			}
		case m.NodeKind == "external" && m.ProofKind == "public-path":
		case i > 0 && m.NodeKind == "" && m.ProofKind == "":
			if paired == 0 {
				paired = i + 1
			}
		default:
			return 0
		}
	}
	return paired
}

func (s NodeChainDescriptor) PrivateStreamAt(position int) bool {
	return position >= 2 && position < len(s.Members) && s.Members[position-1].NodeKind == "" && s.PrivateStreamPosition() > 0
}

func (s NodeChainDescriptor) Validate() error {
	if s.Schema == 8 {
		return s.validateExternalFinal()
	}
	if s.ExternalFinal != nil || (s.Schema != 1 && s.Schema != 2 && s.Schema != 3 && s.Schema != 4 && s.Schema != 5 && s.Schema != 6) || !ident.MatchString(s.EntryID) || !proofID.MatchString(s.EntryNodeID) || !nodeChainPacketMode(s.EntryMode) ||
		!proofID.MatchString(s.SourceSHA256) || !proofID.MatchString(s.DNSPolicySHA256) || !validMemberCount(s.Schema, len(s.Members)) {
		return nodeChainCaptureError
	}
	// Schema 2 preserves every original paired packet prefix, one unlayered
	// penultimate SS2022 import, and a paired SS final. SOCKS5 (schema 3) and
	// HTTP(S) CONNECT (schema 4) retain distinct transport ownership and
	// complete original paired packet-prefix inventories.
	// These descriptors contain no native lower/socket authority. Only the
	// operator's separately captured typed suffix can open its first transport.
	if (s.Schema == 2 || s.Schema == 3 || s.Schema == 4 || s.Schema == 5 || s.Schema == 6) && len(s.Members) < 2 {
		return nodeChainCaptureError
	}
	ids, nodes := map[string]bool{s.EntryID: true}, map[string]bool{s.EntryNodeID: true}
	keys := map[string]bool{}
	streamSources, streamIdentities := map[string]bool{}, map[string]bool{}
	privatePosition := s.PrivateStreamPosition()
	publicCount := 0
	for index, member := range s.Members {
		if member.Position != index+1 || !ident.MatchString(member.ProfileID) || ids[member.ProfileID] ||
			(member.StartLayer != "off" && member.StartLayer != "aes-256-gcm" && member.StartLayer != "aes-256-gcm+xor-whitening") {
			return nodeChainCaptureError
		}
		ids[member.ProfileID] = true
		privateStream := privatePosition > 0 && index < len(s.Members)-1 && member.NodeKind == ""
		if privateStream != (member.StreamIdentitySHA256 != "") {
			return nodeChainCaptureError
		}
		if s.Schema == 6 && member.NodeKind == "external" {
			if index == len(s.Members)-1 || member.Mode != "shadowsocks" || member.ProofKind != "public-path" ||
				!proofID.MatchString(member.SourceSHA256) || streamSources[member.SourceSHA256] || !externalPublicIP(member.ExpectedPublicIP) ||
				member.NodeID != "" || member.StartLayer != "off" || member.ClientPublicKey != "" || member.ServerPublicKey != "" || member.OpenVPNPairSHA256 != "" {
				return nodeChainCaptureError
			}
			streamSources[member.SourceSHA256] = true
			publicCount++
			continue
		}
		if (s.Schema == 2 || s.Schema == 3 || s.Schema == 4 || s.Schema == 5) && index == len(s.Members)-2 {
			modeOK := s.Schema == 2 && member.Mode == "shadowsocks" || s.Schema == 3 && member.Mode == "socks5" ||
				s.Schema == 4 && (member.Mode == "http-connect" || member.Mode == "https-connect") || s.Schema == 5 && member.Mode == "openvpn"
			if member.NodeKind != "external" || member.ProofKind != "public-path" || !proofID.MatchString(member.SourceSHA256) ||
				!externalPublicIP(member.ExpectedPublicIP) || member.NodeID != "" || !modeOK || member.StartLayer != "off" ||
				member.ClientPublicKey != "" || member.ServerPublicKey != "" ||
				s.Schema == 5 && !proofID.MatchString(member.OpenVPNPairSHA256) || s.Schema != 5 && member.OpenVPNPairSHA256 != "" {
				return nodeChainCaptureError
			}
			continue
		}
		if !proofID.MatchString(member.NodeID) || nodes[member.NodeID] || member.NodeKind != "" || member.ProofKind != "" ||
			(!privateStream && member.SourceSHA256 != "") || member.ExpectedPublicIP != "" || member.OpenVPNPairSHA256 != "" {
			return nodeChainCaptureError
		}
		nodes[member.NodeID] = true
		if privateStream {
			if !proofID.MatchString(member.SourceSHA256) || !proofID.MatchString(member.StreamIdentitySHA256) || streamSources[member.SourceSHA256] || streamIdentities[member.StreamIdentitySHA256] || member.ClientPublicKey != "" || member.ServerPublicKey != "" {
				return nodeChainCaptureError
			}
			streamSources[member.SourceSHA256], streamIdentities[member.StreamIdentitySHA256] = true, true
			continue
		}
		if index == len(s.Members)-1 {
			if (member.Mode != "shadowsocks" && (s.Schema != 1 || member.Mode != "hysteria2")) ||
				member.ClientPublicKey != "" || member.ServerPublicKey != "" {
				return nodeChainCaptureError
			}
			continue
		}
		if !nodeChainPacketMode(member.Mode) {
			return nodeChainCaptureError
		}
		for _, key := range []string{member.ClientPublicKey, member.ServerPublicKey} {
			if !nodeChainPacketPublic(key) || keys[key] {
				return nodeChainCaptureError
			}
			keys[key] = true
		}
	}
	if len(s.Members) > NodeChainMaximumMembers && (s.EntryMode != "wg" && s.EntryMode != "awg2-fast" && s.EntryMode != "awg2-strong" || (publicCount != len(s.Members)-1 && privatePosition == 0) || s.Members[len(s.Members)-1].StartLayer != "off") {
		return nodeChainCaptureError
	}
	if s.Schema == 6 && publicCount == 0 {
		return nodeChainCaptureError
	}
	return nil
}

func (s NodeChainDescriptor) validateExternalFinal() error {
	b := s.ExternalFinal
	if b == nil || !ident.MatchString(s.EntryID) || !proofID.MatchString(s.EntryNodeID) || !nodeChainPacketMode(s.EntryMode) ||
		!proofID.MatchString(s.SourceSHA256) || !proofID.MatchString(s.DNSPolicySHA256) || !proofID.MatchString(b.EntrySourceSHA256) ||
		!proofID.MatchString(b.LocalFinalSourceSHA256) || !proofID.MatchString(b.FinalTransportSHA256) || !nodeChainPacketPublic(b.EntryClientPublicKey) ||
		(b.EntryStartLayer != "off" && b.EntryStartLayer != "aes-256-gcm" && b.EntryStartLayer != "aes-256-gcm+xor-whitening") ||
		(b.DNSOwner != "entry-home" && b.DNSOwner != "external-final") || len(s.Members) < 2 || !validMemberCount(s.Schema, len(s.Members)) {
		return nodeChainCaptureError
	}
	if len(b.EntryPeerAddresses) == 0 || len(b.EntryPeerAddresses) > 64 || b.EntrySourceSHA256 == b.LocalFinalSourceSHA256 ||
		b.FinalTransportSHA256 == b.EntrySourceSHA256 || b.FinalTransportSHA256 == b.LocalFinalSourceSHA256 {
		return nodeChainCaptureError
	}
	for i, address := range b.EntryPeerAddresses {
		if !nodeChainPrivateAddress(address) || i > 0 && b.EntryPeerAddresses[i-1] >= address {
			return nodeChainCaptureError
		}
	}
	ids := map[string]bool{s.EntryID: true}
	sources := map[string]bool{b.EntrySourceSHA256: true, b.LocalFinalSourceSHA256: true, b.FinalTransportSHA256: true}
	for i, m := range s.Members {
		ip, err := netip.ParseAddr(m.ExpectedPublicIP)
		if m.Position != i+1 || !ident.MatchString(m.ProfileID) || ids[m.ProfileID] || !proofID.MatchString(m.SourceSHA256) || sources[m.SourceSHA256] ||
			m.NodeKind != "external" || m.ProofKind != "public-path" || m.Mode != "shadowsocks" || m.StartLayer != "off" ||
			err != nil || ip.String() != m.ExpectedPublicIP || !externalPublicIP(m.ExpectedPublicIP) ||
			m.NodeID != "" || m.ClientPublicKey != "" || m.ServerPublicKey != "" || m.OpenVPNPairSHA256 != "" || m.StreamIdentitySHA256 != "" {
			return nodeChainCaptureError
		}
		ids[m.ProfileID], sources[m.SourceSHA256] = true, true
	}
	return nil
}

// SameExternalFinalEntry checks which independently registered public suffixes
// belong to one original paired packet entry. Each suffix retains its own DNS
// policy, credential commitments and final public address.
func (s NodeChainDescriptor) SameExternalFinalEntry(other NodeChainDescriptor) bool {
	if s.Schema != 8 || other.Schema != 8 || s.Validate() != nil || other.Validate() != nil {
		return false
	}
	a, b := s.ExternalFinal, other.ExternalFinal
	return s.EntryNodeID == other.EntryNodeID && s.EntryID == other.EntryID && s.EntryMode == other.EntryMode &&
		a.EntrySourceSHA256 == b.EntrySourceSHA256 && a.EntryStartLayer == b.EntryStartLayer &&
		a.EntryClientPublicKey == b.EntryClientPublicKey && slices.Equal(a.EntryPeerAddresses, b.EntryPeerAddresses)
}

func (s NodeChainDescriptor) Clone() NodeChainDescriptor {
	if s.ExternalFinal != nil {
		binding := *s.ExternalFinal
		binding.EntryPeerAddresses = slices.Clone(binding.EntryPeerAddresses)
		s.ExternalFinal = &binding
	}
	s.Members = append([]NodeChainMember(nil), s.Members...)
	return s
}

func (s NodeChainDescriptor) Digest() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	domain := "routervpn-server-node-chain-descriptor-v1"
	if s.Schema == 2 {
		domain = "routervpn-server-node-chain-descriptor-v2"
	} else if s.Schema == 3 {
		domain = "routervpn-server-node-chain-descriptor-v3"
	} else if s.Schema == 4 {
		domain = "routervpn-server-node-chain-descriptor-v4"
	} else if s.Schema == 5 {
		domain = "routervpn-server-node-chain-descriptor-v5"
	} else if s.Schema == 6 {
		domain = "routervpn-server-node-chain-descriptor-v6"
	} else if s.Schema == 8 {
		domain = "routervpn-server-node-chain-descriptor-v8"
	}
	return nodeChainDigest(domain, s)
}

func (q NodeChainRequest) validateShape() error {
	if (q.Schema != 1 && q.Schema != 2 && q.Schema != 3 && q.Schema != 4 && q.Schema != 5 && q.Schema != 6 && q.Schema != 8) || !nonce.MatchString(q.SessionID) || !proofID.MatchString(q.EntryNodeID) || !proofID.MatchString(q.SourceSHA256) ||
		!proofID.MatchString(q.DescriptorSHA256) || !proofID.MatchString(q.DNSPolicySHA256) || !proofID.MatchString(q.Epoch) ||
		!nodeChainPrivateAddress(q.Peer) || q.AcquireExpiresAt <= 0 || q.Port < 1024 || q.Port > 65535 ||
		!validMemberCount(q.Schema, len(q.Users)) || len(q.Users) > NodeChainMaximumMembers && len(q.LocalPacketPublicKeys) != 1 {
		return nodeChainCaptureError
	}
	if q.HasRegisteredFronts() {
		expected, err := q.registeredFronts(len(q.Users))
		if err != nil || !slices.Equal(expected, q.Users) {
			return nodeChainCaptureError
		}
	}
	if q.Schema == 1 {
		if len(q.LocalPacketPublicKeys) != len(q.Users) || len(q.LocalPacketPositions) != 0 {
			return nodeChainCaptureError
		}
	} else if q.Schema == 8 {
		if len(q.Users) < 2 || len(q.LocalPacketPublicKeys) != 1 || len(q.LocalPacketPositions) != 1 || q.LocalPacketPositions[0] != 0 {
			return nodeChainCaptureError
		}
	} else if q.Schema == 6 {
		if len(q.Users) < 2 || len(q.LocalPacketPublicKeys) < 1 || len(q.LocalPacketPublicKeys) >= len(q.Users) ||
			len(q.LocalPacketPositions) != len(q.LocalPacketPublicKeys) || q.LocalPacketPositions[0] != 0 {
			return nodeChainCaptureError
		}
		for index, position := range q.LocalPacketPositions {
			if position < 0 || position >= len(q.Users) || index > 0 && position <= q.LocalPacketPositions[index-1] {
				return nodeChainCaptureError
			}
		}
	} else if q.Schema == 2 || q.Schema == 3 || q.Schema == 4 || q.Schema == 5 {
		if len(q.Users) < 2 || len(q.LocalPacketPublicKeys) != len(q.Users)-1 || len(q.LocalPacketPositions) != len(q.LocalPacketPublicKeys) {
			return nodeChainCaptureError
		}
		for index, position := range q.LocalPacketPositions {
			if position != index {
				return nodeChainCaptureError
			}
		}
	} else {
		return nodeChainCaptureError
	}
	keys, secrets := map[string]bool{}, map[string]bool{}
	for _, key := range q.LocalPacketPublicKeys {
		if !nodeChainPacketPublic(key) || keys[key] {
			return nodeChainCaptureError
		}
		keys[key] = true
	}
	for index, user := range q.Users {
		if user.Position != index+1 {
			return nodeChainCaptureError
		}
		for _, secret := range []string{user.Username, user.Password} {
			if !listenerSecret.MatchString(secret) || secrets[secret] {
				return nodeChainCaptureError
			}
			secrets[secret] = true
		}
	}
	return nil
}

func (q NodeChainRequest) Validate(source NodeChainDescriptor) error {
	digest, err := source.Digest()
	if err != nil {
		return nodeChainCaptureError
	}
	return q.validateAgainstDescriptor(source, digest)
}

// The caller has validated and hashed this precise descriptor in the same call.
func (q NodeChainRequest) validateAgainstDescriptor(source NodeChainDescriptor, digest string) error {
	if q.validateShape() != nil || q.Schema != source.Schema || q.EntryNodeID != source.EntryNodeID || q.SourceSHA256 != source.SourceSHA256 ||
		q.DescriptorSHA256 != digest || q.DNSPolicySHA256 != source.DNSPolicySHA256 || len(q.Users) != len(source.Members) {
		return nodeChainCaptureError
	}
	if source.Schema == 8 && (q.LocalPacketPublicKeys[0] != source.ExternalFinal.EntryClientPublicKey || !slices.Contains(source.ExternalFinal.EntryPeerAddresses, q.Peer)) {
		return nodeChainCaptureError
	}
	if source.Schema == 6 {
		positions := []int{0}
		private := source.PrivateStreamPosition()
		for index, member := range source.Members {
			if index < len(source.Members)-1 && member.NodeKind == "" && private == 0 {
				positions = append(positions, member.Position)
			}
		}
		if len(positions) != len(q.LocalPacketPositions) {
			return nodeChainCaptureError
		}
		for index, position := range positions {
			if q.LocalPacketPositions[index] != position {
				return nodeChainCaptureError
			}
		}
	}
	local := map[string]bool{}
	for _, key := range q.LocalPacketPublicKeys {
		local[key] = true
	}
	for _, member := range source.Members {
		if local[member.ClientPublicKey] || local[member.ServerPublicKey] {
			return nodeChainCaptureError
		}
	}
	return nil
}

func (q NodeChainRequest) Clone() NodeChainRequest {
	q.LocalPacketPublicKeys = append([]string(nil), q.LocalPacketPublicKeys...)
	q.LocalPacketPositions = append([]int(nil), q.LocalPacketPositions...)
	q.Users = append([]NodeChainUser(nil), q.Users...)
	return q
}

// Digest checks the independent request shape. Source authorization requires
// Validate(originalDescriptor); the digest alone grants no registry authority.
func (q NodeChainRequest) Digest() (string, error) {
	if err := q.validateShape(); err != nil {
		return "", err
	}
	domain := "routervpn-server-node-chain-request-v1"
	if q.Schema == 2 {
		domain = "routervpn-server-node-chain-request-v2"
	} else if q.Schema == 3 {
		domain = "routervpn-server-node-chain-request-v3"
	} else if q.Schema == 4 {
		domain = "routervpn-server-node-chain-request-v4"
	} else if q.Schema == 5 {
		domain = "routervpn-server-node-chain-request-v5"
	} else if q.Schema == 6 {
		domain = "routervpn-server-node-chain-request-v6"
	} else if q.Schema == 8 {
		domain = "routervpn-server-node-chain-request-v8"
	}
	return nodeChainDigest(domain, q)
}

func (c NodeChainCapture) Validate() error {
	digest, err := c.Source.Digest()
	_, offset := c.BootstrapDeadline.Zone()
	if err != nil || c.Schema != 1 || c.Request.validateAgainstDescriptor(c.Source, digest) != nil || c.RegistrySHA256 != digest || c.RegistrySHA256 != c.Request.DescriptorSHA256 ||
		!proofID.MatchString(c.OwnerID) || c.Peer != c.Request.Peer || !nodeChainPrivateAddress(c.Host) ||
		c.BootstrapDeadline.IsZero() || c.BootstrapDeadline.UnixMilli() <= 0 || offset != 0 {
		return nodeChainCaptureError
	}
	return nil
}

func (c NodeChainCapture) Clone() NodeChainCapture {
	c.Request, c.Source = c.Request.Clone(), c.Source.Clone()
	return c
}

func (c NodeChainCapture) Digest() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return nodeChainDigest("routervpn-server-node-chain-capture-v1", c)
}
