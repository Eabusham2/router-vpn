package multihoprelay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"router-vpn/internal/hopmeasure"
)

const NodeChainMaximumMembers = 7

// A longer schema-six suffix has one distinct imported SS provider at each
// interior position. Native physical traversal includes the omitted WG entry.
const NodeChainExtendedMaximumMembers = hopmeasure.PhysicalTraversalDepth - 1

func validMemberCount(schema, count int) bool {
	return count >= 1 && (count <= NodeChainMaximumMembers || schema == 6 && count <= NodeChainExtendedMaximumMembers)
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
	NodeKind          string `json:"node_kind,omitempty"`
	ProofKind         string `json:"proof_kind,omitempty"`
	SourceSHA256      string `json:"source_sha256,omitempty"`
	ExpectedPublicIP  string `json:"expected_public_ip,omitempty"`
	OpenVPNPairSHA256 string `json:"openvpn_pair_sha256,omitempty"`
}

type NodeChainDescriptor struct {
	Schema          int               `json:"schema"`
	EntryID         string            `json:"entry_id"`
	EntryNodeID     string            `json:"entry_node_id"`
	EntryMode       string            `json:"entry_mode"`
	SourceSHA256    string            `json:"source_sha256"`
	DNSPolicySHA256 string            `json:"dns_policy_sha256"`
	Members         []NodeChainMember `json:"members"`
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
	LocalPacketPositions []int           `json:"local_packet_positions,omitempty"`
	Port                 int             `json:"listen_port"`
	Users                []NodeChainUser `json:"users"`
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

func (s NodeChainDescriptor) Validate() error {
	if (s.Schema != 1 && s.Schema != 2 && s.Schema != 3 && s.Schema != 4 && s.Schema != 5 && s.Schema != 6) || !ident.MatchString(s.EntryID) || !proofID.MatchString(s.EntryNodeID) || !nodeChainPacketMode(s.EntryMode) ||
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
	publicSources := map[string]bool{}
	publicCount := 0
	for index, member := range s.Members {
		if member.Position != index+1 || !ident.MatchString(member.ProfileID) || ids[member.ProfileID] ||
			(member.StartLayer != "off" && member.StartLayer != "aes-256-gcm" && member.StartLayer != "aes-256-gcm+xor-whitening") {
			return nodeChainCaptureError
		}
		ids[member.ProfileID] = true
		if s.Schema == 6 && member.NodeKind == "external" {
			if index == len(s.Members)-1 || member.Mode != "shadowsocks" || member.ProofKind != "public-path" ||
				!proofID.MatchString(member.SourceSHA256) || publicSources[member.SourceSHA256] || !externalPublicIP(member.ExpectedPublicIP) ||
				member.NodeID != "" || member.StartLayer != "off" || member.ClientPublicKey != "" || member.ServerPublicKey != "" || member.OpenVPNPairSHA256 != "" {
				return nodeChainCaptureError
			}
			publicSources[member.SourceSHA256] = true
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
			member.SourceSHA256 != "" || member.ExpectedPublicIP != "" || member.OpenVPNPairSHA256 != "" {
			return nodeChainCaptureError
		}
		nodes[member.NodeID] = true
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
	if len(s.Members) > NodeChainMaximumMembers && (s.EntryMode != "wg" && s.EntryMode != "awg2-fast" || publicCount != len(s.Members)-1 || s.Members[len(s.Members)-1].StartLayer != "off") {
		return nodeChainCaptureError
	}
	if s.Schema == 6 && publicCount == 0 {
		return nodeChainCaptureError
	}
	return nil
}

func (s NodeChainDescriptor) Clone() NodeChainDescriptor {
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
	}
	return nodeChainDigest(domain, s)
}

func (q NodeChainRequest) validateShape() error {
	if (q.Schema != 1 && q.Schema != 2 && q.Schema != 3 && q.Schema != 4 && q.Schema != 5 && q.Schema != 6) || !nonce.MatchString(q.SessionID) || !proofID.MatchString(q.EntryNodeID) || !proofID.MatchString(q.SourceSHA256) ||
		!proofID.MatchString(q.DescriptorSHA256) || !proofID.MatchString(q.DNSPolicySHA256) || !proofID.MatchString(q.Epoch) ||
		!nodeChainPrivateAddress(q.Peer) || q.AcquireExpiresAt <= 0 || q.Port < 1024 || q.Port > 65535 ||
		!validMemberCount(q.Schema, len(q.Users)) || len(q.Users) > NodeChainMaximumMembers && len(q.LocalPacketPublicKeys) != 1 {
		return nodeChainCaptureError
	}
	if q.Schema == 1 {
		if len(q.LocalPacketPublicKeys) != len(q.Users) || len(q.LocalPacketPositions) != 0 {
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
	if err != nil || q.validateShape() != nil || q.Schema != source.Schema || q.EntryNodeID != source.EntryNodeID || q.SourceSHA256 != source.SourceSHA256 ||
		q.DescriptorSHA256 != digest || q.DNSPolicySHA256 != source.DNSPolicySHA256 || len(q.Users) != len(source.Members) {
		return nodeChainCaptureError
	}
	if source.Schema == 6 {
		positions := []int{0}
		for index, member := range source.Members {
			if index < len(source.Members)-1 && member.NodeKind == "" {
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
	}
	return nodeChainDigest(domain, q)
}

func (c NodeChainCapture) Validate() error {
	digest, err := c.Source.Digest()
	_, offset := c.BootstrapDeadline.Zone()
	if err != nil || c.Schema != 1 || c.Request.Validate(c.Source) != nil || c.RegistrySHA256 != digest || c.RegistrySHA256 != c.Request.DescriptorSHA256 ||
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
