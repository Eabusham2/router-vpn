package mobilemultihop

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

const NodeChainMaximumNodes = 8
const NodeChainInputLimit = 40 << 20

// NodeChainPrefixMode reports the exact captured packet modes supported before
// the final node of a Local ordered path. It does not normalize UI labels or
// authorize a mode without its matching captured endpoint and credentials.
func NodeChainPrefixMode(mode string) bool {
	return nodeChainPrefixType(mode) != ""
}

func nodeChainPrefixType(mode string) string {
	switch mode {
	case "wg":
		return "wireguard"
	case "awg2-fast", "awg2-strong":
		return AmneziaType
	default:
		return ""
	}
}

// NodeChainSource contains private, canonical NodeProfile launch captures in
// forwarding order. The aggregate limit applies before parsing any node; it is
// not a per-node allowance and an oversized chain is never truncated.
type NodeChainSource struct {
	Schema    int      `json:"schema"`
	Execution string   `json:"execution"`
	Nodes     []string `json:"nodes"`
}

// NodeChainProof identifies a prefix without publishing its API or token.
type NodeChainProof struct {
	Position     int    `json:"position"`
	ProfileID    string `json:"profile_id"`
	NodeID       string `json:"node_id"`
	Mode         string `json:"mode"`
	StartLayer   string `json:"start_layer"`
	SourceSHA256 string `json:"source_sha256"`
	Tag          string `json:"tag"`
}

// NodeChainDNSCapture authorizes one existing native resolver path. An adapter
// must match this receipt against its retained graph before exercising DNS.
type NodeChainDNSCapture struct {
	SourceSHA256   string `json:"source_sha256"`
	ConfigSHA256   string `json:"config_sha256"`
	TUNTag         string `json:"tun_tag"`
	ResolverTag    string `json:"resolver_tag"`
	ResolverSHA256 string `json:"resolver_sha256"`
	FinalTag       string `json:"final_tag"`
}

type nodeChainLaunchRecord struct {
	Kind string `json:"kind"`
	NodeChainSource
	SourceSHA256         string `json:"source_sha256"`
	ConfigSHA256         string `json:"config_sha256"`
	MetadataSHA256       string `json:"metadata_sha256"`
	OriginalConfigSHA256 string `json:"original_config_sha256"`
	TargetOS             string `json:"target_os,omitempty"`
	RestoredMTU          int    `json:"restored_mtu,omitempty"`
	ProjectionKind       string `json:"projection_kind,omitempty"`
	SessionID            string `json:"session_id,omitempty"`
}

// NodeChain is a complete Local path, not an array of independent VPNs. Its
// selected source, compiled graph and prefix inventory remain immutable.
// Existing pair constructors and their runtime ownership are unchanged.
type NodeChain struct {
	sourceJSON, sourceSHA, config, metadata, seal string
	nodes                                         []*NodeProfile
	proofs                                        []NodeChainProof
	dns                                           NodeChainDNSCapture
	physical                                      []PhysicalEgress
	runtime                                       nodeChainRuntime
	originalConfigSHA                             string
	projection                                    nodeChainProjection
}

var nodeChainError = errors.New("ordered node chain requires its complete bounded original Local capture")

func NewNodeChain(sourceJSON string) (*NodeChain, error) {
	var source NodeChainSource
	if exactJSON([]byte(sourceJSON), &source, NodeChainInputLimit) != nil ||
		source.Schema != 1 || source.Execution != "local" ||
		len(source.Nodes) < 2 || len(source.Nodes) > NodeChainMaximumNodes {
		return nil, nodeChainError
	}
	canonical, err := json.Marshal(source)
	if err != nil || len(canonical) > NodeChainInputLimit {
		return nil, nodeChainError
	}
	c := &NodeChain{sourceJSON: string(canonical)}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-source-v1", c.sourceJSON})
	c.sourceSHA = externalDigest(digest)
	clear(digest)
	ids, peers, clients, servers := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for position, input := range source.Nodes {
		node, err := ParseNodeLaunchInput(input)
		if err != nil || node == nil {
			return nil, nodeChainError
		}
		if position < len(source.Nodes)-1 && !NodeChainPrefixMode(node.mode) ||
			position == len(source.Nodes)-1 && node.mode != "shadowsocks" {
			return nil, errors.New("ordered Local chains require captured WG or AWG2 Fast/Strong prefixes and an SS2022 final")
		}
		id, peer := predecessorText(node.profile, "id"), predecessorText(node.profile, "node_proof_id")
		if ids[id] || peers[peer] {
			return nil, errors.New("ordered chain contains a duplicate selected node identity")
		}
		ids[id], peers[peer] = true, true
		if NodeChainPrefixMode(node.mode) {
			client, err := node.PacketClientPublicKey()
			if err != nil || clients[client] {
				return nil, errors.New("ordered chain requires independent canonical WG/AWG client identities")
			}
			clients[client] = true
			closure, err := nodeMultihopPredecessor(node)
			if err != nil {
				return nil, nodeChainError
			}
			rows, ok := closure.final["peers"].([]any)
			if !ok || len(rows) != 1 {
				return nil, nodeChainError
			}
			server := predecessorText(rows[0].(map[string]any), "public_key")
			if !nodeChainCanonicalPeer(server) || servers[server] {
				return nil, errors.New("ordered chain requires independent canonical WG/AWG server identities")
			}
			servers[server] = true
		}
		c.nodes = append(c.nodes, node)
	}
	c.config, c.proofs, c.dns, c.physical, err = compileNodeChain(c.nodes)
	if err != nil {
		return nil, err
	}
	c.dns.SourceSHA256, c.dns.ConfigSHA256 = c.sourceSHA, externalDigest([]byte(c.config))
	c.originalConfigSHA = c.dns.ConfigSHA256
	if err := c.refreshMetadata(); err != nil {
		return nil, err
	}
	c.seal = c.captureSeal()
	if _, err := c.LaunchInput(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *NodeChain) refreshMetadata() error {
	plan, err := nodeChainProjectedMTUPlan(c.config, c.proofs, c.projection)
	if err != nil {
		return err
	}
	meta, err := json.Marshal(struct {
		Schema               int                 `json:"schema"`
		Execution            string              `json:"execution"`
		SourceSHA256         string              `json:"source_sha256"`
		ConfigSHA256         string              `json:"config_sha256"`
		Proofs               []NodeChainProof    `json:"proofs"`
		DNS                  NodeChainDNSCapture `json:"dns"`
		Physical             []PhysicalEgress    `json:"physical"`
		Measurement          string              `json:"measurement"`
		OriginalConfigSHA256 string              `json:"original_config_sha256"`
		Projection           nodeChainProjection `json:"projection"`
		MTU                  NodeChainMTUPlan    `json:"mtu"`
	}{1, "local", c.sourceSHA, c.dns.ConfigSHA256, c.proofs, c.dns, c.physical, "pending-live-proof",
		c.originalConfigSHA, c.projection, plan})
	if err != nil {
		return nodeChainError
	}
	c.metadata = string(meta)
	return nil
}

// Require the unique RFC 7748 u-coordinate representation. In particular a
// high-bit or field-modulus alias cannot create a second selected node proof.
func nodeChainCanonicalPeer(value string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value || raw[31]&128 != 0 {
		return false
	}
	less := false
	for i := 31; i >= 0; i-- {
		limit := byte(255)
		if i == 31 {
			limit = 127
		} else if i == 0 {
			limit = 237
		}
		if raw[i] != limit {
			if raw[i] > limit {
				return false
			}
			less = true
			break
		}
	}
	if !less {
		return false
	}
	peer, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return false
	}
	var scalar [32]byte
	scalar[0] = 9
	key, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		return false
	}
	shared, err := key.ECDH(peer)
	clear(shared)
	return err == nil
}

func (c *NodeChain) captureSeal() string {
	if c == nil {
		return ""
	}
	raw, err := json.Marshal([]any{"routervpn-node-chain-capture-v1", c.sourceJSON, c.sourceSHA,
		c.config, c.metadata, c.proofs, c.dns, c.physical, c.originalConfigSHA, c.projection})
	if err != nil {
		return ""
	}
	seal := externalDigest(raw)
	clear(raw)
	return seal
}

func (c *NodeChain) validateCapture() error {
	if c == nil || c.seal == "" || c.captureSeal() != c.seal || len(c.nodes) != len(c.proofs) {
		return nodeChainError
	}
	for position, node := range c.nodes {
		proof := c.proofs[position]
		if node == nil || node.validateNodeDesktopCapture() != nil || proof.Position != position ||
			node.source != proof.SourceSHA256 || node.mode != proof.Mode ||
			predecessorText(node.profile, "id") != proof.ProfileID ||
			predecessorText(node.profile, "node_proof_id") != proof.NodeID {
			return nodeChainError
		}
	}
	return nil
}

func (c *NodeChain) Config() string               { return c.config }
func (c *NodeChain) SourceSHA256() string         { return c.sourceSHA }
func (c *NodeChain) ConfigSHA256() string         { return c.dns.ConfigSHA256 }
func (c *NodeChain) OriginalConfigSHA256() string { return c.originalConfigSHA }
func (c *NodeChain) TargetOS() string             { return c.projection.TargetOS }
func (c *NodeChain) RestoredMTU() int             { return c.projection.RestoredMTU }

// Metadata is private launch metadata, never a progress/status response.
func (c *NodeChain) Metadata() string    { return c.metadata }
func (c *NodeChain) FinalTag() string    { return c.proofs[len(c.proofs)-1].Tag }
func (c *NodeChain) SelectorTag() string { return SelectorTag }
func (c *NodeChain) ProofInventory() []NodeChainProof {
	return append([]NodeChainProof(nil), c.proofs...)
}
func (c *NodeChain) PrefixTags() []string {
	result := make([]string, len(c.proofs))
	for i, proof := range c.proofs {
		result[i] = proof.Tag
	}
	return result
}
func (c *NodeChain) DNSCapture() NodeChainDNSCapture { return c.dns }
func (c *NodeChain) PhysicalEgress() ([]PhysicalEgress, error) {
	if err := c.validateCapture(); err != nil {
		return nil, err
	}
	return append([]PhysicalEgress(nil), c.physical...), nil
}

func (c *NodeChain) LaunchInput() (string, error) {
	if c.validateCapture() != nil {
		return "", nodeChainError
	}
	var source NodeChainSource
	if exactJSON([]byte(c.sourceJSON), &source, NodeChainInputLimit) != nil {
		return "", nodeChainError
	}
	record := nodeChainLaunchRecord{Kind: "routervpn-node-chain-launch-input", NodeChainSource: source,
		SourceSHA256: c.sourceSHA, ConfigSHA256: c.dns.ConfigSHA256,
		MetadataSHA256: externalDigest([]byte(c.metadata)), OriginalConfigSHA256: c.originalConfigSHA,
		TargetOS: c.projection.TargetOS, RestoredMTU: c.projection.RestoredMTU,
		ProjectionKind: c.projection.Kind, SessionID: c.projection.SessionID}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > NodeChainInputLimit {
		clear(raw)
		return "", nodeChainError
	}
	result := string(raw)
	clear(raw)
	return result, nil
}

func ParseNodeChainLaunchInput(input string) (*NodeChain, error) {
	var record nodeChainLaunchRecord
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil ||
		record.Kind != "routervpn-node-chain-launch-input" ||
		!proofID.MatchString(record.SourceSHA256) || !proofID.MatchString(record.ConfigSHA256) ||
		!proofID.MatchString(record.MetadataSHA256) || !proofID.MatchString(record.OriginalConfigSHA256) {
		return nil, nodeChainError
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != input {
		return nil, nodeChainError
	}
	clear(canonical)
	source, err := json.Marshal(record.NodeChainSource)
	if err != nil {
		return nil, nodeChainError
	}
	chain, err := NewNodeChain(string(source))
	clear(source)
	if err == nil && record.ProjectionKind == nodeChainDesktopPhysicalKind {
		var policy *DesktopNodeChainPolicy
		policy, err = NewDesktopNodeChainPolicy(chain, record.SessionID, record.TargetOS, record.RestoredMTU)
		if err == nil {
			chain = policy.chain
		}
	} else if record.ProjectionKind != "" || record.SessionID != "" {
		return nil, nodeChainError
	} else if err == nil && record.TargetOS != "" {
		chain, err = ProjectNodeChain(chain, record.TargetOS, record.RestoredMTU)
	} else if record.RestoredMTU != 0 {
		return nil, nodeChainError
	}
	if err != nil || chain.sourceSHA != record.SourceSHA256 ||
		chain.dns.ConfigSHA256 != record.ConfigSHA256 ||
		externalDigest([]byte(chain.metadata)) != record.MetadataSHA256 ||
		chain.originalConfigSHA != record.OriginalConfigSHA256 {
		return nil, nodeChainError
	}
	return chain, nil
}

func nodeChainNamespace(position int, source, family, original string) string {
	return fmt.Sprintf("routervpn-chain-%d-%s-%s-%s", position, source[:12], family, externalDigest([]byte(original))[:12])
}

func nodeChainSamePhysical(actual, expected []PhysicalEgress) bool {
	return len(actual) != 0 && reflect.DeepEqual(actual, expected)
}
