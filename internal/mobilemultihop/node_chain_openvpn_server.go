package mobilemultihop

import (
	"encoding/json"
	"reflect"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

// NodeChainOpenVPNServerPairing is operator-private provenance. The Server
// owns only its provider credentials and dedicated key. The Local descriptor
// contains public identity, never the Local certificate key or password.
type NodeChainOpenVPNServerPairing struct {
	PrivateKey string                         `json:"private_key"`
	Local      nativeopenvpn.PublicDescriptor `json:"local"`
	Server     nativeopenvpn.PublicDescriptor `json:"server"`
}

type nodeChainOpenVPNServerScope struct {
	self     *nodeChainOpenVPNServerScope
	policy   *NodeChainServerPolicy
	carrier  *NodeChainServerCarrier
	middle   *nodeChainOpenVPNMember
	prefixes []*NodeProfile
	final    *NodeProfile
	pair     NodeChainOpenVPNServerPairing
	pairSHA  string
}

// NewNodeChainOpenVPNServerPolicy is the distinct schema-five entry. Generic
// Server constructors remain closed to OpenVPN's native connection authority.
func NewNodeChainOpenVPNServerPolicy(source string) (*NodeChainServerPolicy, error) {
	return newNodeChainServerPolicyFamily(source, nil, 5)
}

func nodeChainOpenVPNProfile(m *nodeChainOpenVPNMember) (nativeopenvpn.Profile, map[string]any, error) {
	if m == nil || m.validate() != nil {
		return nativeopenvpn.Profile{}, nil, nodeChainServerError
	}
	external, ok := m.selection.Profile["external"].(map[string]any)
	if !ok || external["protocol"] != "openvpn" {
		return nativeopenvpn.Profile{}, nil, nodeChainServerError
	}
	raw, err := json.Marshal(external["openvpn"])
	var profile nativeopenvpn.Profile
	if err != nil || json.Unmarshal(raw, &profile) != nil {
		return profile, nil, nodeChainServerError
	}
	return profile, external, nil
}

func nodeChainOpenVPNServerPair(m *nodeChainOpenVPNMember, pair *NodeChainOpenVPNServerPairing) (string, error) {
	profile, external, err := nodeChainOpenVPNProfile(m)
	if err != nil || pair == nil {
		return "", nodeChainServerError
	}
	// A Server import cannot smuggle the Local role's private pairing key.
	if _, exists := external["openvpn_pairing"]; exists {
		return "", nodeChainServerError
	}
	actual, err := nativeopenvpn.DescribePeer(profile, pair.PrivateKey)
	if err != nil || !reflect.DeepEqual(actual, pair.Server) {
		return "", nodeChainServerError
	}
	shared, err := nativeopenvpn.PairingAgreement(pair.PrivateKey, pair.Local.PairingPublicKey)
	clear(shared)
	if err != nil {
		return "", nodeChainServerError
	}
	return multihoprelay.NodeChainOpenVPNPairDigest(pair.Local, pair.Server)
}

func (s *nodeChainOpenVPNServerScope) original() bool {
	if s == nil || s.self != s || s.policy == nil || s.policy.openvpn != s || s.policy.openvpnMiddle != s.middle || s.policy.carrier != s.carrier ||
		s.middle == nil || s.policy.descriptor.Schema != 5 || s.policy.socks != nil || s.policy.connect != nil || s.policy.importedMiddle != nil ||
		len(s.policy.nodes) < 2 || len(s.policy.nodes) > NodeChainMaximumNodes-1 || len(s.prefixes) != len(s.policy.nodes)-2 ||
		s.policy.nodes[len(s.policy.nodes)-2] != nil || s.final == nil || s.policy.nodes[len(s.policy.nodes)-1] != s.final || s.final.validateNodeDesktopCapture() != nil {
		return false
	}
	for i, node := range s.prefixes {
		if node == nil || s.policy.nodes[i] != node || !NodeChainPrefixMode(node.mode) || node.validateNodeDesktopCapture() != nil {
			return false
		}
	}
	digest, err := nodeChainOpenVPNServerPair(s.middle, &s.pair)
	return err == nil && digest == s.pairSHA && (s.carrier == nil || len(s.prefixes) > 0 && s.carrier.family == 5 && s.carrier.sealed())
}

type NodeChainOpenVPNDevicePolicy struct {
	Position                              int
	ProfileID, KillSwitchPolicy, IPv6Mode string
	HomeLANAccess                         bool
}

// NodeChainOpenVPNServerCapture contains configured identity, not a connected
// receipt. The native worker must pin its actual endpoint and independently
// observe its original remote, generation, connection time and packet capacity.
type NodeChainOpenVPNServerCapture struct {
	Binding NodeChainServerBinding
	Middle  NodeChainOpenVPNCapture
	Device  NodeChainOpenVPNDevicePolicy
	Proofs  []NodeChainProof
}

func (p *NodeChainServerPolicy) ReadOpenVPNServerCapture(capture multihoprelay.NodeChainCapture) (string, NodeChainOpenVPNServerCapture, error) {
	var result NodeChainOpenVPNServerCapture
	if p == nil || p.openvpn == nil {
		return "", result, nodeChainServerError
	}
	binding, err := p.binding(capture)
	if err != nil {
		return "", result, err
	}
	position := len(p.nodes) - 2
	middle := p.openvpn.middle
	device, err := middle.devicePolicy()
	if err != nil {
		return "", result, err
	}
	var graph map[string]any
	if exactJSON([]byte(p.config), &graph, NodeChainInputLimit) != nil {
		return "", result, nodeChainServerError
	}
	rows, _ := graph["endpoints"].([]any)
	for _, raw := range rows {
		endpoint, ok := raw.(map[string]any)
		if !ok || endpoint["tag"] != p.proofs[position].Tag {
			continue
		}
		remotes, err := nativeopenvpn.Remotes(endpoint)
		mtu, ok := endpoint["mtu"].(float64)
		if err != nil || len(remotes) != 1 || !ok || mtu < 1280 || mtu > 65535 || mtu != float64(int(mtu)) {
			return "", result, nodeChainServerError
		}
		result = NodeChainOpenVPNServerCapture{Binding: binding,
			Middle: NodeChainOpenVPNCapture{Tag: p.proofs[position].Tag, SourceSHA256: middle.source, Remote: remotes[0], ConfiguredMTU: int(mtu)},
			Device: NodeChainOpenVPNDevicePolicy{Position: position + 1, ProfileID: middle.id(), KillSwitchPolicy: device.KillSwitchPolicy, IPv6Mode: device.IPv6Mode, HomeLANAccess: device.HomeLANAccess},
			Proofs: append([]NodeChainProof(nil), p.proofs...)}
		return p.config, result, nil
	}
	return "", result, nodeChainServerError
}
