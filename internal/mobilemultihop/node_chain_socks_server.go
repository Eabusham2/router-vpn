package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"router-vpn/internal/multihoprelay"
)

// NewNodeChainSOCKSServerPolicy captures the administrator's original packet
// prefixes, literal SOCKS5 import and paired SS2022 final. The entry identity
// authenticates the separate lease;
// it does not manufacture a packet endpoint on the server. Generic parsers
// deliberately continue to refuse schema three.
func NewNodeChainSOCKSServerPolicy(source string) (*NodeChainServerPolicy, error) {
	return newNodeChainServerPolicyFamily(source, nil, 3)
}

type nodeChainSOCKSServerScope struct {
	self     *nodeChainSOCKSServerScope
	policy   *NodeChainServerPolicy
	carrier  *NodeChainServerCarrier
	prefixes []*NodeProfile
	middle   *nodeChainSOCKSMember
	final    *NodeProfile
	closures []*externalPredecessor
}

// The paired SS2022 service already supplies AES. Whitening is its captured
// authenticated wrapper, not a second proxy or a new physical dial owner.
// Keep the final's exact original closure and forbid CONNECT's UoT authority.
func nodeChainSOCKSServerFinalClosure(node *NodeProfile, closure *externalPredecessor) bool {
	if node == nil || node.mode != "shadowsocks" || !nodeChainFinalClosure(node, closure) ||
		closure.final["method"] != NativeStartLayerMethod || closure.final["udp_over_tcp"] != nil {
		return false
	}
	switch predecessorText(node.profile, "start_layer") {
	case "", "off", "aes-256-gcm":
		return closure.final["type"] == "shadowsocks"
	case "aes-256-gcm+xor-whitening":
		return closure.final["type"] == "routervpn-aes-xor"
	default:
		return false
	}
}

func (s *nodeChainSOCKSServerScope) original() bool {
	if s == nil || s.self != s || s.policy == nil || s.policy.socks != s || s.policy.socksMiddle != s.middle || s.policy.carrier != s.carrier ||
		s.middle == nil || s.middle.validate() != nil || s.final == nil || s.final.validateNodeDesktopCapture() != nil ||
		s.policy.connect != nil || s.policy.connectMiddle != nil || s.policy.importedMiddle != nil ||
		len(s.policy.nodes) < 2 || len(s.policy.nodes) > NodeChainMaximumNodes-1 || len(s.prefixes) != len(s.policy.nodes)-2 ||
		s.policy.nodes[len(s.policy.nodes)-2] != nil || s.policy.nodes[len(s.policy.nodes)-1] != s.final || s.policy.descriptor.Schema != 3 {
		return false
	}
	for i, original := range s.prefixes {
		if original == nil || s.policy.nodes[i] != original || !NodeChainPrefixMode(original.mode) || original.validateNodeDesktopCapture() != nil {
			return false
		}
	}
	return s.carrier == nil || len(s.prefixes) > 0 && s.carrier.family == 3 && s.carrier.sealed()
}
func (s *nodeChainSOCKSServerScope) members() ([]nodeChainGraphMember, []*externalPredecessor, error) {
	if !s.original() {
		return nil, nil, nodeChainServerError
	}
	members := make([]nodeChainGraphMember, 0, len(s.prefixes)+2)
	closures := make([]*externalPredecessor, 0, len(s.prefixes)+2)
	for i, original := range s.prefixes {
		closure, err := nodeMultihopPredecessor(original)
		if err != nil {
			return nil, nil, err
		}
		if i == 0 && s.carrier != nil {
			if err = s.carrier.apply(original, closure); err != nil {
				return nil, nil, err
			}
		}
		members = append(members, nodeChainGraphMember{profile: original.profile, source: original.source, mode: original.mode})
		closures = append(closures, closure)
	}
	middle, err := s.middle.closure()
	if err != nil {
		return nil, nil, err
	}
	final, err := nodeMultihopPredecessor(s.final)
	if err != nil {
		return nil, nil, err
	}
	if !nodeChainSOCKSServerFinalClosure(s.final, final) {
		return nil, nil, nodeChainServerError
	}
	members = append(members, nodeChainGraphMember{profile: s.middle.selection.Profile, source: s.middle.source, mode: "socks5", imported: true}, nodeChainGraphMember{profile: s.final.profile, source: s.final.source, mode: s.final.mode})
	closures = append(closures, middle, final)
	return members, closures, nil
}
func (s *nodeChainSOCKSServerScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor) error {
	want, graphs, err := s.members()
	if err != nil || !reflect.DeepEqual(want, members) || len(closures) != len(want) || len(s.closures) != len(want) {
		return nodeChainServerError
	}
	for i := range graphs {
		if closures[i] != s.closures[i] || !reflect.DeepEqual(closures[i], graphs[i]) {
			return nodeChainServerError
		}
	}
	return nil
}

// This private compiler witness preserves the dynamic association requirement.
// It grants only the literal TCP control inventory, never a guessed UDP relay.
// Native Server admission must separately retain the negotiated UDP socket and
// its original authenticated control until their joined close.
type nodeChainSOCKSServerPhysicalProof struct {
	self                          *nodeChainSOCKSServerPhysicalProof
	scope                         *nodeChainSOCKSServerScope
	config, middleTag, middleJSON string
}

func (s *nodeChainSOCKSServerScope) captureTransport(config string, proofs []NodeChainProof) (nodeChainCapturedTransportProof, error) {
	if !s.original() || len(proofs) != len(s.prefixes)+2 || len(s.closures) != len(proofs) {
		return nil, nodeChainServerError
	}
	members, _, err := s.members()
	if err != nil {
		return nil, err
	}
	for i, member := range members {
		source := member.source
		if proofs[i].Position != i || proofs[i].SourceSHA256 != source || proofs[i].Tag != nodeChainNamespace(i, source, "node", s.closures[i].finalTag) {
			return nil, nodeChainServerError
		}
	}
	middle := len(proofs) - 2
	raw, err := json.Marshal(s.closures[middle].final)
	if err != nil {
		return nil, err
	}
	p := &nodeChainSOCKSServerPhysicalProof{scope: s, config: config, middleTag: proofs[middle].Tag, middleJSON: string(raw)}
	p.self = p
	if p.validate(config) != nil {
		return nil, nodeChainServerError
	}
	return p, nil
}
func (p *nodeChainSOCKSServerPhysicalProof) validate(config string) error {
	if p == nil || p.self != p || !p.scope.original() || p.config == "" || p.config != config {
		return nodeChainServerError
	}
	middle, err := p.scope.middle.closure()
	if err != nil {
		return err
	}
	position := len(p.scope.prefixes)
	middle.final["tag"] = nodeChainNamespace(position, p.scope.middle.source, "node", middle.finalTag)
	if position > 0 {
		previous := p.scope.prefixes[position-1]
		middle.final["detour"] = nodeChainNamespace(position-1, previous.source, "node", p.scope.closures[position-1].finalTag)
	}
	raw, err := json.Marshal(middle.final)
	if err != nil || string(raw) != p.middleJSON || middle.final["tag"] != p.middleTag {
		return nodeChainServerError
	}
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return nodeChainServerError
	}
	rows, ok := graph["outbounds"].([]any)
	if !ok {
		return nodeChainServerError
	}
	found := 0
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nodeChainServerError
		}
		if row["tag"] == p.middleTag {
			found++
			if !reflect.DeepEqual(row, middle.final) {
				return nodeChainServerError
			}
		}
	}
	if found != 1 {
		return nodeChainServerError
	}
	return nil
}
func (p *nodeChainSOCKSServerPhysicalProof) udpOverTCP(string, map[string]any) (bool, error) {
	return false, nil
}
func (p *nodeChainSOCKSServerPhysicalProof) negotiatedAssociation(tag string, node map[string]any) error {
	if p == nil || p.validate(p.config) != nil || tag != p.middleTag || node["type"] != "socks" || node["version"] != "5" || node["udp_over_tcp"] != nil {
		return nodeChainServerError
	}
	raw, err := json.Marshal(node)
	if err != nil || string(raw) != p.middleJSON {
		return nodeChainServerError
	}
	return nil
}
func (p *NodeChainServerPolicy) SOCKSServerDevice(capture multihoprelay.NodeChainCapture) (NodeChainSOCKSDevicePolicy, error) {
	if p == nil || p.socks == nil {
		return NodeChainSOCKSDevicePolicy{}, nodeChainServerError
	}
	if _, err := p.binding(capture); err != nil {
		return NodeChainSOCKSDevicePolicy{}, err
	}
	return p.readSOCKSServerDevice()
}

func (p *NodeChainServerPolicy) readSOCKSServerDevice() (NodeChainSOCKSDevicePolicy, error) {
	d, err := p.socks.middle.devicePolicy()
	if err != nil {
		return NodeChainSOCKSDevicePolicy{}, err
	}
	return NodeChainSOCKSDevicePolicy{Position: len(p.nodes) - 1, ProfileID: p.socks.middle.selection.ExitID, KillSwitchPolicy: d.KillSwitchPolicy, IPv6Mode: d.IPv6Mode, HomeLANAccess: d.HomeLANAccess}, nil
}

// ReadSOCKSServerCapture makes one fresh, complete source and lease observation
// for the native owner. The configuration, device policy and independent proof
// slice belong to that same observation; callers retain no validity cache.
func (p *NodeChainServerPolicy) ReadSOCKSServerCapture(capture multihoprelay.NodeChainCapture) (string, NodeChainSOCKSDevicePolicy, []NodeChainProof, error) {
	if p == nil || p.socks == nil {
		return "", NodeChainSOCKSDevicePolicy{}, nil, nodeChainServerError
	}
	if _, err := p.binding(capture); err != nil {
		return "", NodeChainSOCKSDevicePolicy{}, nil, err
	}
	device, err := p.readSOCKSServerDevice()
	if err != nil {
		return "", NodeChainSOCKSDevicePolicy{}, nil, err
	}
	return p.config, device, append([]NodeChainProof(nil), p.proofs...), nil
}
