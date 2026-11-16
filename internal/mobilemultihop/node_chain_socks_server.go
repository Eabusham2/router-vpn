package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"router-vpn/internal/multihoprelay"
)

// NewNodeChainSOCKSServerPolicy captures only the administrator's SOCKS5 ->
// paired SS2022 suffix. The entry identity authenticates the separate lease;
// it does not manufacture a packet endpoint on the server. Generic parsers
// deliberately continue to refuse schema three.
func NewNodeChainSOCKSServerPolicy(source string) (*NodeChainServerPolicy, error) {
	return newNodeChainServerPolicyFamily(source, nil, 3)
}

type nodeChainSOCKSServerScope struct {
	self     *nodeChainSOCKSServerScope
	policy   *NodeChainServerPolicy
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
	return s != nil && s.self == s && s.policy != nil && s.policy.socks == s && s.policy.socksMiddle == s.middle &&
		s.middle != nil && s.middle.validate() == nil && s.final != nil && s.final.validateNodeDesktopCapture() == nil &&
		s.policy.connect == nil && s.policy.connectMiddle == nil && s.policy.importedMiddle == nil && s.policy.carrier == nil &&
		len(s.policy.nodes) == 2 && s.policy.nodes[0] == nil && s.policy.nodes[1] == s.final && s.policy.descriptor.Schema == 3
}
func (s *nodeChainSOCKSServerScope) members() ([]nodeChainGraphMember, []*externalPredecessor, error) {
	if !s.original() {
		return nil, nil, nodeChainServerError
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
	return []nodeChainGraphMember{{profile: s.middle.selection.Profile, source: s.middle.source, mode: "socks5", imported: true}, {profile: s.final.profile, source: s.final.source, mode: s.final.mode}}, []*externalPredecessor{middle, final}, nil
}
func (s *nodeChainSOCKSServerScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor) error {
	want, graphs, err := s.members()
	if err != nil || !reflect.DeepEqual(want, members) || len(closures) != 2 || len(s.closures) != 2 {
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
	if !s.original() || len(proofs) != 2 || len(s.closures) != 2 {
		return nil, nodeChainServerError
	}
	for i, source := range []string{s.middle.source, s.final.source} {
		if proofs[i].Position != i || proofs[i].SourceSHA256 != source || proofs[i].Tag != nodeChainNamespace(i, source, "node", s.closures[i].finalTag) {
			return nil, nodeChainServerError
		}
	}
	raw, err := json.Marshal(s.closures[0].final)
	if err != nil {
		return nil, err
	}
	p := &nodeChainSOCKSServerPhysicalProof{scope: s, config: config, middleTag: proofs[0].Tag, middleJSON: string(raw)}
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
	middle.final["tag"] = nodeChainNamespace(0, p.scope.middle.source, "node", middle.finalTag)
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
	if p == nil || p.validate(p.config) != nil || tag != p.middleTag || node["type"] != "socks" || node["version"] != "5" || node["detour"] != nil || node["udp_over_tcp"] != nil {
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
	d, err := p.socks.middle.devicePolicy()
	if err != nil {
		return NodeChainSOCKSDevicePolicy{}, err
	}
	return NodeChainSOCKSDevicePolicy{Position: 1, ProfileID: p.socks.middle.selection.ExitID, KillSwitchPolicy: d.KillSwitchPolicy, IPv6Mode: d.IPv6Mode, HomeLANAccess: d.HomeLANAccess}, nil
}
