package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"router-vpn/internal/multihoprelay"
)

// NewNodeChainCONNECTServerPolicy constructs only the operator-owned stream
// suffix, including its independently captured paired packet prefixes.
// Entry identity authenticates the separate client lease; it is never
// used to invent a WireGuard lower object on this worker.
func NewNodeChainCONNECTServerPolicy(source string) (*NodeChainServerPolicy, error) {
	return newNodeChainServerPolicyCaptured(source, nil, true)
}

type nodeChainCONNECTServerScope struct {
	self     *nodeChainCONNECTServerScope
	policy   *NodeChainServerPolicy
	carrier  *NodeChainServerCarrier
	middle   *nodeChainCONNECTMember
	final    *NodeProfile
	prefixes []*NodeProfile
	closures []*externalPredecessor
}

func (s *nodeChainCONNECTServerScope) original() bool {
	if s == nil || s.self != s || s.policy == nil || s.policy.connect != s || s.policy.carrier != s.carrier ||
		s.middle == nil || s.policy.connectMiddle != s.middle || s.middle.validate() != nil || s.final == nil || s.final.validateNodeDesktopCapture() != nil ||
		s.policy.importedMiddle != nil || s.policy.socks != nil || len(s.policy.nodes) < 2 || len(s.policy.nodes) > NodeChainMaximumNodes-1 ||
		len(s.prefixes) != len(s.policy.nodes)-2 || s.policy.nodes[len(s.policy.nodes)-2] != nil || s.policy.nodes[len(s.policy.nodes)-1] != s.final || s.policy.descriptor.Schema != 4 {
		return false
	}
	for i, original := range s.prefixes {
		if original == nil || s.policy.nodes[i] != original || !NodeChainPrefixMode(original.mode) || original.validateNodeDesktopCapture() != nil {
			return false
		}
	}
	return s.policy.carrier == nil || len(s.prefixes) > 0 && s.policy.carrier.family == 4 && s.policy.carrier.sealed()
}

func (s *nodeChainCONNECTServerScope) members() ([]nodeChainGraphMember, []*externalPredecessor, error) {
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
		if i == 0 && s.policy.carrier != nil {
			if err = s.policy.carrier.apply(original, closure); err != nil {
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
	capability, err := importedCONNECTCapture(final.graph, final.final, "", s.final.mode, s.final.profile, s.final.inputs.Files)
	if err != nil || capability != "uot-v2" {
		return nil, nil, nodeChainServerError
	}
	members = append(members,
		nodeChainGraphMember{profile: s.middle.selection.Profile, source: s.middle.source, mode: s.middle.selection.Protocol, imported: true},
		nodeChainGraphMember{profile: s.final.profile, source: s.final.source, mode: s.final.mode})
	closures = append(closures, middle, final)
	return members, closures, nil
}

func (s *nodeChainCONNECTServerScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor) error {
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

type nodeChainCONNECTServerPhysicalProof struct {
	self                        *nodeChainCONNECTServerPhysicalProof
	scope                       *nodeChainCONNECTServerScope
	config, finalTag, finalJSON string
}

func (s *nodeChainCONNECTServerScope) captureTransport(config string, proofs []NodeChainProof) (nodeChainCapturedTransportProof, error) {
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
	raw, err := json.Marshal(s.closures[len(s.closures)-1].final)
	if err != nil {
		return nil, err
	}
	p := &nodeChainCONNECTServerPhysicalProof{scope: s, config: config, finalTag: proofs[len(proofs)-1].Tag, finalJSON: string(raw)}
	p.self = p
	if p.validate(config) != nil {
		return nil, nodeChainServerError
	}
	return p, nil
}

func (p *nodeChainCONNECTServerPhysicalProof) validate(config string) error {
	if p == nil || p.self != p || !p.scope.original() || p.config == "" || p.config != config {
		return nodeChainServerError
	}
	_, closures, err := p.scope.members()
	if err != nil {
		return err
	}
	last := len(closures) - 1
	final := closures[last].final
	final["tag"] = nodeChainNamespace(last, p.scope.final.source, "node", closures[last].finalTag)
	final["detour"] = nodeChainNamespace(last-1, p.scope.middle.source, "node", closures[last-1].finalTag)
	raw, err := json.Marshal(final)
	if err != nil || string(raw) != p.finalJSON || final["tag"] != p.finalTag {
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
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nodeChainServerError
		}
		if row["tag"] == p.finalTag {
			found++
			if !reflect.DeepEqual(row, final) {
				return nodeChainServerError
			}
		}
	}
	if found != 1 {
		return nodeChainServerError
	}
	return nil
}

func (p *nodeChainCONNECTServerPhysicalProof) udpOverTCP(tag string, node map[string]any) (bool, error) {
	if tag != p.finalTag {
		return false, nil
	}
	raw, err := json.Marshal(node)
	uot, ok := node["udp_over_tcp"].(map[string]any)
	if err != nil || string(raw) != p.finalJSON || !ok || len(uot) != 2 || uot["enabled"] != true || uot["version"] != float64(2) {
		return false, nodeChainServerError
	}
	return true, nil
}

func (p *NodeChainServerPolicy) CONNECTServerDevice(capture multihoprelay.NodeChainCapture) (NodeChainCONNECTDevicePolicy, error) {
	if p == nil || p.connect == nil {
		return NodeChainCONNECTDevicePolicy{}, nodeChainServerError
	}
	if _, err := p.binding(capture); err != nil {
		return NodeChainCONNECTDevicePolicy{}, err
	}
	device, err := p.connect.middle.devicePolicy()
	if err != nil {
		return NodeChainCONNECTDevicePolicy{}, err
	}
	return NodeChainCONNECTDevicePolicy{Position: len(p.nodes) - 1, ProfileID: p.connect.middle.selection.ExitID, KillSwitchPolicy: device.KillSwitchPolicy, IPv6Mode: device.IPv6Mode, HomeLANAccess: device.HomeLANAccess}, nil
}
