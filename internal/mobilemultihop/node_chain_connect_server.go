package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"router-vpn/internal/multihoprelay"
)

// NewNodeChainCONNECTServerPolicy constructs only the operator-owned stream
// suffix. Entry identity authenticates the separate client lease; it is never
// used to invent a WireGuard lower object on this worker.
func NewNodeChainCONNECTServerPolicy(source string) (*NodeChainServerPolicy, error) {
	return newNodeChainServerPolicyCaptured(source, nil, true)
}

type nodeChainCONNECTServerScope struct {
	self     *nodeChainCONNECTServerScope
	policy   *NodeChainServerPolicy
	middle   *nodeChainCONNECTMember
	final    *NodeProfile
	closures []*externalPredecessor
}

func (s *nodeChainCONNECTServerScope) original() bool {
	return s != nil && s.self == s && s.policy != nil && s.policy.connect == s &&
		s.middle != nil && s.policy.connectMiddle == s.middle && s.middle.validate() == nil && s.final != nil && s.final.validateNodeDesktopCapture() == nil &&
		s.policy.importedMiddle == nil && s.policy.carrier == nil && len(s.policy.nodes) == 2 &&
		s.policy.nodes[0] == nil && s.policy.nodes[1] == s.final && s.policy.descriptor.Schema == 4
}

func (s *nodeChainCONNECTServerScope) members() ([]nodeChainGraphMember, []*externalPredecessor, error) {
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
	capability, err := importedCONNECTCapture(final.graph, final.final, "", s.final.mode, s.final.profile, s.final.inputs.Files)
	if err != nil || capability != "uot-v2" {
		return nil, nil, nodeChainServerError
	}
	return []nodeChainGraphMember{
		{profile: s.middle.selection.Profile, source: s.middle.source, mode: s.middle.selection.Protocol, imported: true},
		{profile: s.final.profile, source: s.final.source, mode: s.final.mode},
	}, []*externalPredecessor{middle, final}, nil
}

func (s *nodeChainCONNECTServerScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor) error {
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

type nodeChainCONNECTServerPhysicalProof struct {
	self                        *nodeChainCONNECTServerPhysicalProof
	scope                       *nodeChainCONNECTServerScope
	config, finalTag, finalJSON string
}

func (s *nodeChainCONNECTServerScope) captureTransport(config string, proofs []NodeChainProof) (nodeChainCapturedTransportProof, error) {
	if !s.original() || len(proofs) != 2 || len(s.closures) != 2 {
		return nil, nodeChainServerError
	}
	for i, source := range []string{s.middle.source, s.final.source} {
		if proofs[i].Position != i || proofs[i].SourceSHA256 != source || proofs[i].Tag != nodeChainNamespace(i, source, "node", s.closures[i].finalTag) {
			return nil, nodeChainServerError
		}
	}
	raw, err := json.Marshal(s.closures[1].final)
	if err != nil {
		return nil, err
	}
	p := &nodeChainCONNECTServerPhysicalProof{scope: s, config: config, finalTag: proofs[1].Tag, finalJSON: string(raw)}
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
	final := closures[1].final
	final["tag"] = nodeChainNamespace(1, p.scope.final.source, "node", closures[1].finalTag)
	final["detour"] = nodeChainNamespace(0, p.scope.middle.source, "node", closures[0].finalTag)
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
	return NodeChainCONNECTDevicePolicy{Position: 1, ProfileID: p.connect.middle.selection.ExitID, KillSwitchPolicy: device.KillSwitchPolicy, IPv6Mode: device.IPv6Mode, HomeLANAccess: device.HomeLANAccess}, nil
}
