package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

// NodeChainCONNECTSource is a closed source/compiler result. Execution retains
// its original typed owner; source bytes alone grant no Run or Ready authority.
// Existing generic NodeChain parsers continue to reject its schema 4 source.
type NodeChainCONNECTSource struct {
	sourceJSON, config, seal string
	pair                     *NodeChain
	middle                   *nodeChainCONNECTMember
	metadata                 NodeChainCONNECTSourceMetadata
	desktop                  *nodeChainCONNECTDesktopBinding
	integrity                *nodeChainCONNECTIntegrity
}

type NodeChainCONNECTDevicePolicy struct {
	Position         int    `json:"position"`
	ProfileID        string `json:"profile_id"`
	KillSwitchPolicy string `json:"kill_switch_policy"`
	IPv6Mode         string `json:"ipv6_mode"`
	HomeLANAccess    bool   `json:"home_lan_access"`
}

// This receipt describes original source and configured bounds only. It is
// neither a native owner nor evidence of a live proof, selected route or PMTU.
type NodeChainCONNECTSourceMetadata struct {
	Kind                string                         `json:"kind"`
	Schema              int                            `json:"schema"`
	TransportCapability string                         `json:"transport_capability"`
	NativeAdmission     string                         `json:"native_admission"`
	SourceSHA256        string                         `json:"source_sha256"`
	ConfigSHA256        string                         `json:"config_sha256"`
	Proofs              []NodeChainProof               `json:"proofs"`
	DNS                 NodeChainDNSCapture            `json:"dns"`
	Physical            []PhysicalEgress               `json:"physical"`
	MTU                 NodeChainMTUPlan               `json:"mtu"`
	Devices             []NodeChainCONNECTDevicePolicy `json:"devices"`
}

// NewNodeChainCONNECTSource retains one to six original paired packet prefixes,
// one CONNECT member, and the paired SS final. The paired constructor still
// validates every original member and identity before any closure is composed.
func NewNodeChainCONNECTSource(input string) (*NodeChainCONNECTSource, error) {
	var source NodeChainSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil ||
		source.Schema != 4 || source.Execution != "local" || len(source.Nodes) < 3 || len(source.Nodes) > NodeChainMaximumNodes ||
		len(source.IdentitySources) != len(source.Nodes) {
		return nil, nodeChainCONNECTSourceError
	}
	middlePosition := len(source.Nodes) - 2
	for i, identity := range source.IdentitySources {
		if (i == middlePosition) != (identity == "") {
			return nil, nodeChainCONNECTSourceError
		}
	}
	middle, err := parseNodeChainCONNECTMember(source.Nodes[middlePosition])
	if err != nil {
		return nil, err
	}
	paired := NodeChainSource{Schema: 1, Execution: "local"}
	for i := range source.Nodes {
		if i == middlePosition {
			continue
		}
		paired.Nodes = append(paired.Nodes, source.Nodes[i])
		paired.IdentitySources = append(paired.IdentitySources, source.IdentitySources[i])
	}
	pairJSON, err := json.Marshal(paired)
	if err != nil {
		return nil, nodeChainCONNECTSourceError
	}
	pair, err := NewNodeChain(string(pairJSON))
	if err != nil {
		return nil, nodeChainCONNECTSourceError
	}
	members, closures, err := nodeChainCONNECTMembers(pair, middle)
	if err != nil {
		return nil, err
	}
	for _, closure := range closures {
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return nil, nodeChainCONNECTSourceError
		}
	}
	physical, err := pair.nodes[0].PhysicalEgress()
	if err != nil {
		return nil, nodeChainCONNECTSourceError
	}
	scope, err := newNodeChainCONNECTProofScope(pair, middle, closures)
	if err != nil {
		return nil, err
	}
	config, proofs, dns, actualPhysical, err := compileNodeChainClosuresWithCONNECT(members, closures, physical, scope)
	if err != nil {
		return nil, err
	}
	mtu, err := nodeChainMTUPlan(config, proofs)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(source)
	if err != nil || len(canonical) > NodeChainInputLimit {
		return nil, nodeChainCONNECTSourceError
	}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-connect-source-v1", string(canonical)})
	sourceSHA, configSHA := externalDigest(digest), externalDigest([]byte(config))
	dns.SourceSHA256, dns.ConfigSHA256 = sourceSHA, configSHA
	result := &NodeChainCONNECTSource{
		sourceJSON: string(canonical), config: config, pair: pair, middle: middle,
		metadata: NodeChainCONNECTSourceMetadata{
			Kind: "routervpn-node-chain-connect-source", Schema: 1, NativeAdmission: "closed", TransportCapability: "uot-v2",
			SourceSHA256: sourceSHA, ConfigSHA256: configSHA, Proofs: proofs,
			DNS: dns, Physical: actualPhysical, MTU: mtu,
		},
	}
	for position := range members {
		var device nodeChainImportedDevicePolicy
		if position == middlePosition {
			device, err = middle.devicePolicy()
		} else {
			index := position
			if position > middlePosition {
				index--
			}
			var captured NodeDesktopCapture
			captured, err = pair.nodes[index].DesktopCapture()
			device = nodeChainImportedDevicePolicy{
				captured.KillSwitchPolicy, captured.IPv6Mode, captured.HomeLANAccess,
			}
		}
		if err != nil {
			return nil, nodeChainCONNECTSourceError
		}
		result.metadata.Devices = append(result.metadata.Devices, NodeChainCONNECTDevicePolicy{
			Position: position, ProfileID: proofs[position].ProfileID,
			KillSwitchPolicy: device.KillSwitchPolicy, IPv6Mode: device.IPv6Mode,
			HomeLANAccess: device.HomeLANAccess,
		})
	}
	result.seal = result.digest()
	if result.retainIntegrity() != nil {
		return nil, nodeChainCONNECTSourceError
	}
	return result, nil
}

func (p *NodeChainCONNECTSource) digest() string {
	if p == nil || p.pair == nil || p.middle == nil {
		return ""
	}
	values := []any{
		"routervpn-node-chain-connect-compiler-v1", p.sourceJSON, p.config, p.metadata, p.pair.seal, p.middle.seal,
	}
	if p.desktop != nil {
		values = append(values, p.desktop.currentSeal())
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (p *NodeChainCONNECTSource) validate() error {
	if p == nil || !p.integrity.current(p) {
		return nodeChainCONNECTSourceError
	}
	return nil
}

func (p *NodeChainCONNECTSource) validateCompiled() error {
	if p == nil || p.seal == "" || p.digest() != p.seal || p.pair.validateCapture() != nil ||
		p.middle.validate() != nil || p.metadata.Kind != "routervpn-node-chain-connect-source" ||
		p.metadata.Schema != 1 || p.metadata.NativeAdmission != "closed" || p.metadata.TransportCapability != "uot-v2" {
		return nodeChainCONNECTSourceError
	}
	if p.desktop != nil && p.desktop.validate(p) != nil {
		return nodeChainCONNECTSourceError
	}
	return nil
}

// Source returns the complete private constructor input, including the exact
// original import. It must never be used as a progress/status payload.
func (p *NodeChainCONNECTSource) Source() (string, error) {
	if p.validate() != nil {
		return "", nodeChainCONNECTSourceError
	}
	return p.sourceJSON, nil
}

func (p *NodeChainCONNECTSource) ReadValidated() (string, NodeChainCONNECTSourceMetadata, error) {
	if p.validate() != nil {
		return "", NodeChainCONNECTSourceMetadata{}, nodeChainCONNECTSourceError
	}
	meta := p.metadata
	meta.Proofs = append([]NodeChainProof(nil), meta.Proofs...)
	meta.Physical = append([]PhysicalEgress(nil), meta.Physical...)
	meta.MTU.Prefixes = append([]NodeChainMTUBound(nil), meta.MTU.Prefixes...)
	meta.Devices = append([]NodeChainCONNECTDevicePolicy(nil), meta.Devices...)
	return p.config, meta, nil
}

// nodeChainCONNECTMembers reconstructs all original immutable paired members.
// The imported member remains penultimate; no arbitrary graph can supply UoT
// authority, and every earlier member must retain a supported packet owner.
func nodeChainCONNECTMembers(pair *NodeChain, middle *nodeChainCONNECTMember) ([]nodeChainGraphMember, []*externalPredecessor, error) {
	if pair == nil || pair.validateCapture() != nil || len(pair.nodes) < 2 || len(pair.nodes) >= NodeChainMaximumNodes ||
		pair.importedMiddle != nil || pair.openVPNMiddle != nil || pair.socksSource != nil || pair.connectSource != nil || middle == nil || middle.validate() != nil {
		return nil, nil, nodeChainCONNECTSourceError
	}
	members := make([]nodeChainGraphMember, 0, len(pair.nodes)+1)
	closures := make([]*externalPredecessor, 0, len(pair.nodes)+1)
	for i, node := range pair.nodes {
		final := i == len(pair.nodes)-1
		if node == nil || (!final && !NodeChainPrefixMode(node.mode)) || (final && node.mode != "shadowsocks") ||
			middle.selection.ExitID == predecessorText(node.profile, "id") {
			return nil, nil, nodeChainCONNECTSourceError
		}
		if final {
			closure, err := middle.closure()
			if err != nil {
				return nil, nil, err
			}
			members = append(members, nodeChainGraphMember{profile: middle.selection.Profile, source: middle.source, mode: middle.selection.Protocol, imported: true})
			closures = append(closures, closure)
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil {
			return nil, nil, err
		}
		members = append(members, nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode})
		closures = append(closures, closure)
	}
	return members, closures, nil
}

// This private construction receipt retains every original closure pointer.
// Validation occurs before the compiler mutates their private graph copies.
type nodeChainCONNECTProofScope struct {
	pair     *NodeChain
	middle   *nodeChainCONNECTMember
	closures []*externalPredecessor
	nodes    []*NodeProfile
}

func newNodeChainCONNECTProofScope(pair *NodeChain, middle *nodeChainCONNECTMember, closures []*externalPredecessor) (*nodeChainCONNECTProofScope, error) {
	if pair == nil || pair.validateCapture() != nil || len(pair.nodes) < 2 || len(pair.nodes) >= NodeChainMaximumNodes || middle == nil || middle.validate() != nil || len(closures) != len(pair.nodes)+1 {
		return nil, nodeChainCONNECTSourceError
	}
	for _, closure := range closures {
		if closure == nil {
			return nil, nodeChainCONNECTSourceError
		}
	}
	final := pair.nodes[len(pair.nodes)-1]
	capability, err := importedCONNECTCapture(closures[len(closures)-1].graph, closures[len(closures)-1].final, "", final.mode, final.profile, final.inputs.Files)
	if err != nil || capability != "uot-v2" {
		return nil, nodeChainCONNECTSourceError
	}
	return &nodeChainCONNECTProofScope{pair: pair, middle: middle, closures: append([]*externalPredecessor(nil), closures...), nodes: append([]*NodeProfile(nil), pair.nodes...)}, nil
}

func (s *nodeChainCONNECTProofScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor) error {
	if !s.ownsOriginalNodes() {
		return nodeChainCONNECTSourceError
	}
	wantedMembers, wanted, err := nodeChainCONNECTMembers(s.pair, s.middle)
	if err != nil || !reflect.DeepEqual(members, wantedMembers) || len(closures) != len(wanted) || len(s.closures) != len(wanted) {
		return nodeChainCONNECTSourceError
	}
	final := s.pair.nodes[len(s.pair.nodes)-1]
	last := wanted[len(wanted)-1]
	capability, err := importedCONNECTCapture(last.graph, last.final, "", final.mode, final.profile, final.inputs.Files)
	if err != nil || capability != "uot-v2" {
		return nodeChainCONNECTSourceError
	}
	for i := range wanted {
		if closures[i] == nil || closures[i] != s.closures[i] || !reflect.DeepEqual(closures[i], wanted[i]) {
			return nodeChainCONNECTSourceError
		}
	}
	return nil
}

func (s *nodeChainCONNECTProofScope) ownsOriginalNodes() bool {
	if s == nil || s.pair == nil || len(s.nodes) != len(s.pair.nodes) || len(s.nodes) < 2 {
		return false
	}
	for i, node := range s.nodes {
		if node == nil || node != s.pair.nodes[i] {
			return false
		}
	}
	return true
}
