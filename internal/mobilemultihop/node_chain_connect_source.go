package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

// NodeChainCONNECTSource is a dormant source/compiler result. It deliberately
// has no LaunchInput, Run, Ready or native projection method. Existing generic
// NodeChain parsers continue to reject its schema 4 source.
type NodeChainCONNECTSource struct {
	sourceJSON, config, seal string
	pair                     *NodeChain
	middle                   *nodeChainCONNECTMember
	metadata                 NodeChainCONNECTSourceMetadata
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

// NewNodeChainCONNECTSource validates the two original paired nodes using the
// existing constructor, then uses the same ordered closure compiler, physical
// traversal, final-DNS policy and per-prefix MTU projection as shipping paths.
func NewNodeChainCONNECTSource(input string) (*NodeChainCONNECTSource, error) {
	var source NodeChainSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil ||
		source.Schema != 4 || source.Execution != "local" || len(source.Nodes) != 3 ||
		len(source.IdentitySources) != 3 || source.IdentitySources[0] == "" ||
		source.IdentitySources[1] != "" || source.IdentitySources[2] == "" {
		return nil, nodeChainCONNECTSourceError
	}
	middle, err := parseNodeChainCONNECTMember(source.Nodes[1])
	if err != nil {
		return nil, err
	}
	paired := NodeChainSource{Schema: 1, Execution: "local",
		Nodes:           []string{source.Nodes[0], source.Nodes[2]},
		IdentitySources: []string{source.IdentitySources[0], source.IdentitySources[2]}}
	pairJSON, err := json.Marshal(paired)
	if err != nil {
		return nil, nodeChainCONNECTSourceError
	}
	pair, err := NewNodeChain(string(pairJSON))
	if err != nil || len(pair.nodes) != 2 || !NodeChainPrefixMode(pair.nodes[0].mode) ||
		pair.nodes[1].mode != "shadowsocks" ||
		middle.selection.ExitID == predecessorText(pair.nodes[0].profile, "id") ||
		middle.selection.ExitID == predecessorText(pair.nodes[1].profile, "id") {
		return nil, nodeChainCONNECTSourceError
	}
	first, err := nodeMultihopPredecessor(pair.nodes[0])
	if err != nil {
		return nil, nodeChainCONNECTSourceError
	}
	custom, err := middle.closure()
	if err != nil {
		return nil, err
	}
	final, err := nodeMultihopPredecessor(pair.nodes[1])
	if err != nil {
		return nil, nodeChainCONNECTSourceError
	}
	closures := []*externalPredecessor{first, custom, final}
	for _, closure := range closures {
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return nil, nodeChainCONNECTSourceError
		}
	}
	members := []nodeChainGraphMember{
		{profile: pair.nodes[0].profile, source: pair.nodes[0].source, mode: pair.nodes[0].mode},
		{profile: middle.selection.Profile, source: middle.source, mode: middle.selection.Protocol, imported: true},
		{profile: pair.nodes[1].profile, source: pair.nodes[1].source, mode: "shadowsocks"},
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
		if position == 1 {
			device, err = middle.devicePolicy()
		} else {
			index := 0
			if position == 2 {
				index = 1
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
	if result.validate() != nil {
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
	raw, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (p *NodeChainCONNECTSource) validate() error {
	if p == nil || p.seal == "" || p.digest() != p.seal || p.pair.validateCapture() != nil ||
		p.middle.validate() != nil || p.metadata.Kind != "routervpn-node-chain-connect-source" ||
		p.metadata.Schema != 1 || p.metadata.NativeAdmission != "closed" || p.metadata.TransportCapability != "uot-v2" {
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

// nodeChainCONNECTProofScope is a private one-construction receipt. Ordinary
// callers cannot supply a network flag. The exact three original closures are
// checked again before the shared compiler mutates their private copies.
type nodeChainCONNECTProofScope struct {
	pair     *NodeChain
	middle   *nodeChainCONNECTMember
	closures [3]*externalPredecessor
}

func newNodeChainCONNECTProofScope(pair *NodeChain, middle *nodeChainCONNECTMember, closures []*externalPredecessor) (*nodeChainCONNECTProofScope, error) {
	if pair == nil || pair.validateCapture() != nil || len(pair.nodes) != 2 ||
		middle == nil || middle.validate() != nil || len(closures) != 3 ||
		closures[0] == nil || closures[1] == nil || closures[2] == nil {
		return nil, nodeChainCONNECTSourceError
	}
	final := pair.nodes[1]
	// Existing authority includes every original SS method, key, service
	// declaration and supported layer. A TCP-only declaration cannot carry
	// the original Home AdGuard UDP policy and is not promoted here.
	capability, err := importedCONNECTCapture(closures[2].graph, closures[2].final, "",
		final.mode, final.profile, final.inputs.Files)
	if err != nil || capability != "uot-v2" {
		return nil, nodeChainCONNECTSourceError
	}
	return &nodeChainCONNECTProofScope{pair: pair, middle: middle,
		closures: [3]*externalPredecessor{closures[0], closures[1], closures[2]}}, nil
}

func (s *nodeChainCONNECTProofScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor) error {
	bad := nodeChainCONNECTSourceError
	if s == nil || s.pair == nil || s.pair.validateCapture() != nil || s.middle == nil ||
		s.middle.validate() != nil || len(s.pair.nodes) != 2 || len(members) != 3 || len(closures) != 3 {
		return bad
	}
	first, final := s.pair.nodes[0], s.pair.nodes[1]
	if !NodeChainPrefixMode(first.mode) || final.mode != "shadowsocks" ||
		(s.middle.selection.Protocol != "http-connect" && s.middle.selection.Protocol != "https-connect") {
		return bad
	}
	wantMembers := []nodeChainGraphMember{
		{profile: first.profile, source: first.source, mode: first.mode},
		{profile: s.middle.selection.Profile, source: s.middle.source, mode: s.middle.selection.Protocol, imported: true},
		{profile: final.profile, source: final.source, mode: final.mode},
	}
	if !reflect.DeepEqual(members, wantMembers) {
		return bad
	}
	firstClosure, err := nodeMultihopPredecessor(first)
	if err != nil {
		return bad
	}
	middleClosure, err := s.middle.closure()
	if err != nil {
		return bad
	}
	finalClosure, err := nodeMultihopPredecessor(final)
	if err != nil {
		return bad
	}
	capability, err := importedCONNECTCapture(finalClosure.graph, finalClosure.final, "",
		final.mode, final.profile, final.inputs.Files)
	if err != nil || capability != "uot-v2" {
		return bad
	}
	wanted := []*externalPredecessor{firstClosure, middleClosure, finalClosure}
	for i := range wanted {
		if closures[i] == nil || closures[i] != s.closures[i] ||
			!reflect.DeepEqual(closures[i], wanted[i]) {
			return bad
		}
	}
	return nil
}
