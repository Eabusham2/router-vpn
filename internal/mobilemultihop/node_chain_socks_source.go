package mobilemultihop

import "encoding/json"

// NodeChainSOCKSSource is a dormant source/compiler result. It deliberately
// has no LaunchInput, Run, Ready or native projection method. Existing generic
// NodeChain parsers continue to reject its schema 3 source.
type NodeChainSOCKSSource struct {
	sourceJSON, config, seal string
	pair                     *NodeChain
	middle                   *nodeChainSOCKSMember
	metadata                 NodeChainSOCKSSourceMetadata
	desktop                  *nodeChainSOCKSDesktopBinding
}

type NodeChainSOCKSDevicePolicy struct {
	Position         int    `json:"position"`
	ProfileID        string `json:"profile_id"`
	KillSwitchPolicy string `json:"kill_switch_policy"`
	IPv6Mode         string `json:"ipv6_mode"`
	HomeLANAccess    bool   `json:"home_lan_access"`
}

// This receipt describes original source and configured bounds only. It is
// neither a native owner nor evidence of a live proof, selected route or PMTU.
type NodeChainSOCKSSourceMetadata struct {
	Kind            string                       `json:"kind"`
	Schema          int                          `json:"schema"`
	NativeAdmission string                       `json:"native_admission"`
	SourceSHA256    string                       `json:"source_sha256"`
	ConfigSHA256    string                       `json:"config_sha256"`
	Proofs          []NodeChainProof             `json:"proofs"`
	DNS             NodeChainDNSCapture          `json:"dns"`
	Physical        []PhysicalEgress             `json:"physical"`
	MTU             NodeChainMTUPlan             `json:"mtu"`
	Devices         []NodeChainSOCKSDevicePolicy `json:"devices"`
}

// NewNodeChainSOCKSSource validates the two original paired nodes using the
// existing constructor, then uses the same ordered closure compiler, physical
// traversal, final-DNS policy and per-prefix MTU projection as shipping paths.
func NewNodeChainSOCKSSource(input string) (*NodeChainSOCKSSource, error) {
	var source NodeChainSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil ||
		source.Schema != 3 || source.Execution != "local" || len(source.Nodes) != 3 ||
		len(source.IdentitySources) != 3 || source.IdentitySources[0] == "" ||
		source.IdentitySources[1] != "" || source.IdentitySources[2] == "" {
		return nil, nodeChainSOCKSSourceError
	}
	middle, err := parseNodeChainSOCKSMember(source.Nodes[1])
	if err != nil {
		return nil, err
	}
	paired := NodeChainSource{Schema: 1, Execution: "local",
		Nodes: []string{source.Nodes[0], source.Nodes[2]},
		IdentitySources: []string{source.IdentitySources[0], source.IdentitySources[2]}}
	pairJSON, err := json.Marshal(paired)
	if err != nil {
		return nil, nodeChainSOCKSSourceError
	}
	pair, err := NewNodeChain(string(pairJSON))
	if err != nil || len(pair.nodes) != 2 || !NodeChainPrefixMode(pair.nodes[0].mode) ||
		pair.nodes[1].mode != "shadowsocks" ||
		middle.selection.ExitID == predecessorText(pair.nodes[0].profile, "id") ||
		middle.selection.ExitID == predecessorText(pair.nodes[1].profile, "id") {
		return nil, nodeChainSOCKSSourceError
	}
	first, err := nodeMultihopPredecessor(pair.nodes[0])
	if err != nil {
		return nil, nodeChainSOCKSSourceError
	}
	custom, err := middle.closure()
	if err != nil {
		return nil, err
	}
	final, err := nodeMultihopPredecessor(pair.nodes[1])
	if err != nil {
		return nil, nodeChainSOCKSSourceError
	}
	closures := []*externalPredecessor{first, custom, final}
	for _, closure := range closures {
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return nil, nodeChainSOCKSSourceError
		}
	}
	members := []nodeChainGraphMember{
		{profile: pair.nodes[0].profile, source: pair.nodes[0].source, mode: pair.nodes[0].mode},
		{profile: middle.selection.Profile, source: middle.source, mode: "socks5", imported: true},
		{profile: pair.nodes[1].profile, source: pair.nodes[1].source, mode: "shadowsocks"},
	}
	physical, err := pair.nodes[0].PhysicalEgress()
	if err != nil {
		return nil, nodeChainSOCKSSourceError
	}
	config, proofs, dns, actualPhysical, err := compileNodeChainClosures(members, closures, physical)
	if err != nil {
		return nil, err
	}
	mtu, err := nodeChainMTUPlan(config, proofs)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(source)
	if err != nil || len(canonical) > NodeChainInputLimit {
		return nil, nodeChainSOCKSSourceError
	}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-socks-source-v1", string(canonical)})
	sourceSHA, configSHA := externalDigest(digest), externalDigest([]byte(config))
	dns.SourceSHA256, dns.ConfigSHA256 = sourceSHA, configSHA
	result := &NodeChainSOCKSSource{
		sourceJSON: string(canonical), config: config, pair: pair, middle: middle,
		metadata: NodeChainSOCKSSourceMetadata{
			Kind: "routervpn-node-chain-socks-source", Schema: 1, NativeAdmission: "closed",
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
			return nil, nodeChainSOCKSSourceError
		}
		result.metadata.Devices = append(result.metadata.Devices, NodeChainSOCKSDevicePolicy{
			Position: position, ProfileID: proofs[position].ProfileID,
			KillSwitchPolicy: device.KillSwitchPolicy, IPv6Mode: device.IPv6Mode,
			HomeLANAccess: device.HomeLANAccess,
		})
	}
	result.seal = result.digest()
	if result.validate() != nil {
		return nil, nodeChainSOCKSSourceError
	}
	return result, nil
}

func (p *NodeChainSOCKSSource) digest() string {
	if p == nil || p.pair == nil || p.middle == nil {
		return ""
	}
	values := []any{
		"routervpn-node-chain-socks-compiler-v1", p.sourceJSON, p.config, p.metadata, p.pair.seal, p.middle.seal,
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

func (p *NodeChainSOCKSSource) validate() error {
	if p == nil || p.seal == "" || p.digest() != p.seal || p.pair.validateCapture() != nil ||
		p.middle.validate() != nil || p.metadata.Kind != "routervpn-node-chain-socks-source" ||
		p.metadata.Schema != 1 || p.metadata.NativeAdmission != "closed" {
		return nodeChainSOCKSSourceError
	}
	if p.desktop != nil && p.desktop.validate(p) != nil {
		return nodeChainSOCKSSourceError
	}
	return nil
}

// Source returns the complete private constructor input, including the exact
// original import. It must never be used as a progress/status payload.
func (p *NodeChainSOCKSSource) Source() (string, error) {
	if p.validate() != nil {
		return "", nodeChainSOCKSSourceError
	}
	return p.sourceJSON, nil
}

func (p *NodeChainSOCKSSource) ReadValidated() (string, NodeChainSOCKSSourceMetadata, error) {
	if p.validate() != nil {
		return "", NodeChainSOCKSSourceMetadata{}, nodeChainSOCKSSourceError
	}
	meta := p.metadata
	meta.Proofs = append([]NodeChainProof(nil), meta.Proofs...)
	meta.Physical = append([]PhysicalEgress(nil), meta.Physical...)
	meta.MTU.Prefixes = append([]NodeChainMTUBound(nil), meta.MTU.Prefixes...)
	meta.Devices = append([]NodeChainSOCKSDevicePolicy(nil), meta.Devices...)
	return p.config, meta, nil
}
