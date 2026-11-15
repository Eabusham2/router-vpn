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
	integrity                *nodeChainSOCKSIntegrity
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

// NewNodeChainSOCKSSource retains one to six original paired packet prefixes,
// one SOCKS member, and the paired SS final. The paired constructor still
// validates every original member and identity before any closure is composed.
func NewNodeChainSOCKSSource(input string) (*NodeChainSOCKSSource, error) {
	var source NodeChainSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil ||
		source.Schema != 3 || source.Execution != "local" || len(source.Nodes) < 3 || len(source.Nodes) > NodeChainMaximumNodes ||
		len(source.IdentitySources) != len(source.Nodes) {
		return nil, nodeChainSOCKSSourceError
	}
	middlePosition := len(source.Nodes) - 2
	for i, identity := range source.IdentitySources {
		if (i == middlePosition) != (identity == "") {
			return nil, nodeChainSOCKSSourceError
		}
	}
	middle, err := parseNodeChainSOCKSMember(source.Nodes[middlePosition])
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
		return nil, nodeChainSOCKSSourceError
	}
	pair, err := NewNodeChain(string(pairJSON))
	if err != nil {
		return nil, nodeChainSOCKSSourceError
	}
	members, closures, err := nodeChainSOCKSMembers(pair, middle)
	if err != nil {
		return nil, err
	}
	for _, closure := range closures {
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return nil, nodeChainSOCKSSourceError
		}
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
			return nil, nodeChainSOCKSSourceError
		}
		result.metadata.Devices = append(result.metadata.Devices, NodeChainSOCKSDevicePolicy{
			Position: position, ProfileID: proofs[position].ProfileID,
			KillSwitchPolicy: device.KillSwitchPolicy, IPv6Mode: device.IPv6Mode,
			HomeLANAccess: device.HomeLANAccess,
		})
	}
	result.seal = result.digest()
	if result.retainIntegrity() != nil {
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
	if p == nil || p.integrity == nil || !p.integrity.current(p) {
		return nodeChainSOCKSSourceError
	}
	return nil
}

func (p *NodeChainSOCKSSource) validateCompiled() error {
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

// Every paired prefix and final retains its own original authenticated source.
func nodeChainSOCKSMembers(pair *NodeChain, middle *nodeChainSOCKSMember) ([]nodeChainGraphMember, []*externalPredecessor, error) {
	if pair == nil || pair.validateCapture() != nil || len(pair.nodes) < 2 || len(pair.nodes) >= NodeChainMaximumNodes ||
		pair.importedMiddle != nil || pair.openVPNMiddle != nil || pair.socksSource != nil || pair.connectSource != nil || middle == nil || middle.validate() != nil {
		return nil, nil, nodeChainSOCKSSourceError
	}
	members := make([]nodeChainGraphMember, 0, len(pair.nodes)+1)
	closures := make([]*externalPredecessor, 0, len(pair.nodes)+1)
	for i, node := range pair.nodes {
		final := i == len(pair.nodes)-1
		if node == nil || (!final && !NodeChainPrefixMode(node.mode)) || (final && node.mode != "shadowsocks") ||
			middle.selection.ExitID == predecessorText(node.profile, "id") {
			return nil, nil, nodeChainSOCKSSourceError
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
