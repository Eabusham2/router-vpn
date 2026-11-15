package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

// This receipt is private to one validated CONNECT construction. Inline UoT,
// an ordinary JSON graph, or another source owner cannot create it. It grants
// only physical traversal of the exact final's configured UDP-over-TCP path.
type nodeChainCONNECTPhysicalProof struct {
	owner                             *nodeChainCONNECTPhysicalProof
	scope                             *nodeChainCONNECTProofScope
	pair                              *NodeChain
	middle                            *nodeChainCONNECTMember
	first, final                      *NodeProfile
	config, finalTag, finalJSON, seal string
}

func (s *nodeChainCONNECTProofScope) capturePhysical(config string, proofs []NodeChainProof) (*nodeChainCONNECTPhysicalProof, error) {
	if !s.ownsOriginalNodes() || s.pair == nil || s.middle == nil || len(s.pair.nodes) < 2 || len(s.pair.nodes) >= NodeChainMaximumNodes ||
		s.pair.validateCapture() != nil || s.middle.validate() != nil || len(proofs) != len(s.pair.nodes)+1 || len(s.closures) != len(proofs) {
		return nil, nodeChainCONNECTSourceError
	}
	sources := make([]string, 0, len(proofs))
	for i, node := range s.pair.nodes {
		if i == len(s.pair.nodes)-1 {
			sources = append(sources, s.middle.source)
		}
		sources = append(sources, node.source)
	}
	for i, source := range sources {
		if s.closures[i] == nil || proofs[i].Position != i || proofs[i].SourceSHA256 != source || proofs[i].Tag != nodeChainNamespace(i, source, "node", s.closures[i].finalTag) {
			return nil, nodeChainCONNECTSourceError
		}
	}
	finalPosition := len(proofs) - 1
	finalJSON, err := json.Marshal(s.closures[finalPosition].final)
	if err != nil {
		return nil, nodeChainCONNECTSourceError
	}
	p := &nodeChainCONNECTPhysicalProof{
		scope: s, pair: s.pair, middle: s.middle,
		first: s.pair.nodes[0], final: s.pair.nodes[len(s.pair.nodes)-1],
		config: config, finalTag: proofs[finalPosition].Tag, finalJSON: string(finalJSON),
	}
	p.owner = p
	p.seal = p.digest()
	if p.validate(config) != nil {
		return nil, nodeChainCONNECTSourceError
	}
	return p, nil
}

func (p *nodeChainCONNECTPhysicalProof) digest() string {
	if p == nil || p.pair == nil || p.middle == nil || p.first == nil || p.final == nil {
		return ""
	}
	raw, err := json.Marshal([]string{p.config, p.finalTag, p.finalJSON,
		p.pair.seal, p.middle.seal, p.first.source, p.final.source})
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (p *nodeChainCONNECTPhysicalProof) validate(config string) error {
	bad := nodeChainCONNECTSourceError
	if p == nil || p.seal == "" || p.digest() != p.seal || p.owner != p || !p.scope.ownsOriginalNodes() || p.scope.pair != p.pair ||
		p.scope.middle != p.middle || p.pair == nil || p.middle == nil ||
		p.pair.validateCapture() != nil || p.middle.validate() != nil ||
		len(p.pair.nodes) < 2 || len(p.pair.nodes) >= NodeChainMaximumNodes || p.pair.nodes[0] != p.first || p.pair.nodes[len(p.pair.nodes)-1] != p.final ||
		p.config == "" || p.config != config || p.finalJSON == "" {
		return bad
	}
	// Reuse the existing paired source/service validator; an inline option or
	// arbitrary tag is never sufficient UoT authority. The pinned sing UoT-v2
	// client implements both Dial(UDP) and ListenPacket over its TCP dialer.
	captured, err := nodeMultihopPredecessor(p.final)
	if err != nil {
		return bad
	}
	capability, err := importedCONNECTCapture(captured.graph, captured.final, "",
		p.final.mode, p.final.profile, p.final.inputs.Files)
	if err != nil || capability != "uot-v2" {
		return bad
	}
	captured.final["tag"] = nodeChainNamespace(len(p.pair.nodes), p.final.source, "node", captured.finalTag)
	captured.final["detour"] = nodeChainNamespace(len(p.pair.nodes)-1, p.middle.source, "node", ExternalFinalTag)
	want, err := json.Marshal(captured.final)
	if err != nil || captured.final["tag"] != p.finalTag || string(want) != p.finalJSON {
		return bad
	}
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return bad
	}
	outs, ok := graph["outbounds"].([]any)
	if !ok {
		return bad
	}
	matches := 0
	for _, raw := range outs {
		node, ok := raw.(map[string]any)
		if !ok {
			return bad
		}
		if node["tag"] == p.finalTag {
			matches++
			if !reflect.DeepEqual(node, captured.final) {
				return bad
			}
		}
	}
	if matches != 1 {
		return bad
	}
	return nil
}

func (p *nodeChainCONNECTPhysicalProof) udpOverTCP(tag string, node map[string]any) (bool, error) {
	if tag != p.finalTag {
		return false, nil
	}
	raw, err := json.Marshal(node)
	uot, ok := node["udp_over_tcp"].(map[string]any)
	if err != nil || string(raw) != p.finalJSON ||
		(node["type"] != "shadowsocks" && node["type"] != "routervpn-aes-xor") ||
		!ok || len(uot) != 2 || uot["enabled"] != true || uot["version"] != float64(2) {
		return false, nodeChainCONNECTSourceError
	}
	return true, nil
}

func (s *nodeChainCONNECTProofScope) physicalEgress(config string, networks []string, proofTag string, capture *nodeChainCONNECTPhysicalProof) ([]PhysicalEgress, error) {
	if capture == nil || capture.scope != s || capture.validate(config) != nil {
		return nil, nodeChainCONNECTSourceError
	}
	return compiledPhysicalEgressWithCapturedTransports(config, networks, nil, proofTag, false, capture)
}

// Only a private original-source scope can authorize stream-carried UDP.
// Local CONNECT and remote CONNECT suffixes retain distinct concrete owners.
type nodeChainCapturedTransportProof interface {
	validate(string) error
	udpOverTCP(string, map[string]any) (bool, error)
}
type nodeChainCapturedTransportScope interface {
	validate([]nodeChainGraphMember, []*externalPredecessor) error
	captureTransport(string, []NodeChainProof) (nodeChainCapturedTransportProof, error)
}

func (s *nodeChainCONNECTProofScope) captureTransport(config string, proofs []NodeChainProof) (nodeChainCapturedTransportProof, error) {
	return s.capturePhysical(config, proofs)
}
