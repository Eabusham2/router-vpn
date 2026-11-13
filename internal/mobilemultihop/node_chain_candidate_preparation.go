package mobilemultihop

import (
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/mobilemtu"
)

// NodeChainCandidatePreparation is a separate, default-deny native source. It
// retains the complete saved Local path only as immutable chooser/Save
// provenance. Its runnable graph contains no member after the selected packet
// prefix, and acquiring it grants neither a connected path nor DNS forwarding.
// Native prefix proof and owned measurement still have to bind this capture.
type NodeChainCandidatePreparation struct {
	original                                            *NodeChain
	candidates                                          *NodeChainCandidatePlan
	source, sourceSHA, config, configSHA, capture, seal string
	position                                            int
	proofs                                              []NodeChainProof
	physical                                            []PhysicalEgress
	mtu                                                 NodeChainMTUPlan
}

type nodeChainCandidatePreparationSource struct {
	Kind           string `json:"kind"`
	Schema         int    `json:"schema"`
	OriginalSource string `json:"original_source"`
	PrefixPosition int    `json:"prefix_position"`
	Inventory      string `json:"inventory"`
}

var nodeChainCandidatePreparationError = errors.New("candidate preparation requires its sealed original paired packet prefix and closed application ingress")

// NewNodeChainCandidatePreparation validates sources without opening sockets.
// The original final may be unreachable: it is never included in this graph.
func NewNodeChainCandidatePreparation(originalSource string, position int, inventory string) (*NodeChainCandidatePreparation, error) {
	original, err := NewNodeChain(originalSource)
	if err != nil {
		return nil, err
	}
	candidates, err := original.NewCandidatePlan(position, inventory)
	if err != nil {
		return nil, err
	}
	closures := make([]*externalPredecessor, position+1)
	members := make([]nodeChainGraphMember, position+1)
	for i := range closures {
		node := original.nodes[i]
		if node == nil || !NodeChainPrefixMode(node.mode) {
			return nil, nodeChainCandidatePreparationError
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil || closure == nil || closure.final["type"] != nodeChainPrefixType(node.mode) {
			return nil, nodeChainCandidatePreparationError
		}
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return nil, nodeChainCandidatePreparationError
		}
		closures[i] = closure
		members[i] = nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode}
	}
	config, proofs, _, physical, err := compileNodeChainClosures(members, closures, original.physical)
	if err != nil || !reflect.DeepEqual(proofs, original.proofs[:position+1]) || !nodeChainSamePhysical(physical, original.physical) {
		return nil, errors.Join(err, nodeChainCandidatePreparationError)
	}
	var graph, saved map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil || exactJSON([]byte(original.config), &saved, 4<<20) != nil {
		return nil, nodeChainCandidatePreparationError
	}
	// Preserve the saved device TUN addresses, Fixed/Auto setting and protection
	// restrictions; nested prefix endpoint bounds remain independently captured.
	graph["inbounds"] = saved["inbounds"]
	route := graph["route"].(map[string]any)
	savedRoute := saved["route"].(map[string]any)
	route["rules"] = savedRoute["rules"]
	if err := nodeChainExecutionGate(graph); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return nil, nodeChainCandidatePreparationError
	}
	p := &NodeChainCandidatePreparation{original: original, candidates: candidates, position: position, config: string(raw), configSHA: externalDigest(raw), proofs: proofs, physical: physical}
	p.mtu, err = candidatePreparationMTU(graph, proofs)
	if err != nil {
		return nil, err
	}
	record := nodeChainCandidatePreparationSource{"routervpn-node-chain-candidate-preparation", 1, original.sourceJSON, position, inventory}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > NodeChainInputLimit {
		return nil, nodeChainCandidatePreparationError
	}
	p.source = string(encoded)
	identity, _ := json.Marshal([]string{"routervpn-node-chain-candidate-preparation-source-v1", p.source})
	p.sourceSHA = externalDigest(identity)
	clear(identity)
	capture, _ := json.Marshal([]string{p.sourceSHA, p.configSHA, candidates.capture})
	p.capture = externalDigest(capture)
	clear(capture)
	p.seal = p.digest()
	return p, p.validate()
}

// ParseNodeChainCandidatePreparation derives the executable graph again; no
// host-provided config, outbound tag, credential or ingress flag is trusted.
func ParseNodeChainCandidatePreparation(input string) (*NodeChainCandidatePreparation, error) {
	var source nodeChainCandidatePreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Kind != "routervpn-node-chain-candidate-preparation" || source.Schema != 1 {
		return nil, nodeChainCandidatePreparationError
	}
	p, err := NewNodeChainCandidatePreparation(source.OriginalSource, source.PrefixPosition, source.Inventory)
	if err != nil || p == nil || p.source != input {
		return nil, errors.Join(err, nodeChainCandidatePreparationError)
	}
	return p, nil
}

func candidatePreparationMTU(graph map[string]any, proofs []NodeChainProof) (NodeChainMTUPlan, error) {
	bad := nodeChainCandidatePreparationError
	if len(proofs) < 1 || len(proofs) >= NodeChainMaximumNodes {
		return NodeChainMTUPlan{}, bad
	}
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	actual, err := mtuNumber(tun["mtu"])
	if err != nil || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return NodeChainMTUPlan{}, bad
	}
	result := NodeChainMTUPlan{Original: actual, Ceiling: 9000, TUNTag: predecessorText(tun, "tag")}
	projection := predecessorCopy(graph)
	for _, proof := range proofs {
		projection["route"].(map[string]any)["final"] = proof.Tag
		raw, err := json.Marshal(projection)
		if err != nil {
			return NodeChainMTUPlan{}, err
		}
		plan, err := mobilemtu.NewPlan(string(raw), actual)
		if err != nil {
			return NodeChainMTUPlan{}, err
		}
		if plan.Ceiling < result.Ceiling {
			result.Ceiling = plan.Ceiling
		}
		result.Prefixes = append(result.Prefixes, NodeChainMTUBound{proof.Position, proof.Tag, plan.Ceiling})
	}
	if actual > result.Ceiling {
		return NodeChainMTUPlan{}, errors.New("saved TUN MTU exceeds the captured preparation prefix ceiling")
	}
	return result, nil
}

func (p *NodeChainCandidatePreparation) digest() string {
	if p == nil || p.original == nil || p.candidates == nil {
		return ""
	}
	raw, err := json.Marshal([]any{p.original.seal, p.candidates.seal, p.source, p.sourceSHA, p.config, p.configSHA, p.capture, p.position, p.proofs, p.physical, p.mtu})
	if err != nil {
		return ""
	}
	defer clear(raw)
	return externalDigest(raw)
}
func (p *NodeChainCandidatePreparation) validate() error {
	if p == nil || p.original == nil || p.original.validateCapture() != nil || p.candidates == nil || p.candidates.validate() != nil || p.candidates.chain != p.original ||
		p.seal == "" || p.seal != p.digest() || p.position < 0 || p.position >= len(p.original.proofs)-1 || !reflect.DeepEqual(p.proofs, p.original.proofs[:p.position+1]) {
		return nodeChainCandidatePreparationError
	}
	return nil
}
func (p *NodeChainCandidatePreparation) Source() string {
	if p.validate() != nil {
		return ""
	}
	return p.source
}
func (p *NodeChainCandidatePreparation) SourceSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.sourceSHA
}
func (p *NodeChainCandidatePreparation) Config() string {
	if p.validate() != nil {
		return ""
	}
	return p.config
}
func (p *NodeChainCandidatePreparation) ConfigSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.configSHA
}
func (p *NodeChainCandidatePreparation) OriginalSourceSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.original.sourceSHA
}
func (p *NodeChainCandidatePreparation) CaptureSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.capture
}
func (p *NodeChainCandidatePreparation) PrefixPosition() int {
	if p.validate() != nil {
		return -1
	}
	return p.position
}
func (p *NodeChainCandidatePreparation) ProofInventory() []NodeChainProof {
	if p.validate() != nil {
		return nil
	}
	return append([]NodeChainProof(nil), p.proofs...)
}
func (p *NodeChainCandidatePreparation) PhysicalEgress() ([]PhysicalEgress, error) {
	if p.validate() != nil {
		return nil, nodeChainCandidatePreparationError
	}
	return append([]PhysicalEgress(nil), p.physical...), nil
}
func (p *NodeChainCandidatePreparation) MTUPlan() (NodeChainMTUPlan, error) {
	if p.validate() != nil {
		return NodeChainMTUPlan{}, nodeChainCandidatePreparationError
	}
	result := p.mtu
	result.Prefixes = append([]NodeChainMTUBound(nil), p.mtu.Prefixes...)
	return result, nil
}

// Metadata exposes no endpoints, source bytes, private API credentials or keys.
// A pending source capture is deliberately not a ready/connected receipt.
func (p *NodeChainCandidatePreparation) Metadata() string {
	if p.validate() != nil {
		return ""
	}
	var candidates map[string]any
	if json.Unmarshal([]byte(p.candidates.Metadata()), &candidates) != nil {
		return ""
	}
	candidates["capture_sha256"] = p.capture
	candidates["source_sha256"] = p.sourceSHA
	candidates["config_sha256"] = p.configSHA
	candidates["original_source_sha256"] = p.original.sourceSHA
	candidates["prefixes"] = p.proofs
	candidates["application_open"] = false
	candidates["dns_open"] = false
	candidates["ready"] = false
	candidates["stage"] = "pending-prefix-proof"
	candidates["mtu"] = p.mtu
	candidates["mtu_measurement"] = "configured-bounds-only"
	raw, _ := json.Marshal(candidates)
	return string(raw)
}
