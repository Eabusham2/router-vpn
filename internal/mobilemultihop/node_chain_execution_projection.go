package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

const NodeChainExecutionGateType = "routervpn-node-chain-gate"
const NodeChainExecutionGateTag = "routervpn-chain-application"

// NodeChainExecutionPreparationSource retains the complete original Local
// source before entry-authenticated discovery is available. It grants no
// application forwarding and contains no guessed server source or port.
type NodeChainExecutionPreparationSource struct {
	Schema      int                       `json:"schema"`
	Execution   string                    `json:"execution"`
	LocalSource string                    `json:"local_source"`
	Desktop     *DesktopNodeChainMetadata `json:"desktop,omitempty"`
	DesktopLast string                    `json:"desktop_last,omitempty"`
}

// NodeChainExecutionDiscoveryCapture is private original-route authority. The
// native adapter must bind these hashes to the retained preparation Box and
// use this exact entry, address and credential. It is not a discovery result.
type NodeChainExecutionDiscoveryCapture struct {
	SourceSHA256 string         `json:"source_sha256"`
	ConfigSHA256 string         `json:"config_sha256"`
	Entry        NodeChainProof `json:"entry"`
	API          string         `json:"api"`
	Token        string         `json:"token"`
	Network      string         `json:"network"`
	Address      string         `json:"address"`
}

// NodeChainExecutionTransition describes the only allowed in-place graph
// extension. Native code must additionally retain and compare every original
// Box, TUN, selector, gate, DNS and outbound pointer. Config hashes do not prove
// that those owners survived, and this value never opens the application gate.
type NodeChainExecutionTransition struct {
	PreparationSourceSHA256 string   `json:"preparation_source_sha256"`
	PreparationConfigSHA256 string   `json:"preparation_config_sha256"`
	SourceSHA256            string   `json:"source_sha256"`
	ConfigSHA256            string   `json:"config_sha256"`
	GateTag                 string   `json:"gate_tag"`
	SelectorTag             string   `json:"selector_tag"`
	EntryTag                string   `json:"entry_tag"`
	TUNTag                  string   `json:"tun_tag"`
	SelectorBeforeJSON      string   `json:"selector_before_json"`
	SelectorAfterJSON       string   `json:"selector_after_json"`
	AddedOutbounds          []string `json:"added_outbounds"`
}

type NodeChainExecutionPreparation struct {
	sourceJSON, sourceSHA, config, configSHA, seal string
	source                                         NodeChainExecutionPreparationSource
	local                                          *NodeChain
	discovery                                      NodeChainExecutionDiscoveryCapture
	dns                                            NodeChainExecutionDNSCapture
	physical                                       []PhysicalEgress
	desktop                                        *DesktopNodeChainPolicy
	desktopPhysical                                *DesktopNodeChainExecutionPhysicalPolicy
	mobile                                         *nodeChainExecutionMobileProjection
}

// NewNodeChainExecutionPreparation keeps one complete original Local graph,
// including its TUN. Application traffic goes only to the initially closed
// native gate. The original selector remains one-choice; final selected DNS
// (including explicit bootstrap) already uses that exact selector so extending
// the graph never replaces a constructed resolver or its detour pointer.
func NewNodeChainExecutionPreparation(localSource, execution string) (*NodeChainExecutionPreparation, error) {
	return newNodeChainExecutionPreparation(localSource, execution, nil)
}

func newNodeChainExecutionPreparation(localSource, execution string, desktop *DesktopNodeChainPolicy) (*NodeChainExecutionPreparation, error) {
	return newNodeChainExecutionPreparationProjected(localSource, execution, desktop, nil)
}

func newNodeChainExecutionPreparationProjected(localSource, execution string, desktop *DesktopNodeChainPolicy, mobile *nodeChainExecutionMobileProjection) (*NodeChainExecutionPreparation, error) {
	if execution != "server" && execution != "auto" {
		return nil, nodeChainExecutionError
	}
	local, err := NewNodeChain(localSource)
	var original NodeChainSource
	if err != nil || local.validateCapture() != nil || local.importedMiddle != nil ||
		local.nodes[len(local.nodes)-1].mode != "shadowsocks" ||
		exactJSON([]byte(localSource), &original, NodeChainInputLimit) != nil || original.Schema != 1 ||
		len(original.IdentitySources) != len(local.nodes) {
		return nil, nodeChainExecutionError
	}
	p := &NodeChainExecutionPreparation{source: NodeChainExecutionPreparationSource{Schema: 1, Execution: execution, LocalSource: localSource}, local: local, desktop: desktop, mobile: mobile}
	config := local.Config()
	if mobile != nil {
		if desktop != nil || p.validateMobileCapture() != nil {
			return nil, nodeChainExecutionError
		}
		config = mobile.chain.Config()
	}
	if desktop != nil {
		var meta DesktopNodeChainMetadata
		config, meta, _, err = desktop.ReadValidated()
		if err != nil || desktop.original.sourceJSON != localSource || desktop.original.Config() != local.Config() {
			return nil, nodeChainExecutionError
		}
		p.source.Desktop = &meta
	}
	raw, err := json.Marshal(p.source)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, nodeChainExecutionError
	}
	p.sourceJSON = string(raw)
	digest, _ := json.Marshal([]string{"routervpn-node-chain-execution-preparation-v1", p.sourceJSON})
	p.sourceSHA = externalDigest(digest)
	clear(digest)
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil || nodeChainExecutionGate(graph) != nil {
		return nil, nodeChainExecutionError
	}
	final := local.FinalTag()
	var selected map[string]any
	for _, value := range graph["dns"].(map[string]any)["servers"].([]any) {
		row := value.(map[string]any)
		if row["detour"] == final {
			row["detour"] = SelectorTag
		}
		if row["tag"] == local.dns.ResolverTag {
			selected = row
		}
	}
	if selected == nil || selected["detour"] != SelectorTag {
		return nil, nodeChainExecutionError
	}
	raw, err = json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return nil, nodeChainExecutionError
	}
	p.config, p.configSHA = string(raw), externalDigest(raw)
	entry := local.nodes[0]
	api, err := privateAPI(predecessorText(entry.profile, "router_api"))
	if err != nil {
		return nil, nodeChainExecutionError
	}
	p.discovery = NodeChainExecutionDiscoveryCapture{p.sourceSHA, p.configSHA, local.proofs[0],
		predecessorText(entry.profile, "router_api"), predecessorText(entry.profile, "api_token"), "tcp", api.Host}
	resolver, _ := json.Marshal(selected)
	var finalGraph map[string]any
	if exactJSON([]byte(local.nodes[len(local.nodes)-1].config), &finalGraph, 4<<20) != nil {
		return nil, nodeChainExecutionError
	}
	dnsRaw, err := json.Marshal(finalGraph["dns"])
	if err != nil {
		return nil, nodeChainExecutionError
	}
	dns := local.DNSCapture()
	dns.SourceSHA256, dns.ConfigSHA256, dns.FinalTag = p.sourceSHA, p.configSHA, SelectorTag
	dns.ResolverSHA256 = externalDigest(resolver)
	p.dns = NodeChainExecutionDNSCapture{"local", SelectorTag, final, externalDigest(dnsRaw), dns}
	p.physical, err = local.PhysicalEgress()
	if err != nil {
		return nil, nodeChainExecutionError
	}
	p.seal = p.captureSeal()
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	if desktop != nil {
		p.desktopPhysical, err = newDesktopNodeChainExecutionPhysicalPolicy(p)
		if err != nil || p.desktopPhysical.Validate() != nil {
			return nil, nodeChainExecutionError
		}
	}
	return p, nil
}

// This typed projection adds no physical tuple or direct route. The native
// outbound understands only this fixed selector detour and begins closed.
func nodeChainExecutionGate(graph map[string]any) error {
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != SelectorTag {
		return nodeChainExecutionError
	}
	rows, ok := graph["outbounds"].([]any)
	if !ok {
		return nodeChainExecutionError
	}
	selectors := 0
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok || row["tag"] == NodeChainExecutionGateTag || row["type"] == NodeChainExecutionGateType {
			return nodeChainExecutionError
		}
		if row["tag"] == SelectorTag {
			if row["type"] != "selector" || row["interrupt_exist_connections"] != true {
				return nodeChainExecutionError
			}
			selectors++
		}
	}
	if selectors != 1 {
		return nodeChainExecutionError
	}
	graph["outbounds"] = append(rows, map[string]any{"type": NodeChainExecutionGateType, "tag": NodeChainExecutionGateTag, "detour": SelectorTag})
	route["final"] = NodeChainExecutionGateTag
	return nil
}

func (p *NodeChainExecutionPreparation) captureSeal() string {
	if p == nil {
		return ""
	}
	values := []any{"routervpn-node-chain-execution-preparation-capture-v1", p.sourceJSON, p.sourceSHA,
		p.config, p.configSHA, p.source, p.discovery, p.dns, p.physical}
	if p.mobile != nil {
		if p.mobile.chain == nil {
			return ""
		}
		values = append(values, p.mobile.executionSource, p.mobile.readback, p.mobile.chain.seal)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	digest := externalDigest(raw)
	clear(raw)
	return digest
}

func (p *NodeChainExecutionPreparation) validateCapture() error {
	if p == nil || p.seal == "" || p.captureSeal() != p.seal || p.local == nil || p.local.validateCapture() != nil ||
		p.discovery.Entry != p.local.proofs[0] || p.dns.DNS.SourceSHA256 != p.sourceSHA || p.dns.DNS.ConfigSHA256 != p.configSHA {
		return nodeChainExecutionError
	}
	if p.desktop == nil {
		if p.source.Desktop != nil {
			return nodeChainExecutionError
		}
	} else if p.validateDesktopCapture() != nil {
		return nodeChainExecutionError
	}
	if p.mobile != nil && p.validateMobileCapture() != nil {
		return nodeChainExecutionError
	}
	return nil
}

func (p *NodeChainExecutionPreparation) Source() string            { return p.sourceJSON }
func (p *NodeChainExecutionPreparation) SourceSHA256() string      { return p.sourceSHA }
func (p *NodeChainExecutionPreparation) Config() string            { return p.config }
func (p *NodeChainExecutionPreparation) ConfigSHA256() string      { return p.configSHA }
func (p *NodeChainExecutionPreparation) Execution() string         { return p.source.Execution }
func (p *NodeChainExecutionPreparation) LocalSource() string       { return p.source.LocalSource }
func (p *NodeChainExecutionPreparation) LocalSourceSHA256() string { return p.local.SourceSHA256() }
func (p *NodeChainExecutionPreparation) ProofInventory() []NodeChainProof {
	return p.local.ProofInventory()
}
func (p *NodeChainExecutionPreparation) Discovery() (NodeChainExecutionDiscoveryCapture, error) {
	if p.validateCapture() != nil {
		return NodeChainExecutionDiscoveryCapture{}, nodeChainExecutionError
	}
	return p.discovery, nil
}
func (p *NodeChainExecutionPreparation) DNSCapture() (NodeChainExecutionDNSCapture, error) {
	if p.validateCapture() != nil {
		return NodeChainExecutionDNSCapture{}, nodeChainExecutionError
	}
	return p.dns, nil
}
func (p *NodeChainExecutionPreparation) PhysicalEgress() ([]PhysicalEgress, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return append([]PhysicalEgress(nil), p.physical...), nil
}

type NodeChainExecutionProjection struct {
	preparation  *NodeChainExecutionPreparation
	policy       *NodeChainExecutionPolicy
	config, hash string
	transition   NodeChainExecutionTransition
	seal         string
}

// BindExecution proves that adding Server choices does not re-plan the
// original source, TUN, entry, Local members, resolver or device rules. It
// produces the actual gated final config, whose hash differs from the generic
// execution compiler. Only a native transition can establish live ownership.
func (p *NodeChainExecutionPreparation) BindExecution(policy *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if p.validateCapture() != nil || policy.validateCapture() != nil || p.source.LocalSource != policy.source.LocalSource ||
		p.source.Execution != policy.source.Execution || p.local.Config() != policy.local.Config() ||
		!reflect.DeepEqual(p.physical, policy.physical) || p.dns.DNSPolicySHA256 != policy.source.Server.DNSPolicySHA256 {
		return nil, nodeChainExecutionError
	}
	if p.mobile != nil && p.mobile.executionSource != policy.Source() {
		return nil, nodeChainExecutionError
	}
	if p.desktop != nil || p.mobile != nil {
		return p.bindProjectedExecution(policy)
	}
	var before, after map[string]any
	if exactJSON([]byte(p.config), &before, 4<<20) != nil || exactJSON([]byte(policy.config), &after, 4<<20) != nil || nodeChainExecutionGate(after) != nil {
		return nil, nodeChainExecutionError
	}
	initial, final := before["outbounds"].([]any), after["outbounds"].([]any)
	if len(final) != len(initial)+len(policy.serverProofs)-1 {
		return nil, nodeChainExecutionError
	}
	// The gate was appended after the original Local outbounds. In the final
	// config it follows the new Server outbounds. Compare originals by exact
	// unique tag while preserving every original row's order.
	byTag := map[string]map[string]any{}
	for _, raw := range final {
		row, ok := raw.(map[string]any)
		tag, tagOK := row["tag"].(string)
		if !ok || !tagOK || tag == "" || byTag[tag] != nil {
			return nil, nodeChainExecutionError
		}
		byTag[tag] = row
	}
	transition := NodeChainExecutionTransition{PreparationSourceSHA256: p.sourceSHA, PreparationConfigSHA256: p.configSHA,
		SourceSHA256: policy.sourceSHA, GateTag: NodeChainExecutionGateTag, SelectorTag: SelectorTag,
		EntryTag: p.local.proofs[0].Tag, TUNTag: p.local.dns.TUNTag}
	for index, raw := range initial {
		row := raw.(map[string]any)
		tag := row["tag"].(string)
		matched := byTag[tag]
		if matched == nil {
			return nil, nodeChainExecutionError
		}
		if tag == SelectorTag {
			original := predecessorCopy(row)
			original["outbounds"], original["default"] = matched["outbounds"], matched["default"]
			if !reflect.DeepEqual(original, matched) {
				return nil, nodeChainExecutionError
			}
			beforeRaw, _ := json.Marshal(row)
			afterRaw, _ := json.Marshal(matched)
			transition.SelectorBeforeJSON, transition.SelectorAfterJSON = string(beforeRaw), string(afterRaw)
		} else if !reflect.DeepEqual(row, matched) {
			return nil, nodeChainExecutionError
		}
		if tag != NodeChainExecutionGateTag && !reflect.DeepEqual(final[index], matched) {
			return nil, nodeChainExecutionError
		}
		delete(byTag, tag)
	}
	for _, proof := range policy.serverProofs[1:] {
		row := byTag[proof.Tag]
		if row == nil {
			return nil, nodeChainExecutionError
		}
		raw, _ := json.Marshal(row)
		transition.AddedOutbounds = append(transition.AddedOutbounds, string(raw))
		delete(byTag, proof.Tag)
	}
	if len(byTag) != 0 || transition.SelectorBeforeJSON == "" || transition.SelectorAfterJSON == "" {
		return nil, nodeChainExecutionError
	}
	delete(before, "outbounds")
	withoutOutbounds := predecessorCopy(after)
	delete(withoutOutbounds, "outbounds")
	if !reflect.DeepEqual(before, withoutOutbounds) {
		return nil, nodeChainExecutionError
	}
	raw, err := json.Marshal(after)
	if err != nil || len(raw) > 4<<20 {
		return nil, nodeChainExecutionError
	}
	result := &NodeChainExecutionProjection{preparation: p, policy: policy, config: string(raw), hash: externalDigest(raw)}
	transition.ConfigSHA256 = result.hash
	result.transition = transition
	result.seal = result.captureSeal()
	return result, result.validateCapture()
}

func (p *NodeChainExecutionProjection) captureSeal() string {
	if p == nil {
		return ""
	}
	raw, err := json.Marshal([]any{"routervpn-node-chain-execution-projection-v1", p.config, p.hash, p.transition})
	if err != nil {
		return ""
	}
	digest := externalDigest(raw)
	clear(raw)
	return digest
}
func (p *NodeChainExecutionProjection) validateCapture() error {
	if p == nil || p.seal == "" || p.seal != p.captureSeal() || p.preparation.validateCapture() != nil || p.policy.validateCapture() != nil ||
		p.transition.PreparationSourceSHA256 != p.preparation.sourceSHA || p.transition.PreparationConfigSHA256 != p.preparation.configSHA ||
		p.transition.SourceSHA256 != p.policy.sourceSHA || p.transition.ConfigSHA256 != p.hash || externalDigest([]byte(p.config)) != p.hash {
		return nodeChainExecutionError
	}
	return nil
}

func (p *NodeChainExecutionProjection) Source() string       { return p.policy.Source() }
func (p *NodeChainExecutionProjection) SourceSHA256() string { return p.policy.SourceSHA256() }
func (p *NodeChainExecutionProjection) Config() string       { return p.config }
func (p *NodeChainExecutionProjection) ConfigSHA256() string { return p.hash }
func (p *NodeChainExecutionProjection) Execution() string    { return p.policy.Execution() }
func (p *NodeChainExecutionProjection) Transition() (NodeChainExecutionTransition, error) {
	if p.validateCapture() != nil {
		return NodeChainExecutionTransition{}, nodeChainExecutionError
	}
	result := p.transition
	result.AddedOutbounds = append([]string(nil), result.AddedOutbounds...)
	return result, nil
}
func (p *NodeChainExecutionProjection) ProofInventory(execution string) ([]NodeChainProof, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.policy.ProofInventory(execution)
}
func (p *NodeChainExecutionProjection) DNSCapture(execution string) (NodeChainExecutionDNSCapture, error) {
	if p.validateCapture() != nil {
		return NodeChainExecutionDNSCapture{}, nodeChainExecutionError
	}
	result, err := p.policy.DNSCapture(execution)
	if err != nil {
		return NodeChainExecutionDNSCapture{}, err
	}
	result.DNS.ConfigSHA256 = p.hash
	return result, nil
}
func (p *NodeChainExecutionProjection) PhysicalEgress() ([]PhysicalEgress, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.policy.PhysicalEgress()
}

// ValidateTransition rejects incomplete, stale or relabeled config receipts.
// It deliberately cannot establish native pointer, TUN or socket ownership.
func (p *NodeChainExecutionProjection) ValidateTransition(preparationConfig, projectedConfig string) error {
	if p.validateCapture() != nil || preparationConfig != p.preparation.config || projectedConfig != p.config {
		return nodeChainExecutionError
	}
	return nil
}
