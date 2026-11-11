package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
)

// DesktopNodeChainMetadata binds one physical owner to the complete ordered
// source. SourceSHA256 identifies that session/platform owner; the separate
// OriginalSourceSHA256 is the unchanged ordered source used by NodeChainEngine.
// ConfigSHA256 is the one final executable graph hash used by both owners.
type DesktopNodeChainMetadata struct {
	Schema                 int                       `json:"schema"`
	SessionID              string                    `json:"session_id"`
	TargetOS               string                    `json:"target_os"`
	SourceSHA256           string                    `json:"source_sha256"`
	ConfigSHA256           string                    `json:"config_sha256"`
	OriginalSourceSHA256   string                    `json:"original_source_sha256"`
	OriginalConfigSHA256   string                    `json:"original_config_sha256"`
	OriginalMetadataSHA256 string                    `json:"original_metadata_sha256"`
	OriginalCaptureSHA256  string                    `json:"original_capture_sha256"`
	ProfileID              string                    `json:"profile_id"`
	NodeID                 string                    `json:"node_id"`
	Mode                   string                    `json:"mode"`
	StartLayer             string                    `json:"start_layer"`
	FinalTag               string                    `json:"final_tag"`
	TUNTag                 string                    `json:"tun_tag"`
	OriginalTUNSHA256      string                    `json:"original_tun_sha256"`
	DerivedTUNSHA256       string                    `json:"derived_tun_sha256"`
	Prefixes               []NodeChainProof          `json:"prefixes"`
	Roots                  []DesktopNodeRootMetadata `json:"roots"`
	KillSwitchPolicy       string                    `json:"kill_switch_policy"`
	IPv6Mode               string                    `json:"ipv6_mode"`
	HomeLANAccess          bool                      `json:"home_lan_access"`
	RestoredMTU            int                       `json:"restored_mtu,omitempty"`
}

// DesktopNodeChainPolicy is an independent sealed constructor, never a pair
// cast or caller-created metadata adapter. Its NodeChain contains the actual
// native physical service graph; launch parsing repeats this exact derivation.
// The existing platform connection owner still owns admission and retirement.
type DesktopNodeChainPolicy struct {
	original *NodeChain
	chain    *NodeChain
	metadata DesktopNodeChainMetadata
	inputs   desktopNodePolicyInputs
	seal     string
}

var desktopNodeChainPolicyError = errors.New("desktop ordered chain requires its complete sealed source and original physical owner")

func NewDesktopNodeChainPolicy(original *NodeChain, sessionID, targetOS string, restoredMTU int) (*DesktopNodeChainPolicy, error) {
	policy, _, err := deriveDesktopNodeChainPolicy(original, desktopNodePolicyInputs{sessionID, targetOS, restoredMTU})
	if err != nil || policy.Validate() != nil {
		return nil, desktopNodeChainPolicyError
	}
	return policy, nil
}

func deriveDesktopNodeChainPolicy(original *NodeChain, inputs desktopNodePolicyInputs) (*DesktopNodeChainPolicy, DesktopPhysicalCapture, error) {
	bad := func() (*DesktopNodeChainPolicy, DesktopPhysicalCapture, error) {
		return nil, DesktopPhysicalCapture{}, desktopNodeChainPolicyError
	}
	if original == nil || original.validateCapture() != nil || original.projection.Kind != "" ||
		!desktopExternalSessionID.MatchString(inputs.sessionID) ||
		inputs.targetOS != "linux" && inputs.targetOS != "windows" && inputs.targetOS != "darwin" {
		return bad()
	}
	// Normalize only through the complete constructor source. A prior TUN-only
	// projection grants no implicit restore value or inherited platform owner.
	base, err := NewNodeChain(original.sourceJSON)
	if err != nil {
		return bad()
	}
	derived, err := ProjectNodeChain(base, inputs.targetOS, inputs.restoredMTU)
	if err != nil {
		return bad()
	}
	capture, kill, lan, err := captureDesktopNodeChain(base, derived)
	if err != nil || kill != "on-connect" && kill != "always" {
		return bad()
	}
	launch, err := base.LaunchInput()
	if err != nil {
		return bad()
	}
	var oldGraph, graph map[string]any
	if exactJSON([]byte(base.config), &oldGraph, 4<<20) != nil || exactJSON([]byte(derived.config), &graph, 4<<20) != nil {
		return bad()
	}
	oldTUN := oldGraph["inbounds"].([]any)[0].(map[string]any)
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	final := derived.proofs[len(derived.proofs)-1]
	meta := DesktopNodeChainMetadata{
		Schema: 1, SessionID: inputs.sessionID, TargetOS: inputs.targetOS,
		OriginalSourceSHA256: base.sourceSHA, OriginalConfigSHA256: base.originalConfigSHA,
		OriginalMetadataSHA256: externalDigest([]byte(base.metadata)), OriginalCaptureSHA256: externalDigest([]byte(launch)),
		ProfileID: final.ProfileID, NodeID: final.NodeID, Mode: final.Mode, StartLayer: final.StartLayer,
		FinalTag: final.Tag, TUNTag: capture.TUNTag, Prefixes: derived.ProofInventory(),
		OriginalTUNSHA256: desktopExternalObjectDigest(oldTUN), DerivedTUNSHA256: desktopExternalObjectDigest(tun),
		KillSwitchPolicy: kill, IPv6Mode: capture.IPv6Mode, HomeLANAccess: lan, RestoredMTU: inputs.restoredMTU,
	}
	physical := make([]map[string]any, 0, len(capture.PhysicalRoots))
	for _, root := range capture.PhysicalRoots {
		var found map[string]any
		rows, _ := graph[root.Family].([]any)
		for _, raw := range rows {
			value := raw.(map[string]any)
			if value["tag"] != root.Tag {
				continue
			}
			if found != nil || value["type"] != root.Type || predecessorText(value, "detour") != "" ||
				desktopExternalObjectDigest(value) != root.ConfigSHA256 || root.DynamicSOCKSUDP {
				return bad()
			}
			found = value
		}
		if found == nil {
			return bad()
		}
		physical = append(physical, found)
		meta.Roots = append(meta.Roots, DesktopNodeRootMetadata{Family: root.Family, Tag: root.Tag, Type: root.Type, OriginalSHA256: root.ConfigSHA256})
	}
	meta.SourceSHA256 = desktopExternalObjectDigest(struct {
		Domain string                   `json:"domain"`
		Policy DesktopNodeChainMetadata `json:"policy"`
	}{"routervpn-desktop-node-chain-source-v1", meta})
	if !proofID.MatchString(meta.SourceSHA256) {
		return bad()
	}
	for index, root := range physical {
		root["detour"] = DesktopNodePhysicalTag
		meta.Roots[index].DerivedSHA256 = desktopExternalObjectDigest(root)
	}
	if adaptDesktopPhysicalDNS(graph, capture.SelectedDNS, capture.BootstrapDNS) != nil {
		return bad()
	}
	graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{
		"type": DesktopNodePhysicalType, "tag": DesktopNodePhysicalTag,
		"session_id": inputs.sessionID, "source_sha256": meta.SourceSHA256,
	})
	graph["services"] = []any{map[string]any{
		"type": DesktopNodeNetworkType, "tag": DesktopNodeNetworkTag,
		"session_id": inputs.sessionID, "source_sha256": meta.SourceSHA256,
	}}
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return bad()
	}
	derived.projection.Kind, derived.projection.SessionID = nodeChainDesktopPhysicalKind, inputs.sessionID
	derived.projection.PhysicalSourceSHA256, derived.projection.BaseConfigSHA256 = meta.SourceSHA256, derived.ConfigSHA256()
	derived.config, derived.dns.ConfigSHA256 = string(raw), externalDigest(raw)
	if derived.refreshMetadata() != nil {
		return bad()
	}
	derived.seal = derived.captureSeal()
	if _, err := derived.LaunchInput(); err != nil {
		return bad()
	}
	meta.ConfigSHA256 = derived.ConfigSHA256()
	policy := &DesktopNodeChainPolicy{original: original, chain: derived, metadata: meta, inputs: inputs}
	policy.seal = policy.currentSeal()
	return policy, capture, nil
}

// Capture the unadapted graph using the same strict lower-transport traversal
// as other native policies. Every prefix must converge on the original first
// transport; neither a private proof target nor selected DNS becomes an allow.
func captureDesktopNodeChain(base, projected *NodeChain) (DesktopPhysicalCapture, string, bool, error) {
	bad := func() (DesktopPhysicalCapture, string, bool, error) {
		return DesktopPhysicalCapture{}, "", false, desktopNodeChainPolicyError
	}
	finalCapture, err := base.nodes[len(base.nodes)-1].DesktopCapture()
	if err != nil {
		return bad()
	}
	kill, ipv6, lan := "off", "on", true
	for _, node := range base.nodes {
		capture, err := node.DesktopCapture()
		if err != nil {
			return bad()
		}
		if capture.KillSwitchPolicy == "always" || kill == "off" && capture.KillSwitchPolicy == "on-connect" {
			kill = capture.KillSwitchPolicy
		}
		if capture.IPv6Mode == "off" {
			ipv6 = "off"
		}
		lan = lan && capture.HomeLANAccess
	}
	var graph map[string]any
	if exactJSON([]byte(projected.config), &graph, 4<<20) != nil {
		return bad()
	}
	graph["route"].(map[string]any)["final"] = projected.FinalTag()
	projection, err := json.Marshal(graph)
	if err != nil {
		return bad()
	}
	collector := &externalDesktopRecorder{families: map[string]string{}, roots: map[string]*ExternalDesktopPhysicalRoot{}, bootstrap: map[string]ExternalDesktopDNS{}}
	for _, proof := range projected.proofs {
		tuples, err := compiledPhysicalEgressWithDesktopProof(string(projection), []string{"tcp", "udp"}, collector, proof.Tag)
		if err != nil || !nodeChainSamePhysical(tuples, base.physical) {
			return bad()
		}
	}
	selectedFound := false
	for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
		server := raw.(map[string]any)
		if server["tag"] != projected.dns.ResolverTag {
			continue
		}
		if selectedFound || server["detour"] != projected.FinalTag() ||
			desktopExternalObjectDigest(server) != projected.dns.ResolverSHA256 ||
			collector.dns(ExternalDNSTag, server, false, false, finalCapture.SelectedDNS.Port) != nil {
			return bad()
		}
		collector.selected.Tag, collector.selected.Mode, selectedFound = projected.dns.ResolverTag, finalCapture.SelectedDNS.Mode, true
	}
	if !selectedFound || len(collector.roots) == 0 || len(collector.roots) > 32 {
		return bad()
	}
	var baseGraph map[string]any
	if exactJSON([]byte(base.config), &baseGraph, 4<<20) != nil {
		return bad()
	}
	configured, err := mtuNumber(baseGraph["inbounds"].([]any)[0].(map[string]any)["mtu"])
	if err != nil {
		return bad()
	}
	result := DesktopPhysicalCapture{TUNTag: projected.dns.TUNTag, IPv6Mode: ipv6, ConfiguredMTU: configured, SelectedDNS: collector.selected}
	for _, bootstrap := range collector.bootstrap {
		result.BootstrapDNS = append(result.BootstrapDNS, bootstrap)
	}
	sort.Slice(result.BootstrapDNS, func(i, j int) bool { return result.BootstrapDNS[i].Tag < result.BootstrapDNS[j].Tag })
	for _, root := range collector.roots {
		sort.Strings(root.Networks)
		sortPhysicalEgress(root.Destinations)
		result.PhysicalRoots = append(result.PhysicalRoots, *root)
	}
	sort.Slice(result.PhysicalRoots, func(i, j int) bool {
		if result.PhysicalRoots[i].Family != result.PhysicalRoots[j].Family {
			return result.PhysicalRoots[i].Family < result.PhysicalRoots[j].Family
		}
		return result.PhysicalRoots[i].Tag < result.PhysicalRoots[j].Tag
	})
	for _, tuple := range base.physical {
		address, err := netip.ParseAddr(tuple.Host)
		if err == nil && address.IsPrivate() {
			result.PrivateDestinations = append(result.PrivateDestinations, tuple)
		}
	}
	return result, kill, lan, nil
}

func (p *DesktopNodeChainPolicy) currentSeal() string {
	if p == nil || p.chain == nil {
		return ""
	}
	return desktopExternalObjectDigest(struct {
		Domain   string                   `json:"domain"`
		Chain    string                   `json:"chain_seal"`
		Metadata DesktopNodeChainMetadata `json:"metadata"`
	}{"routervpn-desktop-node-chain-plan-v1", p.chain.captureSeal(), p.metadata})
}

func (p *DesktopNodeChainPolicy) validatedCapture() (DesktopPhysicalCapture, error) {
	if p == nil || p.original == nil || p.chain == nil || p.seal == "" || p.currentSeal() != p.seal ||
		p.chain.validateCapture() != nil || p.metadata.Schema != 1 || p.metadata.ConfigSHA256 != p.chain.ConfigSHA256() ||
		p.metadata.OriginalSourceSHA256 != p.chain.SourceSHA256() {
		return DesktopPhysicalCapture{}, desktopNodeChainPolicyError
	}
	derived, capture, err := deriveDesktopNodeChainPolicy(p.original, p.inputs)
	if err != nil || derived.seal != p.seal || derived.chain.config != p.chain.config {
		return DesktopPhysicalCapture{}, desktopNodeChainPolicyError
	}
	return capture, nil
}

func (p *DesktopNodeChainPolicy) Validate() error {
	_, err := p.validatedCapture()
	return err
}

func (p *DesktopNodeChainPolicy) ReadValidated() (string, DesktopNodeChainMetadata, DesktopPhysicalCapture, error) {
	capture, err := p.validatedCapture()
	if err != nil {
		return "", DesktopNodeChainMetadata{}, DesktopPhysicalCapture{}, err
	}
	meta := p.metadata
	meta.Prefixes = append([]NodeChainProof(nil), meta.Prefixes...)
	meta.Roots = append([]DesktopNodeRootMetadata(nil), meta.Roots...)
	return p.chain.config, meta, capture, nil
}

func (p *DesktopNodeChainPolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.chain.config
}

func (p *DesktopNodeChainPolicy) NodeChain() *NodeChain {
	if p.Validate() != nil {
		return nil
	}
	return p.chain
}

func (p *DesktopNodeChainPolicy) OriginalChain() *NodeChain {
	if p.Validate() != nil {
		return nil
	}
	return p.original
}

func (p *DesktopNodeChainPolicy) Metadata() DesktopNodeChainMetadata {
	_, meta, _, err := p.ReadValidated()
	if err != nil {
		return DesktopNodeChainMetadata{}
	}
	return meta
}

func (*DesktopNodeChainPolicy) desktopPhysicalPolicy() {}

func (p *DesktopNodeChainPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	config, meta, capture, err := p.ReadValidated()
	if err != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	return config, DesktopPhysicalMetadata{Kind: "node-chain", SessionID: meta.SessionID, TargetOS: meta.TargetOS,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256,
		ProfileID: meta.ProfileID, NodeID: meta.NodeID, Mode: meta.Mode, StartLayer: meta.StartLayer,
		KillSwitchPolicy: meta.KillSwitchPolicy, IPv6Mode: meta.IPv6Mode, HomeLANAccess: meta.HomeLANAccess, RestoredMTU: meta.RestoredMTU}, capture, nil
}

// ParseDesktopNodeChainLaunchInput is the child-side typed authority parser.
// It does not project an already-derived chain a second time or adopt caller
// supplied graph bytes. The embedded source and derivation receipt must agree.
func ParseDesktopNodeChainLaunchInput(input string) (*DesktopNodeChainPolicy, error) {
	chain, err := ParseNodeChainLaunchInput(input)
	if err != nil || chain.projection.Kind != nodeChainDesktopPhysicalKind {
		return nil, desktopNodeChainPolicyError
	}
	base, err := NewNodeChain(chain.sourceJSON)
	if err != nil {
		return nil, desktopNodeChainPolicyError
	}
	policy, err := NewDesktopNodeChainPolicy(base, chain.projection.SessionID, chain.projection.TargetOS, chain.projection.RestoredMTU)
	if err != nil {
		return nil, desktopNodeChainPolicyError
	}
	actual, err := policy.chain.LaunchInput()
	if err != nil || actual != input {
		return nil, desktopNodeChainPolicyError
	}
	return policy, nil
}
