package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
)

// DesktopNodeCandidatePreparationMetadata describes a closed prefix source,
// never successful private proof, native MTU readback, DNS or Connected state.
// The complete saved graph remains immutable provenance for an explicit Save.
type DesktopNodeCandidatePreparationMetadata struct {
	Schema                int                       `json:"schema"`
	SessionID             string                    `json:"session_id"`
	TargetOS              string                    `json:"target_os"`
	SourceSHA256          string                    `json:"source_sha256"`
	ConfigSHA256          string                    `json:"config_sha256"`
	CaptureSHA256         string                    `json:"capture_sha256"`
	OriginalSourceSHA256  string                    `json:"original_source_sha256"`
	PreparationSHA256     string                    `json:"preparation_sha256"`
	OriginalCaptureSHA256 string                    `json:"original_capture_sha256"`
	PrefixPosition        int                       `json:"prefix_position"`
	ProfileID             string                    `json:"profile_id"`
	PolicyProfileID       string                    `json:"policy_profile_id"`
	NodeID                string                    `json:"node_id"`
	Mode                  string                    `json:"mode"`
	StartLayer            string                    `json:"start_layer"`
	TUNTag                string                    `json:"tun_tag"`
	OriginalTUNSHA256     string                    `json:"original_tun_sha256"`
	DerivedTUNSHA256      string                    `json:"derived_tun_sha256"`
	Prefixes              []NodeChainProof          `json:"prefixes"`
	Roots                 []DesktopNodeRootMetadata `json:"roots"`
	KillSwitchPolicy      string                    `json:"kill_switch_policy"`
	IPv6Mode              string                    `json:"ipv6_mode"`
	HomeLANAccess         bool                      `json:"home_lan_access"`
	RestoredMTU           int                       `json:"restored_mtu,omitempty"`
	ApplicationOpen       bool                      `json:"application_open"`
	DNSOpen               bool                      `json:"dns_open"`
}

// This is a distinct constructor, not a NodeChain or a full-chain readiness
// adapter. Its only executable graph is the selected paired packet prefix.
type DesktopNodeCandidatePreparationPolicy struct {
	original    *NodeChainCandidatePreparation
	preparation *NodeChainCandidatePreparation
	metadata    DesktopNodeCandidatePreparationMetadata
	capture     DesktopPhysicalCapture
	inputs      desktopNodePolicyInputs
	seal        string
}

type desktopNodeCandidatePreparationSource struct {
	Kind          string `json:"kind"`
	Schema        int    `json:"schema"`
	Preparation   string `json:"preparation"`
	SessionID     string `json:"session_id"`
	TargetOS      string `json:"target_os"`
	RestoredMTU   int    `json:"restored_mtu,omitempty"`
	SourceSHA256  string `json:"source_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
	CaptureSHA256 string `json:"capture_sha256"`
}

var desktopNodeCandidatePreparationError = errors.New("desktop candidate preparation requires its sealed prefix source and original physical owner")

func NewDesktopNodeCandidatePreparationPolicy(original *NodeChainCandidatePreparation, sessionID, targetOS string, restoredMTU int) (*DesktopNodeCandidatePreparationPolicy, error) {
	bad := func() (*DesktopNodeCandidatePreparationPolicy, error) {
		return nil, desktopNodeCandidatePreparationError
	}
	if original == nil || original.validate() != nil || !desktopExternalSessionID.MatchString(sessionID) ||
		targetOS != "linux" && targetOS != "windows" && targetOS != "darwin" {
		return bad()
	}
	// A desktop projection cannot be projected again or substituted for the
	// generic source. This parse also separates the new owner's mutable slices.
	derived, err := ParseNodeChainCandidatePreparation(original.source)
	if err != nil || derived.seal != original.seal {
		return bad()
	}
	var graph map[string]any
	if exactJSON([]byte(derived.config), &graph, 4<<20) != nil {
		return bad()
	}
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	originalTUN := desktopExternalObjectDigest(tun)
	configured, err := mtuNumber(tun["mtu"])
	if err != nil {
		return bad()
	}
	if restoredMTU != 0 {
		final := derived.original.nodes[len(derived.original.nodes)-1].profile
		fixed, fixedErr := fixedMTU(final)
		jumbo, jumboErr := externalJumboPreference(final)
		if _, err := mtuNumber(float64(restoredMTU)); err != nil || fixedErr != nil || jumboErr != nil ||
			fixed != 0 && restoredMTU != fixed || jumbo && (configured != 9000 || restoredMTU != configured) {
			return bad()
		}
		tun["mtu"] = float64(restoredMTU)
	}
	if targetOS == "darwin" {
		delete(tun, "interface_name")
	} else {
		tun["interface_name"] = "router-vpn"
	}
	derived.mtu, err = candidatePreparationMTU(graph, derived.proofs)
	if err != nil {
		return bad()
	}
	capture, kill, lan, err := captureDesktopCandidatePrefix(derived, graph, configured)
	if err != nil || kill != "on-connect" && kill != "always" {
		return bad()
	}
	prefix := derived.proofs[derived.position]
	// Native proof names the selected prefix. Durable protection belongs to
	// the original complete saved control, whose restrictions were aggregated
	// above, even when that final node is deliberately absent from this graph.
	control := derived.original.proofs[len(derived.original.proofs)-1].ProfileID
	meta := DesktopNodeCandidatePreparationMetadata{Schema: 1, SessionID: sessionID, TargetOS: targetOS,
		OriginalSourceSHA256: original.original.sourceSHA, PreparationSHA256: original.sourceSHA,
		OriginalCaptureSHA256: original.capture, PrefixPosition: original.position,
		ProfileID: prefix.ProfileID, PolicyProfileID: control, NodeID: prefix.NodeID, Mode: prefix.Mode, StartLayer: prefix.StartLayer,
		TUNTag: capture.TUNTag, OriginalTUNSHA256: originalTUN, DerivedTUNSHA256: desktopExternalObjectDigest(tun),
		Prefixes: append([]NodeChainProof(nil), derived.proofs...), KillSwitchPolicy: kill,
		IPv6Mode: capture.IPv6Mode, HomeLANAccess: lan, RestoredMTU: restoredMTU}
	meta.SourceSHA256 = desktopExternalObjectDigest([]any{"routervpn-desktop-candidate-prefix-source-v1", original.sourceSHA, sessionID, targetOS, restoredMTU})
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
		found["detour"] = DesktopNodePhysicalTag
		meta.Roots = append(meta.Roots, DesktopNodeRootMetadata{Family: root.Family, Tag: root.Tag, Type: root.Type,
			OriginalSHA256: root.ConfigSHA256, DerivedSHA256: desktopExternalObjectDigest(found)})
	}
	if adaptDesktopPhysicalDNS(graph, capture.SelectedDNS, capture.BootstrapDNS) != nil {
		return bad()
	}
	graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": DesktopNodePhysicalType,
		"tag": DesktopNodePhysicalTag, "session_id": sessionID, "source_sha256": meta.SourceSHA256})
	graph["services"] = []any{map[string]any{"type": DesktopNodeNetworkType, "tag": DesktopNodeNetworkTag,
		"session_id": sessionID, "source_sha256": meta.SourceSHA256}}
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return bad()
	}
	derived.config, derived.configSHA, derived.sourceSHA = string(raw), externalDigest(raw), meta.SourceSHA256
	derived.capture = desktopExternalObjectDigest([]string{derived.sourceSHA, derived.configSHA, derived.candidates.capture})
	meta.ConfigSHA256, meta.CaptureSHA256 = derived.configSHA, derived.capture
	record := desktopNodeCandidatePreparationSource{"routervpn-desktop-node-candidate-preparation", 1, original.source,
		sessionID, targetOS, restoredMTU, meta.SourceSHA256, meta.ConfigSHA256, meta.CaptureSHA256}
	raw, err = json.Marshal(record)
	if err != nil || len(raw) > NodeChainInputLimit {
		return bad()
	}
	derived.source = string(raw)
	derived.seal = derived.digest()
	p := &DesktopNodeCandidatePreparationPolicy{original: original, preparation: derived, metadata: meta, capture: capture,
		inputs: desktopNodePolicyInputs{sessionID, targetOS, restoredMTU}}
	p.seal = p.currentSeal()
	return p, p.Validate()
}

// Capture lower transports from the partial graph itself. The old final and
// unselected middle members supply only saved protection restrictions, never
// a runnable endpoint, DNS permission or proof target.
func captureDesktopCandidatePrefix(p *NodeChainCandidatePreparation, graph map[string]any, configured int) (DesktopPhysicalCapture, string, bool, error) {
	bad := func() (DesktopPhysicalCapture, string, bool, error) {
		return DesktopPhysicalCapture{}, "", false, desktopNodeCandidatePreparationError
	}
	kill, ipv6, lan := "off", "on", true
	for position, node := range p.original.nodes {
		var capture nodeChainImportedDevicePolicy
		if position == 1 && p.original.importedMiddle != nil {
			var err error
			capture, err = p.original.importedMiddle.devicePolicy()
			if err != nil {
				return bad()
			}
		} else {
			paired, err := node.DesktopCapture()
			if err != nil {
				return bad()
			}
			capture.KillSwitchPolicy, capture.IPv6Mode, capture.HomeLANAccess = paired.KillSwitchPolicy, paired.IPv6Mode, paired.HomeLANAccess
		}
		if capture.KillSwitchPolicy == "always" || kill == "off" && capture.KillSwitchPolicy == "on-connect" {
			kill = capture.KillSwitchPolicy
		}
		if capture.IPv6Mode == "off" {
			ipv6 = "off"
		}
		lan = lan && capture.HomeLANAccess
	}
	selectedCapture, err := p.original.nodes[p.position].DesktopCapture()
	if err != nil {
		return bad()
	}
	projection := predecessorCopy(graph)
	projection["route"].(map[string]any)["final"] = p.proofs[p.position].Tag
	raw, err := json.Marshal(projection)
	if err != nil {
		return bad()
	}
	collector := &externalDesktopRecorder{families: map[string]string{}, roots: map[string]*ExternalDesktopPhysicalRoot{}, bootstrap: map[string]ExternalDesktopDNS{}}
	for _, proof := range p.proofs {
		tuples, err := compiledPhysicalEgressWithDesktopProof(string(raw), []string{"tcp", "udp"}, collector, proof.Tag)
		if err != nil || !nodeChainSamePhysical(tuples, p.physical) {
			return bad()
		}
	}
	dns := graph["dns"].(map[string]any)
	selected := predecessorText(dns, "final")
	found := false
	for _, raw := range dns["servers"].([]any) {
		server := raw.(map[string]any)
		if server["tag"] != selected {
			continue
		}
		if found || server["detour"] != p.proofs[p.position].Tag || collector.dns(ExternalDNSTag, server, false, false, selectedCapture.SelectedDNS.Port) != nil {
			return bad()
		}
		collector.selected.Tag, collector.selected.Mode, found = selected, selectedCapture.SelectedDNS.Mode, true
	}
	if !found || len(collector.roots) == 0 || len(collector.roots) > 32 {
		return bad()
	}
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	result := DesktopPhysicalCapture{TUNTag: predecessorText(tun, "tag"), IPv6Mode: ipv6, ConfiguredMTU: configured, SelectedDNS: collector.selected}
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
	for _, tuple := range p.physical {
		address, err := netip.ParseAddr(tuple.Host)
		if err == nil && address.IsPrivate() {
			result.PrivateDestinations = append(result.PrivateDestinations, tuple)
		}
	}
	return result, kill, lan, nil
}

func (p *DesktopNodeCandidatePreparationPolicy) currentSeal() string {
	if p == nil || p.original == nil || p.preparation == nil {
		return ""
	}
	return desktopExternalObjectDigest([]any{"routervpn-desktop-candidate-prefix-policy-v1", p.original.seal, p.preparation.seal,
		p.metadata, p.capture, p.inputs.sessionID, p.inputs.targetOS, p.inputs.restoredMTU})
}

func (p *DesktopNodeCandidatePreparationPolicy) Validate() error {
	if p == nil || p.original == nil || p.preparation == nil || p.original == p.preparation ||
		p.original.validate() != nil || p.preparation.validate() != nil || p.seal == "" || p.currentSeal() != p.seal ||
		p.metadata.ApplicationOpen || p.metadata.DNSOpen || p.metadata.SourceSHA256 != p.preparation.sourceSHA ||
		p.metadata.PolicyProfileID != p.original.original.proofs[len(p.original.original.proofs)-1].ProfileID ||
		p.metadata.ConfigSHA256 != p.preparation.configSHA || p.metadata.CaptureSHA256 != p.preparation.capture {
		return desktopNodeCandidatePreparationError
	}
	return nil
}

func (*DesktopNodeCandidatePreparationPolicy) desktopPhysicalPolicy() {}

func (p *DesktopNodeCandidatePreparationPolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.preparation.config
}

func (p *DesktopNodeCandidatePreparationPolicy) Source() string {
	if p.Validate() != nil {
		return ""
	}
	return p.preparation.source
}

func (p *DesktopNodeCandidatePreparationPolicy) Preparation() *NodeChainCandidatePreparation {
	if p.Validate() != nil {
		return nil
	}
	return p.preparation
}

func (p *DesktopNodeCandidatePreparationPolicy) Metadata() DesktopNodeCandidatePreparationMetadata {
	if p.Validate() != nil {
		return DesktopNodeCandidatePreparationMetadata{}
	}
	meta := p.metadata
	meta.Prefixes = append([]NodeChainProof(nil), meta.Prefixes...)
	meta.Roots = append([]DesktopNodeRootMetadata(nil), meta.Roots...)
	return meta
}

func (p *DesktopNodeCandidatePreparationPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	if p.Validate() != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, desktopNodeCandidatePreparationError
	}
	// Query data cannot mutate the retained source or broaden a physical allow.
	raw, err := json.Marshal(p.capture)
	var capture DesktopPhysicalCapture
	if err != nil || json.Unmarshal(raw, &capture) != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, desktopNodeCandidatePreparationError
	}
	m := p.metadata
	return p.preparation.config, DesktopPhysicalMetadata{Kind: "node-candidate-prefix", SessionID: m.SessionID, TargetOS: m.TargetOS,
		SourceSHA256: m.SourceSHA256, ConfigSHA256: m.ConfigSHA256, ProfileID: m.ProfileID, NodeID: m.NodeID, Mode: m.Mode, StartLayer: m.StartLayer,
		KillSwitchPolicy: m.KillSwitchPolicy, IPv6Mode: m.IPv6Mode, HomeLANAccess: m.HomeLANAccess, RestoredMTU: m.RestoredMTU}, capture, nil
}

// Parsing replays only the closed source constructor and compares exact bytes;
// a supplied graph, full-chain launch or generic mobile prefix is never enough.
func ParseDesktopNodeCandidatePreparationPolicy(input string) (*DesktopNodeCandidatePreparationPolicy, error) {
	var record desktopNodeCandidatePreparationSource
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil || record.Schema != 1 || record.Kind != "routervpn-desktop-node-candidate-preparation" {
		return nil, desktopNodeCandidatePreparationError
	}
	base, err := ParseNodeChainCandidatePreparation(record.Preparation)
	if err != nil {
		return nil, desktopNodeCandidatePreparationError
	}
	policy, err := NewDesktopNodeCandidatePreparationPolicy(base, record.SessionID, record.TargetOS, record.RestoredMTU)
	if err != nil || policy.Source() != input {
		return nil, desktopNodeCandidatePreparationError
	}
	return policy, nil
}
