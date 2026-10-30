package mobilemultihop

import (
	"encoding/json"
	"errors"
)

const (
	DesktopNodeNetworkType  = "routervpn-desktop-node-network"
	DesktopNodeNetworkTag   = "routervpn-node-network-owner"
	DesktopNodePhysicalType = "routervpn-desktop-node-physical"
	DesktopNodePhysicalTag  = "routervpn-node-physical-egress"
)

type DesktopNodeRootMetadata struct {
	Family         string `json:"family"`
	Tag            string `json:"tag"`
	Type           string `json:"type"`
	OriginalSHA256 string `json:"original_sha256"`
	DerivedSHA256  string `json:"derived_sha256"`
}

// DesktopNodeMetadata binds the retained original compiler output and exact
// desktop adaptation. Its hashes describe bytes and captured identity; none is
// a successful node/DNS/MTU proof or a native socket capability.
type DesktopNodeMetadata struct {
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
	Roots                  []DesktopNodeRootMetadata `json:"roots"`
	KillSwitchPolicy       string                    `json:"kill_switch_policy"`
	IPv6Mode               string                    `json:"ipv6_mode"`
	HomeLANAccess          bool                      `json:"home_lan_access"`
	RestoredMTU            int                       `json:"restored_mtu,omitempty"`
}

// DesktopNodePolicy derives only from a sealed NodeProfile. It is distinct from
// the direct ordinary-proxy DesktopExternalPolicy and never broadens that
// constructor. Native availability, retained kernel ownership and readiness are
// separately proved by the target host; there is no public metadata constructor.
type DesktopNodePolicy struct {
	original *NodeProfile
	config   string
	metadata DesktopNodeMetadata
	inputs   desktopNodePolicyInputs
	seal     string
}

type desktopNodePolicyInputs struct {
	sessionID   string
	targetOS    string
	restoredMTU int
}

var desktopNodePolicyError = errors.New("desktop Router node lower path requires its complete sealed native source")

func NewDesktopNodePolicy(original *NodeProfile, sessionID, targetOS string) (*DesktopNodePolicy, error) {
	return NewDesktopNodePolicyWithMTU(original, sessionID, targetOS, 0)
}

// NewDesktopNodePolicyWithMTU restores only a previously captured live system
// TUN value. Zero retains the original compiler's configured MTU and exact
// existing desktop bytes. A nonzero value is part of the new source identity,
// even when it equals the original. The caller must own the live readback and
// path; compilation neither measures a path nor proves that this value worked.
// The original profile, packet endpoint MTUs, private inputs and saved policy
// remain unchanged. Fixed and explicit Jumbo selections cannot be overridden.
func NewDesktopNodePolicyWithMTU(original *NodeProfile, sessionID, targetOS string, restoredMTU int) (*DesktopNodePolicy, error) {
	policy, err := deriveDesktopNodePolicy(original, desktopNodePolicyInputs{sessionID, targetOS, restoredMTU})
	if err != nil || policy.Validate() != nil {
		return nil, desktopNodePolicyError
	}
	return policy, nil
}

func deriveDesktopNodePolicy(original *NodeProfile, inputs desktopNodePolicyInputs) (*DesktopNodePolicy, error) {
	sessionID, targetOS, restoredMTU := inputs.sessionID, inputs.targetOS, inputs.restoredMTU
	if original == nil || !desktopExternalSessionID.MatchString(sessionID) ||
		(targetOS != "linux" && targetOS != "windows" && targetOS != "darwin") {
		return nil, desktopNodePolicyError
	}
	capture, err := original.DesktopCapture()
	if err != nil || (capture.KillSwitchPolicy != "on-connect" && capture.KillSwitchPolicy != "always") ||
		(capture.IPv6Mode != "on" && capture.IPv6Mode != "off") || !capture.UDPAvailable ||
		capture.FinalTag != "proxy" || len(capture.PhysicalRoots) == 0 || len(capture.PhysicalRoots) > 32 {
		return nil, desktopNodePolicyError
	}
	if restoredMTU != 0 {
		if _, err := mtuNumber(float64(restoredMTU)); err != nil {
			return nil, desktopNodePolicyError
		}
		jumbo, err := externalJumboPreference(original.profile)
		if err != nil || capture.MTUPolicy == "fixed" && restoredMTU != capture.ConfiguredMTU ||
			jumbo && (capture.ConfiguredMTU != 9000 || restoredMTU != capture.ConfiguredMTU) {
			return nil, desktopNodePolicyError
		}
	}
	var graph map[string]any
	if exactJSON([]byte(original.Config()), &graph, 4<<20) != nil || graph == nil {
		return nil, desktopNodePolicyError
	}
	for _, family := range []string{"inbounds", "outbounds", "endpoints", "services"} {
		if raw, exists := graph[family]; exists {
			rows, ok := raw.([]any)
			if !ok {
				return nil, desktopNodePolicyError
			}
			for _, raw := range rows {
				value, ok := raw.(map[string]any)
				if !ok || value["tag"] == DesktopNodePhysicalTag || value["tag"] == DesktopNodeNetworkTag ||
					value["type"] == DesktopNodePhysicalType || value["type"] == DesktopNodeNetworkType {
					return nil, desktopNodePolicyError
				}
			}
		}
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) != 1 {
		return nil, desktopNodePolicyError
	}
	tun, ok := ins[0].(map[string]any)
	if !ok || tun["tag"] != capture.TUNTag || tun["type"] != "tun" {
		return nil, desktopNodePolicyError
	}
	meta := DesktopNodeMetadata{
		Schema: 1, SessionID: sessionID, TargetOS: targetOS,
		OriginalSourceSHA256: capture.SourceSHA256, OriginalConfigSHA256: capture.ConfigSHA256,
		OriginalMetadataSHA256: capture.MetadataSHA256, OriginalCaptureSHA256: capture.CaptureSHA256,
		ProfileID: capture.ProfileID, NodeID: capture.NodeID, Mode: capture.Mode, StartLayer: capture.StartLayer,
		FinalTag: capture.FinalTag, TUNTag: capture.TUNTag, OriginalTUNSHA256: desktopExternalObjectDigest(tun),
		KillSwitchPolicy: capture.KillSwitchPolicy, IPv6Mode: capture.IPv6Mode, HomeLANAccess: capture.HomeLANAccess,
		RestoredMTU: restoredMTU,
	}
	physical := make([]map[string]any, 0, len(capture.PhysicalRoots))
	for _, root := range capture.PhysicalRoots {
		if (root.Family != "endpoints" && root.Family != "outbounds") || root.DynamicSOCKSUDP ||
			!proofID.MatchString(root.ConfigSHA256) || len(root.Destinations) == 0 {
			return nil, desktopNodePolicyError
		}
		var found map[string]any
		rows, _ := graph[root.Family].([]any)
		for _, raw := range rows {
			value := raw.(map[string]any)
			if value["tag"] == root.Tag {
				if found != nil || value["type"] != root.Type || predecessorText(value, "detour") != "" ||
					desktopExternalObjectDigest(value) != root.ConfigSHA256 {
					return nil, desktopNodePolicyError
				}
				found = value
			}
		}
		if found == nil {
			return nil, desktopNodePolicyError
		}
		physical = append(physical, found)
		meta.Roots = append(meta.Roots, DesktopNodeRootMetadata{Family: root.Family, Tag: root.Tag, Type: root.Type, OriginalSHA256: root.ConfigSHA256})
	}
	// The pre-derivation source identity binds the complete original, session
	// and target before inserting owner objects. The final ConfigSHA256 binds
	// all adapted bytes without introducing a self-referential graph digest.
	meta.SourceSHA256 = desktopExternalObjectDigest(struct {
		Domain string              `json:"domain"`
		Policy DesktopNodeMetadata `json:"policy"`
	}{"routervpn-desktop-node-source-v1", meta})
	if !proofID.MatchString(meta.SourceSHA256) {
		return nil, desktopNodePolicyError
	}
	for index, root := range physical {
		root["detour"] = DesktopNodePhysicalTag
		meta.Roots[index].DerivedSHA256 = desktopExternalObjectDigest(root)
	}
	// Desktop naming is part of the sealed adaptation. A launcher must never
	// post-edit this graph to select a different interface or config identity.
	if targetOS == "darwin" {
		delete(tun, "interface_name")
	} else {
		tun["interface_name"] = "router-vpn"
	}
	if restoredMTU != 0 {
		tun["mtu"] = float64(restoredMTU)
	}
	meta.DerivedTUNSHA256 = desktopExternalObjectDigest(tun)
	if err := adaptDesktopNodeDNS(graph, capture); err != nil {
		return nil, err
	}
	rows, _ := graph["outbounds"].([]any)
	graph["outbounds"] = append(rows, map[string]any{
		"type": DesktopNodePhysicalType, "tag": DesktopNodePhysicalTag,
		"session_id": sessionID, "source_sha256": meta.SourceSHA256,
	})
	services, _ := graph["services"].([]any)
	graph["services"] = append(services, map[string]any{
		"type": DesktopNodeNetworkType, "tag": DesktopNodeNetworkTag,
		"session_id": sessionID, "source_sha256": meta.SourceSHA256,
	})
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return nil, desktopNodePolicyError
	}
	meta.ConfigSHA256 = externalDigest(raw)
	policy := &DesktopNodePolicy{original: original, config: string(raw), metadata: meta, inputs: inputs}
	policy.seal = policy.currentSeal()
	if policy.seal == "" {
		return nil, desktopNodePolicyError
	}
	return policy, nil
}

func adaptDesktopNodeDNS(graph map[string]any, capture NodeDesktopCapture) error {
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return desktopNodePolicyError
	}
	servers, ok := dns["servers"].([]any)
	if !ok {
		return desktopNodePolicyError
	}
	selected := false
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		if !ok {
			return desktopNodePolicyError
		}
		if server["tag"] == capture.SelectedDNS.Tag {
			if selected || capture.SelectedDNS.Physical || desktopExternalObjectDigest(server) != capture.SelectedDNS.ConfigSHA256 {
				return desktopNodePolicyError
			}
			selected = true
		}
	}
	if !selected {
		return desktopNodePolicyError
	}
	for _, bootstrap := range capture.BootstrapDNS {
		if !bootstrap.Physical {
			continue
		}
		found := false
		for _, raw := range servers {
			server := raw.(map[string]any)
			if server["tag"] != bootstrap.Tag {
				continue
			}
			if found || bootstrap.Tag == capture.SelectedDNS.Tag || predecessorText(server, "detour") != "" ||
				desktopExternalObjectDigest(server) != bootstrap.ConfigSHA256 {
				return desktopNodePolicyError
			}
			server["detour"], found = DesktopNodePhysicalTag, true
		}
		if !found {
			return desktopNodePolicyError
		}
	}
	return nil
}

func (p *DesktopNodePolicy) currentSeal() string {
	if p == nil || p.original == nil || p.config == "" {
		return ""
	}
	return desktopExternalObjectDigest(struct {
		Domain   string              `json:"domain"`
		Config   string              `json:"config"`
		Metadata DesktopNodeMetadata `json:"metadata"`
	}{"routervpn-desktop-node-plan-v1", p.config, p.metadata})
}

func (p *DesktopNodePolicy) Validate() error {
	if p == nil || p.original == nil || p.seal == "" || p.currentSeal() != p.seal || p.metadata.Schema != 1 ||
		p.metadata.ConfigSHA256 != externalDigest([]byte(p.config)) {
		return desktopNodePolicyError
	}
	// Rebuild from the retained constructor inputs. A matching recomputed hash
	// must not authorize caller-edited graph bytes, metadata or an MTU value
	// substituted after the original desktop capture.
	derived, err := deriveDesktopNodePolicy(p.original, p.inputs)
	if err != nil || derived.config != p.config || derived.seal != p.seal {
		return desktopNodePolicyError
	}
	return nil
}

func (p *DesktopNodePolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.config
}

func (p *DesktopNodePolicy) Metadata() DesktopNodeMetadata {
	if p.Validate() != nil {
		return DesktopNodeMetadata{}
	}
	copy := p.metadata
	copy.Roots = append([]DesktopNodeRootMetadata(nil), p.metadata.Roots...)
	return copy
}

func (p *DesktopNodePolicy) Capture() (NodeDesktopCapture, error) {
	if p.Validate() != nil {
		return NodeDesktopCapture{}, desktopNodePolicyError
	}
	return p.original.DesktopCapture()
}

func (p *DesktopNodePolicy) OriginalProfile() *NodeProfile {
	if p.Validate() != nil {
		return nil
	}
	return p.original
}
