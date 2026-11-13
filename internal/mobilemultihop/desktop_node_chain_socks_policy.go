package mobilemultihop

import (
	"encoding/json"
	"errors"
	"reflect"
)

// DesktopNodeChainSOCKSMetadata is distinct from generic ordered admission.
// Its physical owner hash binds the target/session and the complete original
// typed source; the runtime still proves the unchanged original prefix IDs.
type DesktopNodeChainSOCKSMetadata struct {
	Kind string `json:"kind"`
	DesktopNodeChainMetadata
}

type DesktopNodeChainSOCKSPolicy struct {
	original *NodeChainSOCKSSource
	native   *NodeChainSOCKSSource
	metadata DesktopNodeChainSOCKSMetadata
	inputs   desktopNodePolicyInputs
	seal     string
}

// This private binding is created only by the typed desktop derivation.
// It does not make arbitrary graph bytes a NodeChainSOCKSSource.
type nodeChainSOCKSDesktopBinding struct {
	original   *NodeChainSOCKSSource
	projection nodeChainProjection
	metadata   DesktopNodeChainSOCKSMetadata
	nativeMetadata NodeChainSOCKSSourceMetadata
	seal       string
}

var desktopNodeChainSOCKSPolicyError = errors.New("desktop SOCKS path requires its exact original source and captured physical owner")

func NewDesktopNodeChainSOCKSPolicy(original *NodeChainSOCKSSource, sessionID, targetOS string, restoredMTU int) (*DesktopNodeChainSOCKSPolicy, error) {
	policy, _, err := deriveDesktopNodeChainSOCKSPolicy(original, desktopNodePolicyInputs{sessionID, targetOS, restoredMTU})
	if err != nil || policy.Validate() != nil {
		return nil, desktopNodeChainSOCKSPolicyError
	}
	return policy, nil
}

func deriveDesktopNodeChainSOCKSPolicy(original *NodeChainSOCKSSource, inputs desktopNodePolicyInputs) (*DesktopNodeChainSOCKSPolicy, DesktopPhysicalCapture, error) {
	bad := func() (*DesktopNodeChainSOCKSPolicy, DesktopPhysicalCapture, error) {
		return nil, DesktopPhysicalCapture{}, desktopNodeChainSOCKSPolicyError
	}
	if original == nil || original.desktop != nil || original.validate() != nil ||
		!desktopExternalSessionID.MatchString(inputs.sessionID) ||
		inputs.targetOS != "linux" && inputs.targetOS != "windows" && inputs.targetOS != "darwin" {
		return bad()
	}
	config, originalMeta, err := original.ReadValidated()
	if err != nil || len(originalMeta.Proofs) != 3 || len(originalMeta.Devices) != 3 {
		return bad()
	}
	projectedConfig, err := projectNodeChainTUN(config, original.pair.nodes[1].profile, inputs.targetOS, inputs.restoredMTU)
	if err != nil {
		return bad()
	}
	finalCapture, err := original.pair.nodes[1].DesktopCapture()
	if err != nil {
		return bad()
	}
	kill, ipv6, lan := "off", "on", true
	for position, device := range originalMeta.Devices {
		if device.Position != position || device.ProfileID != originalMeta.Proofs[position].ProfileID {
			return bad()
		}
		if device.KillSwitchPolicy == "always" || kill == "off" && device.KillSwitchPolicy == "on-connect" {
			kill = device.KillSwitchPolicy
		}
		if device.IPv6Mode == "off" {
			ipv6 = "off"
		}
		lan = lan && device.HomeLANAccess
	}
	capture, kill, lan, err := captureDesktopNodeChainGraph(config, projectedConfig, originalMeta.Proofs, originalMeta.DNS, originalMeta.Physical, finalCapture, kill, ipv6, lan)
	if err != nil || kill != "always" && kill != "on-connect" {
		return bad()
	}
	var originalGraph, graph map[string]any
	if exactJSON([]byte(config), &originalGraph, 4<<20) != nil ||
		exactJSON([]byte(projectedConfig), &graph, 4<<20) != nil {
		return bad()
	}
	oldTUN := originalGraph["inbounds"].([]any)[0].(map[string]any)
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	encodedMeta, err := json.Marshal(originalMeta)
	if err != nil {
		return bad()
	}
	final := originalMeta.Proofs[2]
	meta := DesktopNodeChainSOCKSMetadata{
		Kind: "routervpn-desktop-node-chain-socks",
		DesktopNodeChainMetadata: DesktopNodeChainMetadata{
			Schema: 1, SessionID: inputs.sessionID, TargetOS: inputs.targetOS,
			OriginalSourceSHA256: originalMeta.SourceSHA256, OriginalConfigSHA256: originalMeta.ConfigSHA256,
			OriginalMetadataSHA256: externalDigest(encodedMeta), OriginalCaptureSHA256: externalDigest([]byte(original.sourceJSON)),
			ProfileID: final.ProfileID, NodeID: final.NodeID, Mode: final.Mode, StartLayer: final.StartLayer,
			FinalTag: final.Tag, TUNTag: capture.TUNTag, Prefixes: originalMeta.Proofs,
			OriginalTUNSHA256: desktopExternalObjectDigest(oldTUN), DerivedTUNSHA256: desktopExternalObjectDigest(tun),
			KillSwitchPolicy: kill, IPv6Mode: capture.IPv6Mode, HomeLANAccess: lan, RestoredMTU: inputs.restoredMTU,
		},
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
		Domain string `json:"domain"`
		Policy DesktopNodeChainSOCKSMetadata `json:"policy"`
	}{"routervpn-desktop-node-chain-socks-source-v1", meta})
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
	meta.ConfigSHA256 = externalDigest(raw)
	projection := nodeChainProjection{
		TargetOS: inputs.targetOS, RestoredMTU: inputs.restoredMTU,
		Kind: nodeChainDesktopPhysicalKind, SessionID: inputs.sessionID,
		PhysicalSourceSHA256: meta.SourceSHA256, BaseConfigSHA256: externalDigest([]byte(projectedConfig)),
	}
	mtu, err := nodeChainProjectedMTUPlan(string(raw), originalMeta.Proofs, projection)
	if err != nil {
		return bad()
	}
	nativeMeta := originalMeta
	nativeMeta.ConfigSHA256, nativeMeta.DNS.ConfigSHA256, nativeMeta.MTU = meta.ConfigSHA256, meta.ConfigSHA256, mtu
	binding := &nodeChainSOCKSDesktopBinding{original: original, projection: projection, metadata: meta, nativeMetadata: nativeMeta}
	binding.seal = binding.currentSeal()
	native := &NodeChainSOCKSSource{
		sourceJSON: original.sourceJSON, config: string(raw), pair: original.pair, middle: original.middle,
		metadata: nativeMeta, desktop: binding,
	}
	native.seal = native.digest()
	if native.validate() != nil {
		return bad()
	}
	policy := &DesktopNodeChainSOCKSPolicy{original: original, native: native, metadata: meta, inputs: inputs}
	policy.seal = policy.currentSeal()
	return policy, capture, nil
}

func (b *nodeChainSOCKSDesktopBinding) currentSeal() string {
	if b == nil || b.original == nil {
		return ""
	}
	raw, err := json.Marshal([]any{"routervpn-socks-desktop-binding-v1", b.original.seal, b.projection, b.metadata, b.nativeMetadata})
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (b *nodeChainSOCKSDesktopBinding) validate(source *NodeChainSOCKSSource) error {
	if b == nil || b.original == nil || b.original.desktop != nil || b.original.validate() != nil ||
		source == nil || source.desktop != b || b.seal == "" || b.currentSeal() != b.seal ||
		source.sourceJSON != b.original.sourceJSON || source.pair != b.original.pair || source.middle != b.original.middle ||
		b.metadata.Kind != "routervpn-desktop-node-chain-socks" || b.metadata.Schema != 1 ||
		b.metadata.OriginalSourceSHA256 != b.original.metadata.SourceSHA256 ||
		b.metadata.OriginalConfigSHA256 != b.original.metadata.ConfigSHA256 ||
		b.metadata.ConfigSHA256 != externalDigest([]byte(source.config)) ||
		b.projection.PhysicalSourceSHA256 != b.metadata.SourceSHA256 ||
		b.projection.SessionID != b.metadata.SessionID || b.projection.TargetOS != b.metadata.TargetOS ||
		b.projection.RestoredMTU != b.metadata.RestoredMTU {
		return desktopNodeChainSOCKSPolicyError
	}
	// The complete graph/MTU derivation was validated before this private
	// binding was sealed. Observation keeps that exact receipt; it does not
	// repeatedly recompile all prefixes inside an owned caller deadline.
	if !reflect.DeepEqual(source.metadata, b.nativeMetadata) {
		return desktopNodeChainSOCKSPolicyError
	}
	return nil
}

func (p *NodeChainSOCKSSource) runtimeProjection() nodeChainProjection {
	if p != nil && p.desktop != nil {
		return p.desktop.projection
	}
	return nodeChainProjection{}
}

func (p *NodeChainSOCKSSource) originalConfigSHA256() string {
	if p != nil && p.desktop != nil {
		return p.desktop.original.metadata.ConfigSHA256
	}
	if p == nil {
		return ""
	}
	return p.metadata.ConfigSHA256
}

func (p *DesktopNodeChainSOCKSPolicy) currentSeal() string {
	if p == nil || p.original == nil || p.native == nil {
		return ""
	}
	return desktopExternalObjectDigest([]any{"routervpn-desktop-node-chain-socks-plan-v1", p.original.seal, p.native.seal, p.metadata})
}

func (p *DesktopNodeChainSOCKSPolicy) validatedCapture() (DesktopPhysicalCapture, error) {
	if p == nil || p.original == nil || p.native == nil || p.seal == "" ||
		p.currentSeal() != p.seal || p.native.validate() != nil || p.native.desktop == nil ||
		p.native.desktop.original != p.original {
		return DesktopPhysicalCapture{}, desktopNodeChainSOCKSPolicyError
	}
	derived, capture, err := deriveDesktopNodeChainSOCKSPolicy(p.original, p.inputs)
	if err != nil || derived.seal != p.seal || derived.native.config != p.native.config {
		return DesktopPhysicalCapture{}, desktopNodeChainSOCKSPolicyError
	}
	return capture, nil
}

func (p *DesktopNodeChainSOCKSPolicy) Validate() error {
	_, err := p.validatedCapture()
	return err
}

func (p *DesktopNodeChainSOCKSPolicy) ReadValidated() (string, DesktopNodeChainSOCKSMetadata, DesktopPhysicalCapture, error) {
	capture, err := p.validatedCapture()
	if err != nil {
		return "", DesktopNodeChainSOCKSMetadata{}, DesktopPhysicalCapture{}, err
	}
	meta := p.metadata
	meta.Prefixes = append([]NodeChainProof(nil), meta.Prefixes...)
	meta.Roots = append([]DesktopNodeRootMetadata(nil), meta.Roots...)
	return p.native.config, meta, capture, nil
}

// NativeSource retains the typed constructor object for the actual local SOCKS
// registry and opaque proof/MTU runtime. It never returns a generic NodeChain.
func (p *DesktopNodeChainSOCKSPolicy) NativeSource() (*NodeChainSOCKSSource, error) {
	if p.Validate() != nil {
		return nil, desktopNodeChainSOCKSPolicyError
	}
	return p.native, nil
}

func (p *DesktopNodeChainSOCKSPolicy) Config() string {
	config, _, _, err := p.ReadValidated()
	if err != nil {
		return ""
	}
	return config
}

func (p *DesktopNodeChainSOCKSPolicy) OriginalSource() (*NodeChainSOCKSSource, error) {
	if p.Validate() != nil {
		return nil, desktopNodeChainSOCKSPolicyError
	}
	return p.original, nil
}

func (*DesktopNodeChainSOCKSPolicy) desktopPhysicalPolicy() {}

func (p *DesktopNodeChainSOCKSPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	config, meta, capture, err := p.ReadValidated()
	if err != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	return config, DesktopPhysicalMetadata{
		Kind: "node-chain-socks", SessionID: meta.SessionID, TargetOS: meta.TargetOS,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256,
		ProfileID: meta.ProfileID, NodeID: meta.NodeID, Mode: meta.Mode, StartLayer: meta.StartLayer,
		KillSwitchPolicy: meta.KillSwitchPolicy, IPv6Mode: meta.IPv6Mode, HomeLANAccess: meta.HomeLANAccess, RestoredMTU: meta.RestoredMTU,
	}, capture, nil
}

type desktopNodeChainSOCKSLaunch struct {
	Kind string `json:"kind"`
	Schema int `json:"schema"`
	OriginalSource string `json:"original_source"`
	Metadata DesktopNodeChainSOCKSMetadata `json:"metadata"`
}

func (p *DesktopNodeChainSOCKSPolicy) LaunchInput() (string, error) {
	if p.Validate() != nil {
		return "", desktopNodeChainSOCKSPolicyError
	}
	raw, err := json.Marshal(desktopNodeChainSOCKSLaunch{
		"routervpn-desktop-node-chain-socks", 1, p.original.sourceJSON, p.metadata,
	})
	if err != nil || len(raw) > NodeChainInputLimit {
		return "", desktopNodeChainSOCKSPolicyError
	}
	return string(raw), nil
}

func ParseDesktopNodeChainSOCKSLaunchInput(input string) (*DesktopNodeChainSOCKSPolicy, error) {
	var captured desktopNodeChainSOCKSLaunch
	if exactJSON([]byte(input), &captured, NodeChainInputLimit) != nil ||
		captured.Kind != "routervpn-desktop-node-chain-socks" || captured.Schema != 1 {
		return nil, desktopNodeChainSOCKSPolicyError
	}
	original, err := NewNodeChainSOCKSSource(captured.OriginalSource)
	if err != nil {
		return nil, err
	}
	meta := captured.Metadata
	policy, err := NewDesktopNodeChainSOCKSPolicy(original, meta.SessionID, meta.TargetOS, meta.RestoredMTU)
	if err != nil {
		return nil, err
	}
	canonical, err := policy.LaunchInput()
	if err != nil || canonical != input {
		return nil, desktopNodeChainSOCKSPolicyError
	}
	return policy, nil
}
