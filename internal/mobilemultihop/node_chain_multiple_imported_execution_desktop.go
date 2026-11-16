package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

// The original complete Local imported policy already owns its sealed physical
// projection. This distinct adjunct retains that exact constructor and both
// source pointers; it never invents a second Local provider or native owner.
type nodeChainMultipleImportedExecutionDesktop struct {
	self             *nodeChainMultipleImportedExecutionDesktop
	original         *DesktopNodeChainPolicy
	source, native   *NodeChain
	inputs           desktopNodePolicyInputs
	metadata         DesktopNodeChainMetadata
	physicalMetadata DesktopPhysicalMetadata
	capture          DesktopPhysicalCapture
	seal             string
	preparation      *NodeChainExecutionPreparation
	binding          *nodeChainMultipleImportedExecutionBinding
	physical         *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy
}

// Raw strings are freshly read and hashed on every observation. Their field
// names, byte lengths and digests remain in this desktop-only internal seal;
// the complete remaining typed fields still use canonical JSON. This avoids
// re-escaping large already-encoded source/config/launch strings, not validation.
func (p *NodeChainExecutionPreparation) captureMultipleImportedDesktopSeal() string {
	if p == nil || p.mobile != nil {
		return ""
	}
	type rawInput struct {
		Length int    `json:"length"`
		SHA256 string `json:"sha256"`
	}
	capture := func(value string) rawInput {
		return rawInput{len(value), externalDigest([]byte(value))}
	}
	source := p.source
	inputs := struct {
		SourceJSON, Config, LocalSource, MultipleImportedLocalLaunch, DesktopLast rawInput
	}{capture(p.sourceJSON), capture(p.config), capture(source.LocalSource), capture(source.MultipleImportedLocalLaunch), capture(source.DesktopLast)}
	source.LocalSource, source.MultipleImportedLocalLaunch, source.DesktopLast = "", "", ""
	raw, err := json.Marshal([]any{"routervpn-desktop-multiple-imported-execution-preparation-capture-v1", inputs,
		p.sourceSHA, p.configSHA, source, p.discovery, p.dns, p.physical})
	if err != nil {
		return ""
	}
	seal := externalDigest(raw)
	clear(raw)
	return seal
}

func NewDesktopNodeChainMultipleImportedExecutionPreparation(original *DesktopNodeChainPolicy, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || execution != "server" && execution != "auto" {
		return nil, nodeChainExecutionError
	}
	_, metadata, _, err := original.ReadValidated()
	if err != nil || original.original.importedNodes == nil || original.original.projection.Kind != "" || original.original.projection.TargetOS != "" || len(metadata.Prefixes) < 3 || len(metadata.Prefixes) > NodeChainMaximumNodes || original.original.nodes[len(original.original.nodes)-1] == nil || original.original.nodes[len(original.original.nodes)-1].mode != "shadowsocks" {
		return nil, nodeChainExecutionError
	}
	_, physicalMetadata, capture, err := original.PhysicalReadValidated()
	if err != nil {
		return nil, err
	}
	d := &nodeChainMultipleImportedExecutionDesktop{original: original, source: original.original, native: original.chain, inputs: original.inputs, metadata: metadata, physicalMetadata: physicalMetadata, capture: capture}
	d.self = d
	d.seal = d.captureSeal()
	p, err := newNodeChainExecutionPreparationOwnedFamilies(d.source.sourceJSON, execution, nil, nil, d.source, nil, nil, nil, nil, nil, d.source, nil, d)
	if err != nil || d.physical.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

// Child reconstruction retains the original sealed Local launch and repeats
// only the original DesktopNodeChainPolicy derivation. Metadata is not authority.
func ParseDesktopNodeChainMultipleImportedExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var source NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 6 || source.DesktopMultipleImported == nil || source.Desktop != nil || source.DesktopCONNECT != nil || source.DesktopSOCKS != nil || source.DesktopOpenVPN != nil || source.OpenVPNLocalLaunch != "" {
		return nil, nodeChainExecutionError
	}
	local, err := ParseNodeChainLaunchInput(source.MultipleImportedLocalLaunch)
	if err != nil || local.sourceJSON != source.LocalSource || local.projection.Kind != "" {
		return nil, nodeChainExecutionError
	}
	meta := source.DesktopMultipleImported
	original, err := NewDesktopNodeChainPolicy(local, meta.SessionID, meta.TargetOS, meta.RestoredMTU)
	if err != nil || !reflect.DeepEqual(original.metadata, *meta) {
		return nil, nodeChainExecutionError
	}
	var p *NodeChainExecutionPreparation
	if source.DesktopLast != "" {
		p, err = NewDesktopNodeChainMultipleImportedExecutionLastPreparation(original, source.Execution, source.DesktopLast)
	} else {
		p, err = NewDesktopNodeChainMultipleImportedExecutionPreparation(original, source.Execution)
	}
	if err != nil || p.Source() != input {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

func (d *nodeChainMultipleImportedExecutionDesktop) captureSeal() string {
	if d == nil || d.original == nil || d.source == nil || d.native == nil {
		return ""
	}
	return desktopExternalObjectDigest([]any{"routervpn-desktop-multiple-imported-execution-capture-v1", d.original.seal, d.source.seal, d.native.seal, []any{d.inputs.sessionID, d.inputs.targetOS, d.inputs.restoredMTU}, d.metadata, d.physicalMetadata, d.capture})
}
func (d *nodeChainMultipleImportedExecutionDesktop) originalCurrent() error {
	if d == nil || d.self != d || d.original == nil || d.source == nil || d.native == nil || d.original.original != d.source || d.original.chain != d.native || d.original.inputs != d.inputs || d.inputs.sessionID != d.metadata.SessionID || d.inputs.targetOS != d.metadata.TargetOS || d.inputs.restoredMTU != d.metadata.RestoredMTU || d.source.projection.Kind != "" || d.native.projection.Kind != nodeChainDesktopPhysicalKind || d.source.importedNodes == nil || d.native.importedNodes == nil || d.original.Validate() != nil || !reflect.DeepEqual(d.metadata, d.original.metadata) || d.seal == "" || d.captureSeal() != d.seal {
		return nodeChainExecutionError
	}
	return nil
}
func (d *nodeChainMultipleImportedExecutionDesktop) bind(p *NodeChainExecutionPreparation, b *nodeChainMultipleImportedExecutionBinding) error {
	if d.originalCurrent() != nil || p == nil || b == nil || d.preparation != nil || d.binding != nil || d.physical != nil || p.desktop != nil || p.mobile != nil || p.source.Desktop != nil || p.source.DesktopCONNECT != nil || p.source.DesktopSOCKS != nil || p.source.DesktopOpenVPN != nil || p.source.DesktopMultipleImported != nil || p.connect != nil || p.socks != nil || p.openvpn != nil || b.desktop != d || b.source != d.source || b.local != d.source {
		return nodeChainExecutionError
	}
	metadata := d.metadata
	metadata.Prefixes = append([]NodeChainProof(nil), metadata.Prefixes...)
	metadata.Roots = append([]DesktopNodeRootMetadata(nil), metadata.Roots...)
	p.source.DesktopMultipleImported = &metadata
	d.preparation, d.binding = p, b
	d.physical = &DesktopNodeChainMultipleImportedExecutionPhysicalPolicy{owner: d, preparation: p, original: d.original}
	d.physical.self = d.physical
	return nil
}
func (d *nodeChainMultipleImportedExecutionDesktop) validate(p *NodeChainExecutionPreparation, b *nodeChainMultipleImportedExecutionBinding) error {
	if d.originalCurrent() != nil || p == nil || b == nil || d.preparation != p || d.binding != b || p.multiple != b || b.desktop != d || b.source != d.source || p.local != d.source || p.desktop != nil || p.mobile != nil || p.source.Desktop != nil || p.source.DesktopCONNECT != nil || p.source.DesktopSOCKS != nil || p.source.DesktopOpenVPN != nil || p.connect != nil || p.socks != nil || p.openvpn != nil || p.source.DesktopMultipleImported == nil || !reflect.DeepEqual(*p.source.DesktopMultipleImported, d.metadata) || d.physical == nil || d.physical.self != d.physical || d.physical.owner != d || d.physical.original != d.original || d.physical.preparation != p {
		return nodeChainExecutionError
	}
	return nil
}

// The concrete type grants static physical construction only. A native desktop
// factory must separately bind its exact service/process/network and retirement.
type DesktopNodeChainMultipleImportedExecutionPhysicalPolicy struct {
	self        *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy
	owner       *nodeChainMultipleImportedExecutionDesktop
	preparation *NodeChainExecutionPreparation
	original    *DesktopNodeChainPolicy
}

func (*DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) desktopPhysicalPolicy() {}
func (p *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) Validate() error {
	if p == nil || p.self != p || p.owner == nil || p.owner.physical != p || p.preparation == nil || p.original == nil || p.owner.original != p.original || p.owner.preparation != p.preparation || p.preparation.validateCapture() != nil {
		return nodeChainExecutionError
	}
	return nil
}
func (p *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.preparation.Config()
}
func (p *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) OriginalDesktopMultipleImportedPolicy() (*DesktopNodeChainPolicy, error) {
	if p.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p.original, nil
}
func (p *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) ReadOriginalValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, DesktopNodeChainMetadata, error) {
	original, _, metadata, err := p.ReadOriginalSourceValidated(preparation)
	return original, metadata, err
}

// Each result is an immediate observation of the same original preparation and
// physical owner. It stores no validation result or live native authority.
func (p *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) ReadOriginalSourceValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, *NodeChain, DesktopNodeChainMetadata, error) {
	if p == nil || preparation == nil || p.preparation != preparation || p.Validate() != nil {
		return nil, nil, DesktopNodeChainMetadata{}, nodeChainExecutionError
	}
	metadata := p.owner.metadata
	metadata.Prefixes = append([]NodeChainProof(nil), metadata.Prefixes...)
	metadata.Roots = append([]DesktopNodeRootMetadata(nil), metadata.Roots...)
	return p.original, p.owner.source, metadata, nil
}

func (p *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) ReadExecutionValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, *NodeChain, DesktopNodeChainMetadata, string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	original, source, metadata, err := p.ReadOriginalSourceValidated(preparation)
	if err != nil {
		return nil, nil, DesktopNodeChainMetadata{}, "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	config, physical, capture, err := p.physicalReadValidated()
	if err != nil {
		return nil, nil, DesktopNodeChainMetadata{}, "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	return original, source, metadata, config, physical, capture, nil
}
func (p *NodeChainExecutionPreparation) RequiresDesktopMultipleImportedExecutionObserver() bool {
	return p != nil && (p.source.DesktopMultipleImported != nil || p.multiple != nil && p.multiple.desktop != nil)
}
func (p *NodeChainExecutionPreparation) MultipleImportedDesktopPhysicalPolicy() (*DesktopNodeChainMultipleImportedExecutionPhysicalPolicy, error) {
	if p == nil || p.multiple == nil || p.multiple.desktop == nil || p.validateCapture() != nil || p.multiple.desktop.physical.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p.multiple.desktop.physical, nil
}
func (p *NodeChainExecutionProjection) MultipleImportedDesktopPhysicalPolicy() (*DesktopNodeChainMultipleImportedExecutionPhysicalPolicy, error) {
	if p == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.preparation.MultipleImportedDesktopPhysicalPolicy()
}
func (p *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	if p.Validate() != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, nodeChainExecutionError
	}
	return p.physicalReadValidated()
}
func (p *DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) physicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	bad := func() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, nodeChainExecutionError
	}
	raw, err := json.Marshal(p.owner.capture)
	var capture DesktopPhysicalCapture
	if err != nil || json.Unmarshal(raw, &capture) != nil {
		return bad()
	}
	var graph map[string]any
	if exactJSON([]byte(p.preparation.config), &graph, 4<<20) != nil {
		return bad()
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return bad()
	}
	servers, ok := dns["servers"].([]any)
	if !ok {
		return bad()
	}
	update := func(value *ExternalDesktopDNS) error {
		if value.Detour != p.preparation.local.FinalTag() {
			return nil
		}
		if value.Physical {
			return nodeChainExecutionError
		}
		found := false
		for _, raw := range servers {
			row, ok := raw.(map[string]any)
			if !ok {
				return nodeChainExecutionError
			}
			if row["tag"] != value.Tag {
				continue
			}
			if found || row["detour"] != SelectorTag {
				return nodeChainExecutionError
			}
			value.Detour, value.ConfigSHA256, found = SelectorTag, desktopExternalObjectDigest(row), true
		}
		if !found {
			return nodeChainExecutionError
		}
		return nil
	}
	if update(&capture.SelectedDNS) != nil || capture.SelectedDNS.Detour != SelectorTag || capture.SelectedDNS.Physical || capture.SelectedDNS.ConfigSHA256 != p.preparation.dns.DNS.ResolverSHA256 {
		return bad()
	}
	for i := range capture.BootstrapDNS {
		if update(&capture.BootstrapDNS[i]) != nil {
			return bad()
		}
	}
	meta := p.owner.physicalMetadata
	meta.Kind = "node-chain-multiple-imported-execution"
	meta.ConfigSHA256 = p.preparation.ConfigSHA256()
	return p.preparation.Config(), meta, capture, nil
}
func (p *NodeChainExecutionPreparation) bindMultipleImportedDesktopProjected(policy *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if p.multiple == nil || p.multiple.desktop == nil || p.multiple.desktop.validate(p, p.multiple) != nil {
		return nil, nodeChainExecutionError
	}
	original, err := NewNodeChainMultipleImportedExecutionPreparation(p.multiple.source, p.Execution())
	if err != nil {
		return nil, err
	}
	exact, err := NewNodeChainMultipleImportedExecutionPolicy(original, policy.Source())
	if err != nil {
		return nil, err
	}
	addition, err := original.BindExecution(exact)
	if err != nil {
		return nil, err
	}
	return p.bindProjectedExecutionAddition(policy, addition)
}
