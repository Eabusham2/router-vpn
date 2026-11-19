package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

// This adjunct is constructor-owned. Serialized derivation inputs cannot lend
// another policy, native source, lower owner, or preparation this authority.
type nodeChainCONNECTExecutionDesktop struct {
	self             *nodeChainCONNECTExecutionDesktop
	original         *DesktopNodeChainCONNECTPolicy
	source, native   *NodeChainCONNECTSource
	inputs           desktopNodePolicyInputs
	metadata         DesktopNodeChainCONNECTMetadata
	physicalMetadata DesktopPhysicalMetadata
	capture          DesktopPhysicalCapture
	seal             string
	preparation      *NodeChainExecutionPreparation
	binding          *nodeChainCONNECTExecutionBinding
	physical         *DesktopNodeChainCONNECTExecutionPhysicalPolicy
}

// NewDesktopNodeChainCONNECTExecutionPreparation captures one concrete Local
// desktop CONNECT policy. It performs no native/platform or public admission.
// Generic execution constructors and their schema1/2 parsers remain closed.
func NewDesktopNodeChainCONNECTExecutionPreparation(original *DesktopNodeChainCONNECTPolicy, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || execution != "server" && execution != "auto" {
		return nil, nodeChainExecutionError
	}
	_, metadata, _, err := original.ReadValidated()
	if err != nil || (len(metadata.Prefixes) < 3 || len(metadata.Prefixes) > NodeChainMaximumNodes) {
		return nil, nodeChainExecutionError
	}
	native, err := original.NativeSource()
	if err != nil || native == nil || native.desktop == nil || native.desktop.original != original.original {
		return nil, nodeChainExecutionError
	}
	_, physicalMetadata, capture, err := original.PhysicalReadValidated()
	if err != nil {
		return nil, err
	}
	runtime, err := NewNodeChainCONNECTRuntime(native)
	if err != nil {
		return nil, err
	}
	d := &nodeChainCONNECTExecutionDesktop{original: original, source: original.original, native: native, inputs: original.inputs, metadata: metadata, physicalMetadata: physicalMetadata, capture: capture}
	d.self = d
	d.seal = d.captureSeal()
	p, err := newNodeChainExecutionPreparationCaptured(native.sourceJSON, execution, nil, nil, runtime.chain, native, d)
	if err != nil || d.physical.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

// Parsing reconstructs the exact typed desktop derivation once for this child.
// It never treats caller metadata or a mobile preparation as physical authority.
func ParseDesktopNodeChainCONNECTExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var source NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 4 || source.DesktopCONNECT == nil || source.Desktop != nil {
		return nil, nodeChainExecutionError
	}
	original, err := NewNodeChainCONNECTSource(source.LocalSource)
	if err != nil {
		return nil, err
	}
	meta := source.DesktopCONNECT
	policy, err := NewDesktopNodeChainCONNECTPolicyWithDevicePreference(original, meta.SessionID, meta.TargetOS, meta.RestoredMTU, meta.DeviceRevision, meta.DeviceFixedMTU)
	if err != nil || !reflect.DeepEqual(policy.metadata, *meta) {
		return nil, nodeChainExecutionError
	}
	var p *NodeChainExecutionPreparation
	if source.DesktopLast != "" {
		p, err = NewDesktopNodeChainCONNECTExecutionLastPreparation(policy, source.Execution, source.DesktopLast)
	} else {
		p, err = NewDesktopNodeChainCONNECTExecutionPreparation(policy, source.Execution)
	}
	if err != nil || p.Source() != input {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

func (d *nodeChainCONNECTExecutionDesktop) captureSeal() string {
	if d == nil || d.original == nil || d.source == nil || d.native == nil {
		return ""
	}
	return desktopExternalObjectDigest([]any{"routervpn-desktop-connect-execution-capture-v1", d.original.seal, d.source.seal, d.native.seal, []any{d.inputs.sessionID, d.inputs.targetOS, d.inputs.restoredMTU}, d.metadata, d.physicalMetadata, d.capture})
}
func (d *nodeChainCONNECTExecutionDesktop) originalCurrent() error {
	if d == nil || d.self != d || d.original == nil || d.source == nil || d.native == nil || d.original.original != d.source || d.original.native != d.native || d.original.inputs != d.inputs || d.inputs.sessionID != d.metadata.SessionID || d.inputs.targetOS != d.metadata.TargetOS || d.inputs.restoredMTU != d.metadata.RestoredMTU || d.inputs.deviceFixed != d.metadata.DeviceFixedMTU || d.inputs.deviceRevision != d.metadata.DeviceRevision || d.original.seal == "" || d.original.currentSeal() != d.original.seal || d.source.desktop != nil || d.native.desktop == nil || d.native.desktop.original != d.source || d.source.validate() != nil || d.native.validate() != nil || !reflect.DeepEqual(d.metadata, d.original.metadata) || d.seal == "" || d.captureSeal() != d.seal {
		return nodeChainExecutionError
	}
	return nil
}
func (d *nodeChainCONNECTExecutionDesktop) bind(p *NodeChainExecutionPreparation, b *nodeChainCONNECTExecutionBinding) error {
	if d.originalCurrent() != nil || p == nil || b == nil || d.preparation != nil || d.binding != nil || d.physical != nil || p.desktop != nil || p.mobile != nil || p.source.Desktop != nil || p.source.DesktopCONNECT != nil || b.desktop != d || b.source != d.native {
		return nodeChainExecutionError
	}
	raw, err := json.Marshal(d.metadata)
	var metadata DesktopNodeChainCONNECTMetadata
	if err != nil || json.Unmarshal(raw, &metadata) != nil {
		return nodeChainExecutionError
	}
	p.source.DesktopCONNECT = &metadata
	d.preparation, d.binding = p, b
	d.physical = &DesktopNodeChainCONNECTExecutionPhysicalPolicy{owner: d, preparation: p, original: d.original}
	d.physical.self = d.physical
	return nil
}
func (d *nodeChainCONNECTExecutionDesktop) validate(p *NodeChainExecutionPreparation, b *nodeChainCONNECTExecutionBinding) error {
	if d.originalCurrent() != nil || p == nil || b == nil || d.preparation != p || d.binding != b || p.connect != b || b.desktop != d || b.source != d.native || p.local != b.local || p.local.connectSource != d.native || p.desktop != nil || p.mobile != nil || p.source.Desktop != nil || p.source.DesktopCONNECT == nil || !reflect.DeepEqual(*p.source.DesktopCONNECT, d.metadata) || d.physical == nil || d.physical.self != d.physical || d.physical.owner != d || d.physical.original != d.original || d.physical.preparation != p {
		return nodeChainExecutionError
	}
	return nil
}

// A distinct concrete wrapper keeps typed CONNECT physical authority separate
// from generic paired execution and Local CONNECT. Native factories still need
// their own exact-family adoption; this constructor alone opens no sockets.
type DesktopNodeChainCONNECTExecutionPhysicalPolicy struct {
	self        *DesktopNodeChainCONNECTExecutionPhysicalPolicy
	owner       *nodeChainCONNECTExecutionDesktop
	preparation *NodeChainExecutionPreparation
	original    *DesktopNodeChainCONNECTPolicy
}

func (*DesktopNodeChainCONNECTExecutionPhysicalPolicy) desktopPhysicalPolicy() {}
func (p *DesktopNodeChainCONNECTExecutionPhysicalPolicy) Validate() error {
	if p == nil || p.self != p || p.owner == nil || p.owner.physical != p || p.preparation == nil || p.original == nil || p.owner.original != p.original || p.owner.preparation != p.preparation || p.preparation.validateCapture() != nil {
		return nodeChainExecutionError
	}
	return nil
}
func (p *DesktopNodeChainCONNECTExecutionPhysicalPolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.preparation.Config()
}
func (p *DesktopNodeChainCONNECTExecutionPhysicalPolicy) OriginalDesktopCONNECTPolicy() (*DesktopNodeChainCONNECTPolicy, error) {
	if p.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p.original, nil
}

// ReadOriginalValidated is a fresh read of the distinct CONNECT physical
// owner, exact preparation and original policy, never a cached live proof.
func (p *DesktopNodeChainCONNECTExecutionPhysicalPolicy) ReadOriginalValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainCONNECTPolicy, DesktopNodeChainMetadata, error) {
	if p == nil || preparation == nil || p.preparation != preparation || p.Validate() != nil {
		return nil, DesktopNodeChainMetadata{}, nodeChainExecutionError
	}
	_, metadata, _, err := p.original.ReadValidated()
	if err != nil {
		return nil, DesktopNodeChainMetadata{}, err
	}
	return p.original, metadata.DesktopNodeChainMetadata, nil
}
func (p *NodeChainExecutionPreparation) CONNECTDesktopPhysicalPolicy() (*DesktopNodeChainCONNECTExecutionPhysicalPolicy, error) {
	if p == nil || p.connect == nil || p.connect.desktop == nil || p.validateCapture() != nil || p.connect.desktop.physical.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p.connect.desktop.physical, nil
}
func (p *NodeChainExecutionProjection) CONNECTDesktopPhysicalPolicy() (*DesktopNodeChainCONNECTExecutionPhysicalPolicy, error) {
	if p == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.preparation.CONNECTDesktopPhysicalPolicy()
}
func (p *DesktopNodeChainCONNECTExecutionPhysicalPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	bad := func() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, nodeChainExecutionError
	}
	if p.Validate() != nil {
		return bad()
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
	meta.Kind = "node-chain-connect-execution"
	meta.ConfigSHA256 = p.preparation.ConfigSHA256()
	return p.preparation.Config(), meta, capture, nil
}

// Remove only the exact original desktop lower wrappers for static tuple
// analysis. The actual execution graph retains them unchanged. This operation
// grants neither a caller-supplied direct route nor generic inline UoT support.
func (d *nodeChainCONNECTExecutionDesktop) physicalEgress(config, entryTag string) ([]PhysicalEgress, error) {
	if d.originalCurrent() != nil || d.preparation == nil || d.binding == nil || d.validate(d.preparation, d.binding) != nil || entryTag != d.native.metadata.Proofs[0].Tag {
		return nil, nodeChainExecutionError
	}
	var graph, native, original map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil || exactJSON([]byte(d.native.config), &native, 4<<20) != nil || exactJSON([]byte(d.source.config), &original, 4<<20) != nil {
		return nil, nodeChainExecutionError
	}
	if !reflect.DeepEqual(graph["services"], native["services"]) {
		return nil, nodeChainExecutionError
	}
	if value, ok := original["services"]; ok {
		graph["services"] = value
	} else {
		delete(graph, "services")
	}
	rowsByTag := func(value any) (map[string]map[string]any, error) {
		rows, ok := value.([]any)
		if !ok {
			return nil, nodeChainExecutionError
		}
		result := map[string]map[string]any{}
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return nil, nodeChainExecutionError
			}
			tag, ok := row["tag"].(string)
			if !ok || tag == "" || result[tag] != nil {
				return nil, nodeChainExecutionError
			}
			result[tag] = row
		}
		return result, nil
	}
	for _, family := range []string{"outbounds", "endpoints"} {
		rows, exists := graph[family]
		if !exists {
			if _, ok := native[family]; ok {
				return nil, nodeChainExecutionError
			}
			continue
		}
		actual, err := rowsByTag(rows)
		if err != nil {
			return nil, err
		}
		captured, err := rowsByTag(native[family])
		if err != nil {
			return nil, err
		}
		before, err := rowsByTag(original[family])
		if err != nil {
			return nil, err
		}
		if family == "outbounds" {
			if !reflect.DeepEqual(actual[DesktopNodePhysicalTag], captured[DesktopNodePhysicalTag]) || captured[DesktopNodePhysicalTag] == nil {
				return nil, nodeChainExecutionError
			}
		}
		roots := map[string]bool{}
		for _, root := range d.metadata.Roots {
			if root.Family != family {
				continue
			}
			if !reflect.DeepEqual(actual[root.Tag], captured[root.Tag]) || before[root.Tag] == nil || desktopExternalObjectDigest(before[root.Tag]) != root.OriginalSHA256 || desktopExternalObjectDigest(captured[root.Tag]) != root.DerivedSHA256 {
				return nil, nodeChainExecutionError
			}
			roots[root.Tag] = true
		}
		next := []any{}
		for _, raw := range rows.([]any) {
			row := raw.(map[string]any)
			tag := row["tag"].(string)
			if tag == DesktopNodePhysicalTag {
				continue
			}
			if roots[tag] {
				next = append(next, before[tag])
			} else {
				next = append(next, row)
			}
		}
		graph[family] = next
	}
	gd, gok := graph["dns"].(map[string]any)
	nd, nok := native["dns"].(map[string]any)
	od, ook := original["dns"].(map[string]any)
	if !gok || !nok || !ook {
		return nil, nodeChainExecutionError
	}
	gs, err := rowsByTag(gd["servers"])
	if err != nil {
		return nil, err
	}
	ns, err := rowsByTag(nd["servers"])
	if err != nil {
		return nil, err
	}
	os, err := rowsByTag(od["servers"])
	if err != nil {
		return nil, err
	}
	for _, dns := range d.capture.BootstrapDNS {
		if !dns.Physical {
			continue
		}
		if !reflect.DeepEqual(gs[dns.Tag], ns[dns.Tag]) || os[dns.Tag] == nil {
			return nil, nodeChainExecutionError
		}
		for i, raw := range gd["servers"].([]any) {
			if raw.(map[string]any)["tag"] == dns.Tag {
				gd["servers"].([]any)[i] = os[dns.Tag]
			}
		}
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	proof, err := desktopNodeChainCONNECTPhysicalProof(d.source, string(encoded))
	if err != nil {
		return nil, err
	}
	physical, err := compiledPhysicalEgressWithCapturedTransports(string(encoded), []string{"tcp", "udp"}, nil, entryTag, false, proof)
	if err != nil || !nodeChainSamePhysical(physical, d.native.metadata.Physical) {
		return nil, nodeChainExecutionError
	}
	return physical, nil
}
