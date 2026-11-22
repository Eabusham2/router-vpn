package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

// NewDesktopNodeChainExecutionPreparation retains the exact original sealed
// desktop projection. Its physical source, native service, lower resolvers,
// TUN and MTU are not reconstructed from a generic mobile graph or relabeled.
// The caller still owns native preparation, proof and joined retirement.
func NewDesktopNodeChainExecutionPreparation(original *DesktopNodeChainPolicy, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || original.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return newNodeChainExecutionPreparation(original.original.sourceJSON, execution, original)
}

// ParseNodeChainExecutionPreparation repeats only closed constructors. The
// optional desktop receipt carries derivation inputs/digests, never another
// caller-supplied graph or a second copy of the private ordered source.
func ParseNodeChainExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var source NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 1 {
		return nil, nodeChainExecutionError
	}
	var desktop *DesktopNodeChainPolicy
	if source.Desktop != nil {
		local, err := NewNodeChain(source.LocalSource)
		if err != nil {
			return nil, err
		}
		meta := source.Desktop
		desktop, err = NewDesktopNodeChainPolicyWithDevicePreference(local, meta.SessionID, meta.TargetOS, meta.RestoredMTU, meta.DeviceRevision, meta.DeviceFixedMTU)
		if err != nil || !reflect.DeepEqual(desktop.Metadata(), *meta) {
			return nil, nodeChainExecutionError
		}
	}
	var preparation *NodeChainExecutionPreparation
	var err error
	if source.DesktopLast != "" {
		preparation, err = NewDesktopNodeChainExecutionLastPreparation(desktop, source.Execution, source.DesktopLast)
	} else {
		preparation, err = newNodeChainExecutionPreparation(source.LocalSource, source.Execution, desktop)
	}
	if err != nil || preparation.Source() != input {
		return nil, nodeChainExecutionError
	}
	return preparation, nil
}

// A desktop child must retain the typed family even if a valid generic source
// is substituted. Its caller still compares the authenticated source digest.
func ParseDesktopNodeChainExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	preparation, err := ParseNodeChainExecutionPreparation(input)
	if err != nil || preparation.desktop == nil {
		return nil, nodeChainExecutionError
	}
	return preparation, nil
}

// The full original constructor runs before this preparation is sealed and
// again on typed parsing. Repeated native observations compare that complete
// original state instead of recompiling it. Both source and derived chains,
// metadata and every constructor input must still be the captured originals.
func (p *NodeChainExecutionPreparation) validateDesktopCapture() error {
	d := p.desktop
	if d == nil || p.source.Desktop == nil || d.original == nil || d.chain == nil ||
		d.seal == "" || !p.packetDesktop.policyCurrent(p, d) && (d.currentSeal() != d.seal || d.original.validateCapture() != nil || d.chain.validateCapture() != nil) ||
		!reflect.DeepEqual(*p.source.Desktop, d.metadata) || d.metadata.ConfigSHA256 != d.chain.ConfigSHA256() ||
		d.inputs.sessionID != d.metadata.SessionID || d.inputs.targetOS != d.metadata.TargetOS || d.inputs.restoredMTU != d.metadata.RestoredMTU || d.inputs.deviceFixed != d.metadata.DeviceFixedMTU || d.inputs.deviceRevision != d.metadata.DeviceRevision ||
		d.original.sourceJSON != p.source.LocalSource || d.chain.sourceJSON != p.source.LocalSource || d.original.Config() != p.local.Config() {
		return nodeChainExecutionError
	}
	return nil
}

// DesktopNodeChainExecutionPhysicalPolicy is the one preparation-time native
// authority. It remains the same pointer after Server outbounds are appended.
// Config is the actual construction graph; the execution projection separately
// identifies the later graph and its proved in-place native transition.
// Generic preparation does not implement DesktopPhysicalPolicy.
type DesktopNodeChainExecutionPhysicalPolicy struct {
	preparation *NodeChainExecutionPreparation
	original    *DesktopNodeChainPolicy
	metadata    DesktopPhysicalMetadata
	capture     DesktopPhysicalCapture
	seal        string
}

func newDesktopNodeChainExecutionPhysicalPolicy(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainExecutionPhysicalPolicy, error) {
	_, metadata, capture, err := preparation.desktop.PhysicalReadValidated()
	if err != nil {
		return nil, err
	}
	p := &DesktopNodeChainExecutionPhysicalPolicy{preparation: preparation, original: preparation.desktop, metadata: metadata, capture: capture}
	p.seal = p.captureSeal()
	return p, nil
}

func (p *DesktopNodeChainExecutionPhysicalPolicy) captureSeal() string {
	if p == nil || p.preparation == nil || p.original == nil {
		return ""
	}
	return desktopExternalObjectDigest([]any{"routervpn-desktop-node-chain-execution-physical-v1", p.preparation.seal, p.original.seal, p.metadata, p.capture})
}

func (p *DesktopNodeChainExecutionPhysicalPolicy) Validate() error {
	if p.validateOwner() != nil || p.preparation.validateCapture() != nil {
		return nodeChainExecutionError
	}
	return nil
}

// The preparation is checked by Validate, or by a projection in the same
// synchronous observation. This verifies the remaining exact physical binding.
func (p *DesktopNodeChainExecutionPhysicalPolicy) validateOwner() error {
	if p == nil || p.preparation == nil || p.original == nil || p.seal == "" || p.captureSeal() != p.seal ||
		p.preparation.desktopPhysical != p || p.preparation.desktop != p.original {
		return nodeChainExecutionError
	}
	return nil
}

func (*DesktopNodeChainExecutionPhysicalPolicy) desktopPhysicalPolicy() {}

func (p *DesktopNodeChainExecutionPhysicalPolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.preparation.Config()
}

func (p *DesktopNodeChainExecutionPhysicalPolicy) OriginalDesktopPolicy() (*DesktopNodeChainPolicy, error) {
	if p.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p.original, nil
}

// ReadOriginalValidated checks this physical owner and its exact preparation
// once, then reads the original immutable policy. The returned metadata is a
// fresh value; callers must still perform their live process/network proofs.
func (p *DesktopNodeChainExecutionPhysicalPolicy) ReadOriginalValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, DesktopNodeChainMetadata, error) {
	if p == nil || preparation == nil || p.preparation != preparation || p.Validate() != nil {
		return nil, DesktopNodeChainMetadata{}, nodeChainExecutionError
	}
	_, metadata, _, err := p.original.ReadValidated()
	if err != nil {
		return nil, DesktopNodeChainMetadata{}, err
	}
	return p.original, metadata, nil
}

// ReadOriginalSourceValidated returns the exact source pointer from the same
// validated observation. It grants no live readiness or lifetime authority.
func (p *DesktopNodeChainExecutionPhysicalPolicy) ReadOriginalSourceValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, *NodeChain, DesktopNodeChainMetadata, error) {
	original, metadata, err := p.ReadOriginalValidated(preparation)
	if err != nil {
		return nil, nil, DesktopNodeChainMetadata{}, err
	}
	return original, original.original, metadata, nil
}

// ReadExecutionValidated binds the original source and copied physical view in
// one synchronous observation. No validation result survives this call.
func (p *DesktopNodeChainExecutionPhysicalPolicy) ReadExecutionValidated(preparation *NodeChainExecutionPreparation) (*DesktopNodeChainPolicy, *NodeChain, DesktopNodeChainMetadata, string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
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

func (p *NodeChainExecutionPreparation) DesktopPhysicalPolicy() (*DesktopNodeChainExecutionPhysicalPolicy, error) {
	if p == nil || p.desktopPhysical == nil || p.desktopPhysical.preparation != p || p.desktopPhysical.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p.desktopPhysical, nil
}

func (p *NodeChainExecutionProjection) DesktopPhysicalPolicy() (*DesktopNodeChainExecutionPhysicalPolicy, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	physical := p.preparation.desktopPhysical
	if physical == nil || physical.preparation != p.preparation || physical.validateOwner() != nil {
		return nil, nodeChainExecutionError
	}
	return physical, nil
}

func (p *DesktopNodeChainExecutionPhysicalPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	if p.Validate() != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, nodeChainExecutionError
	}
	return p.physicalReadValidated()
}

// Caller has validated this exact owner during the same synchronous read.
func (p *DesktopNodeChainExecutionPhysicalPolicy) physicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	bad := func() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, nodeChainExecutionError
	}
	// Deep-copy pointer-bearing query fields as well as root/network slices.
	rawCapture, err := json.Marshal(p.capture)
	var capture DesktopPhysicalCapture
	if err != nil || json.Unmarshal(rawCapture, &capture) != nil {
		return bad()
	}
	metadata := p.metadata
	// Only the encrypted final selected-DNS/bootstrap detour changed from the
	// single Local final to the same retained selector. Original lower resolver
	// intent and every physical root remain untouched.
	var graph map[string]any
	if exactJSON([]byte(p.preparation.config), &graph, 4<<20) != nil {
		return bad()
	}
	servers, ok := graph["dns"].(map[string]any)["servers"].([]any)
	if !ok {
		return bad()
	}
	update := func(dns *ExternalDesktopDNS) error {
		if dns.Detour != p.preparation.local.FinalTag() {
			return nil
		}
		if dns.Physical {
			return nodeChainExecutionError
		}
		found := false
		for _, value := range servers {
			row, ok := value.(map[string]any)
			if !ok {
				return nodeChainExecutionError
			}
			if row["tag"] != dns.Tag {
				continue
			}
			if found || row["detour"] != SelectorTag {
				return nodeChainExecutionError
			}
			dns.Detour, dns.ConfigSHA256, found = SelectorTag, desktopExternalObjectDigest(row), true
		}
		if !found {
			return nodeChainExecutionError
		}
		return nil
	}
	if update(&capture.SelectedDNS) != nil || capture.SelectedDNS.Detour != SelectorTag || capture.SelectedDNS.Physical ||
		capture.SelectedDNS.ConfigSHA256 != p.preparation.dns.DNS.ResolverSHA256 {
		return bad()
	}
	for i := range capture.BootstrapDNS {
		if update(&capture.BootstrapDNS[i]) != nil {
			return bad()
		}
	}
	metadata.Kind = "node-chain-execution"
	metadata.ConfigSHA256 = p.preparation.ConfigSHA256()
	return p.preparation.Config(), metadata, capture, nil
}

type desktopNodeChainExecutionReadyCapture struct {
	metadata DesktopPhysicalMetadata
	physical DesktopPhysicalCapture
	plan     NodeChainMTUPlan
	proofs   []NodeChainProof
	dns      NodeChainExecutionDNSCapture
}

// A heartbeat reads one freshly validated immutable projection. Calling each
// public getter in turn would revalidate its complete preparation and Server
// graph repeatedly. This private result lives only within the current record
// validation; it cannot authorize a later observation or a native owner.
func (p *NodeChainExecutionProjection) readDesktopReadyCapture(execution string) (desktopNodeChainExecutionReadyCapture, error) {
	bad := func() (desktopNodeChainExecutionReadyCapture, error) {
		return desktopNodeChainExecutionReadyCapture{}, nodeChainExecutionError
	}
	if p == nil || p.validateCapture() != nil || p.preparation.desktop == nil {
		return bad()
	}
	physical := p.preparation.desktopPhysical
	if physical == nil || physical.preparation != p.preparation || physical.validateOwner() != nil {
		return bad()
	}
	_, metadata, capture, err := physical.physicalReadValidated()
	if err != nil {
		return bad()
	}
	// Keep the original MTU derivation, including the actual adopted TUN and
	// complete Local packet graph. Its configured ceiling is not a path proof.
	plan, err := p.MTUPlan()
	if err != nil {
		return bad()
	}
	var proofs []NodeChainProof
	switch execution {
	case "local":
		proofs = p.policy.localProofs
	case "server":
		proofs = p.policy.serverProofs
	default:
		return bad()
	}
	if len(proofs) < 2 {
		return bad()
	}
	dns := NodeChainExecutionDNSCapture{execution, SelectorTag, proofs[len(proofs)-1].Tag, p.policy.source.Server.DNSPolicySHA256, p.policy.dns}
	dns.DNS.ConfigSHA256 = p.hash
	return desktopNodeChainExecutionReadyCapture{metadata, capture, plan, append([]NodeChainProof(nil), proofs...), dns}, nil
}

func (p *NodeChainExecutionPreparation) bindProjectedExecution(policy *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if p.multiple != nil && p.multiple.desktop != nil {
		return p.bindMultipleImportedDesktopProjected(policy)
	}
	if p.mobile != nil && p.mobile.multiple != nil {
		return p.bindMultipleImportedMobileProjected(policy)
	}
	if p.openvpn != nil && p.openvpn.desktop != nil {
		return p.bindOpenVPNDesktopProjected(policy)
	}
	if p.mobile != nil && p.mobile.openvpn != nil {
		return p.bindOpenVPNMobileProjected(policy)
	}
	if p.mobile != nil && p.mobile.socks != nil {
		return p.bindSOCKSMobileProjected(policy)
	}
	if p.mobile != nil && p.mobile.connect != nil {
		return p.bindCONNECTMobileProjected(policy)
	}
	// First retain the existing generic compiler's exact structural transition
	// checks. A valid storage seal alone cannot authorize changed original rows.
	generic, err := NewNodeChainExecutionPreparation(p.source.LocalSource, p.source.Execution)
	if err != nil {
		return nil, err
	}
	addition, err := generic.BindExecution(policy)
	if err != nil {
		return nil, err
	}
	return p.bindProjectedExecutionAddition(policy, addition)
}

func (p *NodeChainExecutionPreparation) bindProjectedExecutionAddition(policy *NodeChainExecutionPolicy, addition *NodeChainExecutionProjection) (*NodeChainExecutionProjection, error) {
	transition, err := addition.Transition()
	if err != nil {
		return nil, err
	}
	var graph map[string]any
	if exactJSON([]byte(p.config), &graph, 4<<20) != nil {
		return nil, nodeChainExecutionError
	}
	rows, ok := graph["outbounds"].([]any)
	if !ok {
		return nil, nodeChainExecutionError
	}
	var resultRows []any
	selector, gate := false, false
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, nodeChainExecutionError
		}
		switch row["tag"] {
		case SelectorTag:
			encoded, _ := json.Marshal(row)
			if selector || string(encoded) != transition.SelectorBeforeJSON {
				return nil, nodeChainExecutionError
			}
			var replacement map[string]any
			if exactJSON([]byte(transition.SelectorAfterJSON), &replacement, 64<<10) != nil {
				return nil, nodeChainExecutionError
			}
			raw, selector = replacement, true
		case NodeChainExecutionGateTag:
			if gate || !reflect.DeepEqual(row, map[string]any{"type": NodeChainExecutionGateType, "tag": NodeChainExecutionGateTag, "detour": SelectorTag}) {
				return nil, nodeChainExecutionError
			}
			for _, added := range transition.AddedOutbounds {
				var outbound map[string]any
				if exactJSON([]byte(added), &outbound, 64<<10) != nil {
					return nil, nodeChainExecutionError
				}
				resultRows = append(resultRows, outbound)
			}
			gate = true
		}
		resultRows = append(resultRows, raw)
	}
	if !selector || !gate || len(resultRows) != len(rows)+len(transition.AddedOutbounds) {
		return nil, nodeChainExecutionError
	}
	graph["outbounds"] = resultRows
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return nil, nodeChainExecutionError
	}
	result := &NodeChainExecutionProjection{preparation: p, policy: policy, config: string(raw), hash: externalDigest(raw)}
	transition.PreparationSourceSHA256, transition.PreparationConfigSHA256 = p.sourceSHA, p.configSHA
	transition.ConfigSHA256 = result.hash
	result.transition = transition
	result.seal = result.captureSeal()
	return result, result.validateCapture()
}
