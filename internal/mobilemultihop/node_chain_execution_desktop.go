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
		desktop, err = NewDesktopNodeChainPolicy(local, meta.SessionID, meta.TargetOS, meta.RestoredMTU)
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
		d.seal == "" || d.currentSeal() != d.seal || d.original.validateCapture() != nil || d.chain.validateCapture() != nil ||
		!reflect.DeepEqual(*p.source.Desktop, d.metadata) || d.metadata.ConfigSHA256 != d.chain.ConfigSHA256() ||
		d.inputs.sessionID != d.metadata.SessionID || d.inputs.targetOS != d.metadata.TargetOS || d.inputs.restoredMTU != d.metadata.RestoredMTU ||
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
	if p == nil || p.preparation == nil || p.original == nil || p.seal == "" || p.captureSeal() != p.seal ||
		p.preparation.desktopPhysical != p || p.preparation.desktop != p.original || p.preparation.validateCapture() != nil {
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

func (p *NodeChainExecutionPreparation) DesktopPhysicalPolicy() (*DesktopNodeChainExecutionPhysicalPolicy, error) {
	if p.validateCapture() != nil || p.desktop == nil || p.desktopPhysical.Validate() != nil {
		return nil, nodeChainExecutionError
	}
	return p.desktopPhysical, nil
}

func (p *NodeChainExecutionProjection) DesktopPhysicalPolicy() (*DesktopNodeChainExecutionPhysicalPolicy, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.preparation.DesktopPhysicalPolicy()
}

func (p *DesktopNodeChainExecutionPhysicalPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	bad := func() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, nodeChainExecutionError
	}
	if p.Validate() != nil {
		return bad()
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

func (p *NodeChainExecutionPreparation) bindProjectedExecution(policy *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
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
