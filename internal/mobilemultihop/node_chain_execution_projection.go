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
	ExternalFinalLocalLaunch    string                           `json:"external_final_local_launch,omitempty"`
	DesktopMultipleImported     *DesktopNodeChainMetadata        `json:"desktop_multiple_imported,omitempty"`
	MultipleImportedLocalLaunch string                           `json:"multiple_imported_local_launch,omitempty"`
	DesktopOpenVPN              *DesktopNodeChainMetadata        `json:"desktop_openvpn,omitempty"`
	OpenVPNLocalLaunch          string                           `json:"openvpn_local_launch,omitempty"`
	Schema                      int                              `json:"schema"`
	Execution                   string                           `json:"execution"`
	LocalSource                 string                           `json:"local_source"`
	Desktop                     *DesktopNodeChainMetadata        `json:"desktop,omitempty"`
	DesktopLast                 string                           `json:"desktop_last,omitempty"`
	DesktopCONNECT              *DesktopNodeChainCONNECTMetadata `json:"desktop_connect,omitempty"`
	DesktopSOCKS                *DesktopNodeChainSOCKSMetadata   `json:"desktop_socks,omitempty"`
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
	externalFinal                                  *nodeChainExternalFinalExecutionBinding
	sourceJSON, sourceSHA, config, configSHA, seal string
	source                                         NodeChainExecutionPreparationSource
	local                                          *NodeChain
	discovery                                      NodeChainExecutionDiscoveryCapture
	dns                                            NodeChainExecutionDNSCapture
	physical                                       []PhysicalEgress
	desktop                                        *DesktopNodeChainPolicy
	desktopPhysical                                *DesktopNodeChainExecutionPhysicalPolicy
	packetDesktop                                  *nodeChainDesktopPacketObservation
	originalPreparationSeal                        *nodeChainExecutionPreparationSeal
	mobile                                         *nodeChainExecutionMobileProjection
	connect                                        *nodeChainCONNECTExecutionBinding
	socks                                          *nodeChainSOCKSExecutionBinding
	openvpn                                        *nodeChainOpenVPNExecutionBinding
	multiple                                       *nodeChainMultipleImportedExecutionBinding
	importedPublic                                 *nodeChainExecutionImportedPublicCapture
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
	if err != nil || local.validateCapture() != nil || local.pairedHysteria != nil || local.importedNodes != nil || local.openVPNMiddle != nil || local.importedMiddle != nil && !nodeChainImportedExecutionMemberSupported(local.importedMiddle, len(local.nodes)) ||
		exactJSON([]byte(localSource), &original, NodeChainInputLimit) != nil || (original.Schema != 1 && original.Schema != 2) ||
		!nodeChainServerFinalCapture(original.Schema, local.nodes[len(local.nodes)-1]) ||
		len(original.IdentitySources) != len(local.nodes) {
		return nil, nodeChainExecutionError
	}
	return newNodeChainExecutionPreparationCaptured(localSource, execution, desktop, mobile, local, nil)
}

// The distinct typed caller supplies its original private runtime and source.
// Generic public constructors still pass only their validated schema1/2 graph.
func newNodeChainExecutionPreparationCaptured(localSource, execution string, desktop *DesktopNodeChainPolicy, mobile *nodeChainExecutionMobileProjection, local *NodeChain, connect *NodeChainCONNECTSource, typedDesktop ...*nodeChainCONNECTExecutionDesktop) (*NodeChainExecutionPreparation, error) {
	return newNodeChainExecutionPreparationFamily(localSource, execution, desktop, mobile, local, connect, nil, typedDesktop...)
}

func newNodeChainExecutionPreparationFamily(localSource, execution string, desktop *DesktopNodeChainPolicy, mobile *nodeChainExecutionMobileProjection, local *NodeChain, connect *NodeChainCONNECTSource, socks *NodeChainSOCKSSource, typedDesktop ...*nodeChainCONNECTExecutionDesktop) (*NodeChainExecutionPreparation, error) {
	if len(typedDesktop) > 1 || len(typedDesktop) == 1 && (typedDesktop[0] == nil || connect == nil || desktop != nil || mobile != nil) {
		return nil, nodeChainExecutionError
	}
	var captured *nodeChainCONNECTExecutionDesktop
	if len(typedDesktop) == 1 {
		captured = typedDesktop[0]
	}
	return newNodeChainExecutionPreparationOwned(localSource, execution, desktop, mobile, local, connect, socks, captured, nil)
}

// Each typed desktop adjunct is issued by its original family constructor.
// A serialized metadata value is never sufficient to enter this boundary.
func newNodeChainExecutionPreparationOwned(localSource, execution string, desktop *DesktopNodeChainPolicy, mobile *nodeChainExecutionMobileProjection, local *NodeChain, connect *NodeChainCONNECTSource, socks *NodeChainSOCKSSource, connectDesktop *nodeChainCONNECTExecutionDesktop, socksDesktop *nodeChainSOCKSExecutionDesktop) (*NodeChainExecutionPreparation, error) {
	return newNodeChainExecutionPreparationOwnedOpenVPN(localSource, execution, desktop, mobile, local, connect, socks, connectDesktop, socksDesktop, nil)
}

func newNodeChainExecutionPreparationOwnedOpenVPN(localSource, execution string, desktop *DesktopNodeChainPolicy, mobile *nodeChainExecutionMobileProjection, local *NodeChain, connect *NodeChainCONNECTSource, socks *NodeChainSOCKSSource, connectDesktop *nodeChainCONNECTExecutionDesktop, socksDesktop *nodeChainSOCKSExecutionDesktop, openvpn *NodeChain, typedOpenVPNDesktop ...*nodeChainOpenVPNExecutionDesktop) (*NodeChainExecutionPreparation, error) {
	return newNodeChainExecutionPreparationOwnedMultiple(localSource, execution, desktop, mobile, local, connect, socks, connectDesktop, socksDesktop, openvpn, nil, typedOpenVPNDesktop...)
}

func newNodeChainExecutionPreparationOwnedMultiple(localSource, execution string, desktop *DesktopNodeChainPolicy, mobile *nodeChainExecutionMobileProjection, local *NodeChain, connect *NodeChainCONNECTSource, socks *NodeChainSOCKSSource, connectDesktop *nodeChainCONNECTExecutionDesktop, socksDesktop *nodeChainSOCKSExecutionDesktop, openvpn, multiple *NodeChain, typedOpenVPNDesktop ...*nodeChainOpenVPNExecutionDesktop) (*NodeChainExecutionPreparation, error) {
	if len(typedOpenVPNDesktop) > 1 || len(typedOpenVPNDesktop) == 1 && (typedOpenVPNDesktop[0] == nil || openvpn == nil || desktop != nil || mobile != nil) {
		return nil, nodeChainExecutionError
	}
	var openvpnDesktop *nodeChainOpenVPNExecutionDesktop
	if len(typedOpenVPNDesktop) == 1 {
		openvpnDesktop = typedOpenVPNDesktop[0]
	}
	return newNodeChainExecutionPreparationOwnedFamilies(localSource, execution, desktop, mobile, local, connect, socks, connectDesktop, socksDesktop, openvpn, multiple, openvpnDesktop, nil, nil)
}

// Closed family constructors retain their exact original physical owner. A
// generic metadata field cannot supply either typed desktop adjunct.
func newNodeChainExecutionPreparationOwnedFamilies(localSource, execution string, desktop *DesktopNodeChainPolicy, mobile *nodeChainExecutionMobileProjection, local *NodeChain, connect *NodeChainCONNECTSource, socks *NodeChainSOCKSSource, connectDesktop *nodeChainCONNECTExecutionDesktop, socksDesktop *nodeChainSOCKSExecutionDesktop, openvpn, multiple *NodeChain, openvpnDesktop *nodeChainOpenVPNExecutionDesktop, multipleDesktop *nodeChainMultipleImportedExecutionDesktop, externalFinal *nodeChainExternalFinalExecutionBinding) (*NodeChainExecutionPreparation, error) {
	if local != nil && local.pairedHysteria != nil {
		// The complete Local owner grants no selected remote or Compare trial.
		return nil, nodeChainExecutionError
	}

	if multipleDesktop != nil && (multiple == nil || mobile != nil || desktop != nil || connectDesktop != nil || socksDesktop != nil || openvpnDesktop != nil) {
		return nil, nodeChainExecutionError
	}
	if openvpn != nil && (local != openvpn || connect != nil || socks != nil || desktop != nil || connectDesktop != nil || socksDesktop != nil || mobile != nil && (mobile.openvpn == nil || mobile.socks != nil || mobile.connect != nil)) {
		return nil, nodeChainExecutionError
	}
	if socks != nil && (connect != nil || desktop != nil || connectDesktop != nil || mobile != nil && (mobile.socks == nil || mobile.connect != nil || mobile.openvpn != nil)) ||
		connectDesktop != nil && (connect == nil || desktop != nil || mobile != nil || socksDesktop != nil) ||
		socksDesktop != nil && (socks == nil || connect != nil || desktop != nil || mobile != nil || connectDesktop != nil) {
		return nil, nodeChainExecutionError
	}
	if multiple != nil && (!multiple.selectedMultipleTransportSupported() || local != multiple || openvpn != nil || connect != nil || socks != nil || desktop != nil || connectDesktop != nil || socksDesktop != nil || openvpnDesktop != nil || mobile != nil && (mobile.multiple == nil || mobile.connect != nil || mobile.socks != nil || mobile.openvpn != nil)) {
		return nil, nodeChainExecutionError
	}
	var err error
	p := &NodeChainExecutionPreparation{source: NodeChainExecutionPreparationSource{Schema: 1, Execution: execution, LocalSource: localSource}, local: local, desktop: desktop, mobile: mobile}
	if externalFinal != nil {
		if externalFinal.local != local || connect != nil || socks != nil || openvpn != nil || multiple != nil || desktop != nil && (desktop.original != local || !desktop.chain.HasExternalFinal() || mobile != nil) || mobile != nil && mobile.externalFinal == nil || connectDesktop != nil || socksDesktop != nil || openvpnDesktop != nil || multipleDesktop != nil {
			return nil, nodeChainExecutionError
		}
		p.externalFinal = externalFinal
		externalFinal.preparation = p
		p.source.Schema, p.source.ExternalFinalLocalLaunch = 8, externalFinal.launch
	}
	if connect != nil {
		p.source.Schema = 4
		p.connect = &nodeChainCONNECTExecutionBinding{source: connect, local: local, preparation: p}
		p.connect.self = p.connect
		if connectDesktop != nil {
			p.connect.desktop = connectDesktop
			if err := connectDesktop.bind(p, p.connect); err != nil {
				return nil, err
			}
		}
	}
	if socks != nil {
		p.source.Schema = 3
		p.socks = &nodeChainSOCKSExecutionBinding{source: socks, local: local, preparation: p}
		p.socks.self = p.socks
		if socksDesktop != nil {
			p.socks.desktop = socksDesktop
			if err := socksDesktop.bind(p, p.socks); err != nil {
				return nil, err
			}
		}
	}
	if openvpn != nil {
		pair, server, pairSHA, pairErr := nodeChainOpenVPNLocalPair(openvpn.openVPNMiddle)
		if pairErr != nil {
			return nil, pairErr
		}
		launch, err := openvpn.LaunchInput()
		if err != nil {
			return nil, err
		}
		p.source.Schema, p.source.OpenVPNLocalLaunch = 5, launch
		p.openvpn = &nodeChainOpenVPNExecutionBinding{source: openvpn, preparation: p, local: local, middle: openvpn.openVPNMiddle, pair: pair, server: server, pairSHA: pairSHA}
		capture, captureErr := openvpn.OpenVPNMiddleCapture()
		if captureErr != nil {
			return nil, captureErr
		}
		p.openvpn.sourceSeal, p.openvpn.launch, p.openvpn.capture = openvpn.seal, launch, capture
		p.openvpn.valuesSeal = p.openvpn.immutableValuesSeal()
		p.openvpn.self = p.openvpn
		if openvpnDesktop != nil {
			p.openvpn.desktop = openvpnDesktop
			if err := openvpnDesktop.bind(p, p.openvpn); err != nil {
				return nil, err
			}
		}
	}
	if multiple != nil {
		launch, err := multiple.LaunchInput()
		if err != nil {
			return nil, err
		}
		p.source.Schema, p.source.MultipleImportedLocalLaunch = 6, launch
		p.multiple = &nodeChainMultipleImportedExecutionBinding{preparation: p, source: multiple, local: local, owners: multiple.importedNodes, sourceSeal: multiple.seal, launch: launch}
		p.multiple.self = p.multiple
		if multipleDesktop != nil {
			p.multiple.desktop = multipleDesktop
			if err := multipleDesktop.bind(p, p.multiple); err != nil {
				return nil, err
			}
		}
	}
	config := local.Config()
	if multipleDesktop != nil {
		config = multipleDesktop.native.config
	}
	if openvpnDesktop != nil {
		config = openvpnDesktop.native.config
	}
	if mobile != nil {
		if desktop != nil || p.validateMobileCapture() != nil {
			return nil, nodeChainExecutionError
		}
		config = mobile.config()
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
	if selected == nil || selected["detour"] != externalFinal.resolverTag() {
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
	dnsPolicySHA := ""
	if externalFinal != nil {
		dnsPolicySHA = externalFinal.policySHA
	} else {
		var finalGraph map[string]any
		if exactJSON([]byte(local.nodes[len(local.nodes)-1].config), &finalGraph, 4<<20) != nil {
			return nil, nodeChainExecutionError
		}
		dnsRaw, err := json.Marshal(finalGraph["dns"])
		if err != nil {
			return nil, nodeChainExecutionError
		}
		dnsPolicySHA = externalDigest(dnsRaw)
	}
	dns := local.DNSCapture()
	dns.SourceSHA256, dns.ConfigSHA256, dns.FinalTag = p.sourceSHA, p.configSHA, SelectorTag
	dns.ResolverSHA256 = externalDigest(resolver)
	p.dns = NodeChainExecutionDNSCapture{"local", SelectorTag, final, dnsPolicySHA, dns}
	p.physical, err = local.PhysicalEgress()
	if err != nil {
		return nil, nodeChainExecutionError
	}
	p.seal = p.captureSeal()
	p.rememberMultipleImportedSeal()
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	p.rememberPreparationSeal()
	p.importedPublic = captureNodeChainExecutionImportedPublic(p)
	if desktop != nil {
		p.rememberDesktopPacketObservation()
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
	// The local compiler may have routed the paired final API through its
	// selector before a LAN deny. It must close along with application ingress.
	rules, ok := route["rules"].([]any)
	if route["rules"] != nil && !ok {
		return nodeChainExecutionError
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return nodeChainExecutionError
		}
		if rule["action"] == "route" {
			if rule["outbound"] != SelectorTag {
				return nodeChainExecutionError
			}
			rule["outbound"] = NodeChainExecutionGateTag
		}
	}
	route["final"] = NodeChainExecutionGateTag
	return nil
}

func (p *NodeChainExecutionPreparation) captureSeal() string {
	if p == nil {
		return ""
	}
	if p.originalPreparationSeal.matches(p) {
		return p.originalPreparationSeal.seal
	}
	if p.packetDesktop.matchesPreparation(p) {
		return p.packetDesktop.seal
	}
	if p.multiple != nil && p.multiple.originalSeal.matches(p) {
		return p.multiple.originalSeal.seal
	}
	if p.multiple != nil && p.multiple.desktop != nil {
		return p.captureMultipleImportedDesktopSeal()
	}
	if p.openvpn != nil && p.openvpn.desktop != nil {
		return p.captureOpenVPNDesktopSeal()
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
	if p == nil || p.seal == "" || p.captureSeal() != p.seal || p.local == nil || len(p.local.proofs) == 0 || p.socks == nil && p.connect == nil && p.openvpn == nil && p.multiple == nil && p.externalFinal == nil && !p.packetDesktop.localCurrent(p) && !p.originalPreparationSeal.localPacketCurrent(p) && p.local.validateCapture() != nil || p.local.openVPNMiddle != nil && p.openvpn == nil ||
		p.discovery.Entry != p.local.proofs[0] || p.dns.DNS.SourceSHA256 != p.sourceSHA || p.dns.DNS.ConfigSHA256 != p.configSHA {
		return nodeChainExecutionError
	}
	if p.externalFinal != nil {
		if !p.externalFinal.current(p) {
			return nodeChainExecutionError
		}
	} else if p.source.Schema == 8 || p.source.ExternalFinalLocalLaunch != "" {
		return nodeChainExecutionError
	} else if p.multiple != nil {
		if p.multiple.validate(p, p.local) != nil {
			return nodeChainExecutionError
		}
	} else if p.local.importedNodes != nil || p.source.MultipleImportedLocalLaunch != "" || p.source.DesktopMultipleImported != nil || p.source.Schema == 6 {
		return nodeChainExecutionError
	} else if p.openvpn != nil {
		if p.openvpn.validate(p, p.local) != nil {
			return nodeChainExecutionError
		}
	} else if p.source.OpenVPNLocalLaunch != "" || p.source.DesktopOpenVPN != nil {
		return nodeChainExecutionError
	} else if p.socks != nil {
		if p.socks.validate(p, p.local) != nil {
			return nodeChainExecutionError
		}
	} else if p.validateCONNECTExecutionCapture() != nil {
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
	originalSeal *nodeChainExecutionProjectionSeal
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
	if p.externalFinal != policy.externalFinal || p.connect != policy.connect || p.socks != policy.socks || p.openvpn != policy.openvpn || p.multiple != policy.multiple {
		return nil, nodeChainExecutionError
	}
	if p.mobile != nil && p.mobile.executionSource != policy.Source() {
		return nil, nodeChainExecutionError
	}
	if p.desktop != nil || p.mobile != nil || p.openvpn != nil && p.openvpn.desktop != nil || p.multiple != nil && p.multiple.desktop != nil {
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
	result.rememberProjectionSeal()
	return result, result.validateCapture()
}

func (p *NodeChainExecutionProjection) captureSeal() string {
	if p == nil {
		return ""
	}
	if p.originalSeal.matches(p) {
		return p.originalSeal.seal
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
	if p == nil || p.seal == "" || p.seal != p.captureSeal() || p.policy == nil || p.policy.validateCapture() != nil ||
		(p.policy.connect == nil && p.policy.socks == nil && p.policy.openvpn == nil && p.policy.multiple == nil && p.policy.externalFinal == nil && p.preparation.validateCapture() != nil) ||
		(p.policy.connect != nil && p.preparation != p.policy.connect.preparation) ||
		(p.policy.socks != nil && p.preparation != p.policy.socks.preparation) ||
		(p.policy.openvpn != nil && p.preparation != p.policy.openvpn.preparation) ||
		(p.policy.multiple != nil && p.preparation != p.policy.multiple.preparation) || (p.policy.externalFinal != nil && p.policy.externalFinal.preparation != p.preparation) ||
		p.transition.PreparationSourceSHA256 != p.preparation.sourceSHA || p.transition.PreparationConfigSHA256 != p.preparation.configSHA ||
		p.transition.SourceSHA256 != p.policy.sourceSHA || p.transition.ConfigSHA256 != p.hash || !(p.originalSeal != nil && p.originalSeal.owner == p && p.originalSeal.config == p.config && p.originalSeal.hash == p.hash) && externalDigest([]byte(p.config)) != p.hash {
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
	return p.policy.proofInventoryValidated(execution)
}
func (p *NodeChainExecutionProjection) DNSCapture(execution string) (NodeChainExecutionDNSCapture, error) {
	if p.validateCapture() != nil {
		return NodeChainExecutionDNSCapture{}, nodeChainExecutionError
	}
	proofs, err := p.policy.proofInventoryValidated(execution)
	if err != nil {
		return NodeChainExecutionDNSCapture{}, err
	}
	result := NodeChainExecutionDNSCapture{execution, SelectorTag, proofs[len(proofs)-1].Tag, p.policy.source.Server.DNSPolicySHA256, p.policy.dns}
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
