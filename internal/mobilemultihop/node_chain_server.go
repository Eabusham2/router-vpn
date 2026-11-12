package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"

	"router-vpn/internal/multihoprelay"
)

// NodeChainServerSource is an operator-owned private source, never a client
// request. Nodes are complete original suffix launch inputs; the first client
// entry is identified separately and is not instantiated on this server.
type NodeChainServerSource struct {
	Schema          int      `json:"schema"`
	EntryID         string   `json:"entry_id"`
	EntryNodeID     string   `json:"entry_node_id"`
	EntryMode       string   `json:"entry_mode"`
	Nodes           []string `json:"nodes"`
	IdentitySources []string `json:"identity_sources"`
}

type NodeChainServerBinding struct {
	SourceSHA256  string `json:"source_sha256"`
	CaptureSHA256 string `json:"capture_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
}

// A proof target is private worker input. It cannot be published as capability
// metadata: its original API credential belongs only to this captured member.
type NodeChainServerProof struct {
	Binding NodeChainServerBinding `json:"binding"`
	Proof   NodeChainProof         `json:"proof"`
	API     string                 `json:"api"`
	Token   string                 `json:"token"`
	Network string                 `json:"network"`
	Address string                 `json:"address"`
}

type NodeChainServerDestination struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type NodeChainServerDNSCapture struct {
	Binding        NodeChainServerBinding       `json:"binding"`
	PolicySHA256   string                       `json:"policy_sha256"`
	PolicyJSON     string                       `json:"policy_json"`
	RouterJSON     string                       `json:"router_json"`
	ResolverTag    string                       `json:"resolver_tag"`
	ResolverSHA256 string                       `json:"resolver_sha256"`
	FinalTag       string                       `json:"final_tag"`
	Destinations   []NodeChainServerDestination `json:"destinations"`
}

// A prefix credential grants only Destinations through its one captured tag.
// Final grants TCP/UDP application traffic through the final tag, subject to
// the original union of node policies. Its Destinations are exact captured
// control/DNS exceptions, not CIDR or wildcard grants. A restricted hostname
// must first be resolved by the retained selected DNS owner and every resolved
// literal checked with AllowsDestination before the worker dispatches it.
type NodeChainServerFrontRoute struct {
	Binding           NodeChainServerBinding       `json:"binding"`
	Position          int                          `json:"position"`
	Username          string                       `json:"username"`
	Password          string                       `json:"password"`
	Tag               string                       `json:"tag"`
	Final             bool                         `json:"final"`
	UDPOverTCPVersion int                          `json:"udp_over_tcp_version"`
	Destinations      []NodeChainServerDestination `json:"destinations"`
	BlockIPv6         bool                         `json:"block_ipv6"`
	BlockedCIDRs      []string                     `json:"blocked_cidrs"`
}

// AllowsDestination is a pure tuple check, not front admission or readiness.
// The worker must retain this exact route, authenticate its peer/credential,
// prove the captured native owner, and keep the front closed until bootstrap.
func (r NodeChainServerFrontRoute) AllowsDestination(network, address string) bool {
	if network != "tcp" && network != "udp" {
		return false
	}
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || host == "" {
		return false
	}
	for _, destination := range r.Destinations {
		if destination.Network == network && destination.Address == address {
			return true
		}
	}
	if !r.Final {
		return false
	}
	ip, parseErr := netip.ParseAddr(host)
	if parseErr != nil {
		return !r.BlockIPv6 && len(r.BlockedCIDRs) == 0 && externalDNSHostname(host)
	}
	if ip.Zone() != "" || ip.Is4In6() || ip.String() != host || r.BlockIPv6 && ip.Is6() {
		return false
	}
	for _, value := range r.BlockedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// NodeChainServerPolicy holds a sealed no-inbound native graph. Creating it
// opens no socket and proves no connectivity. The worker owns the separate
// authenticated front and must not forward while proofs are pending.
type NodeChainServerPolicy struct {
	carrier                                        *NodeChainServerCarrier
	sourceJSON, sourceSHA, config, configSHA, seal string
	nodes                                          []*NodeProfile
	descriptor                                     multihoprelay.NodeChainDescriptor
	proofs                                         []NodeChainProof
	proofTargets                                   []NodeChainServerProof
	dns                                            NodeChainServerDNSCapture
	blockIPv6                                      bool
	blockedCIDRs                                   []string
}

var nodeChainServerError = errors.New("ordered server path lost its complete operator-owned source")

func NewNodeChainServerPolicy(sourceJSON string) (*NodeChainServerPolicy, error) {
	return newNodeChainServerPolicy(sourceJSON, nil)
}

func newNodeChainServerPolicy(sourceJSON string, carrier *NodeChainServerCarrier) (*NodeChainServerPolicy, error) {
	var source NodeChainServerSource
	if exactJSON([]byte(sourceJSON), &source, NodeChainInputLimit) != nil || source.Schema != 1 ||
		!exactID.MatchString(source.EntryID) || !proofID.MatchString(source.EntryNodeID) || !NodeChainPrefixMode(source.EntryMode) ||
		len(source.Nodes) < 1 || len(source.Nodes) > multihoprelay.NodeChainMaximumMembers || len(source.IdentitySources) != len(source.Nodes) {
		return nil, nodeChainServerError
	}
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, nodeChainServerError
	}
	p := &NodeChainServerPolicy{sourceJSON: string(raw)}
	digest, _ := json.Marshal([]string{"routervpn-server-node-chain-source-v1", p.sourceJSON})
	p.sourceSHA = externalDigest(digest)
	clear(digest)
	p.descriptor = multihoprelay.NodeChainDescriptor{Schema: 1, EntryID: source.EntryID, EntryNodeID: source.EntryNodeID,
		EntryMode: source.EntryMode, SourceSHA256: p.sourceSHA}
	members := make([]nodeChainGraphMember, 0, len(source.Nodes))
	closures := make([]*externalPredecessor, 0, len(source.Nodes))
	blocked := map[string]bool{}
	for index, launch := range source.Nodes {
		node, err := ParseNodeLaunchInput(launch)
		if err != nil || node == nil || validateNodeChainIdentity(source.IdentitySources[index], node) != nil ||
			index < len(source.Nodes)-1 && !NodeChainPrefixMode(node.mode) || index == len(source.Nodes)-1 && node.mode != "shadowsocks" {
			return nil, nodeChainServerError
		}
		// Every suffix establishment is already a later captured peer. No
		// hostname here gains a new bootstrap or ambient socket authority.
		endpoint := predecessorText(node.profile, "endpoint")
		ip, err := netip.ParseAddr(endpoint)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.String() != endpoint {
			return nil, nodeChainServerError
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil || closure == nil {
			return nil, nodeChainServerError
		}
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return nil, nodeChainServerError
		}
		layer := predecessorText(node.profile, "start_layer")
		if layer == "" {
			layer = "off"
		}
		member := multihoprelay.NodeChainMember{Position: index + 1, ProfileID: predecessorText(node.profile, "id"),
			NodeID: predecessorText(node.profile, "node_proof_id"), Mode: node.mode, StartLayer: layer}
		if index < len(source.Nodes)-1 {
			if closure.final["type"] != nodeChainPrefixType(node.mode) {
				return nil, nodeChainServerError
			}
			member.ClientPublicKey, err = node.PacketClientPublicKey()
			peers, ok := closure.final["peers"].([]any)
			if err != nil || !ok || len(peers) != 1 {
				return nil, nodeChainServerError
			}
			peer, ok := peers[0].(map[string]any)
			if !ok {
				return nil, nodeChainServerError
			}
			member.ServerPublicKey = predecessorText(peer, "public_key")
		} else if closure.final["method"] != NativeStartLayerMethod ||
			closure.final["type"] != "shadowsocks" && closure.final["type"] != "routervpn-aes-xor" {
			return nil, nodeChainServerError
		}
		ipv6, ranges, err := externalDevicePolicy(node.profile)
		if err != nil {
			return nil, nodeChainServerError
		}
		p.blockIPv6 = p.blockIPv6 || ipv6 == "off"
		for _, value := range ranges {
			blocked[value] = true
		}
		p.nodes = append(p.nodes, node)
		p.descriptor.Members = append(p.descriptor.Members, member)
		members = append(members, nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode})
		closures = append(closures, closure)
	}
	for value := range blocked {
		p.blockedCIDRs = append(p.blockedCIDRs, value)
	}
	sort.Strings(p.blockedCIDRs)
	// The policy digest is the exact original final DNS tree, before private
	// graph namespacing. It includes TLS, HTTPS paths and bootstrap dependencies.
	policyRaw, err := json.Marshal(closures[len(closures)-1].graph["dns"])
	if err != nil {
		return nil, nodeChainServerError
	}
	p.descriptor.DNSPolicySHA256 = externalDigest(policyRaw)
	if p.descriptor.Validate() != nil {
		return nil, nodeChainServerError
	}
	expected, err := p.nodes[0].PhysicalEgress()
	if err != nil {
		return nil, nodeChainServerError
	}
	if carrier != nil {
		if carrier.sourceSHA != p.sourceSHA || carrier.source != p.sourceJSON || carrier.apply(p.nodes[0], closures[0]) != nil {
			return nil, nodeChainServerCarrierError
		}
		p.carrier = carrier
	}
	config, proofs, dns, _, err := compileNodeChainClosures(members, closures, expected)
	if err != nil {
		return nil, err
	}
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return nil, nodeChainServerError
	}
	// The native graph is deliberately listener-free. The worker receives the
	// captured restrictions and proof/DNS exceptions separately for its front.
	graph["inbounds"] = []any{}
	route := graph["route"].(map[string]any)
	route["rules"] = []any{}
	route["final"] = dns.FinalTag
	rows := graph["outbounds"].([]any)
	kept := make([]any, 0, len(rows)-1)
	for _, value := range rows {
		row := value.(map[string]any)
		if row["tag"] != SelectorTag {
			kept = append(kept, row)
		}
	}
	graph["outbounds"] = kept
	if carrier != nil && carrier.bind(graph, proofs[0].Tag) != nil {
		return nil, nodeChainServerCarrierError
	}
	raw, err = json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return nil, nodeChainServerError
	}
	p.config, p.configSHA = string(raw), externalDigest(raw)
	for index, proof := range proofs {
		proof.Position = index + 1
		p.proofs = append(p.proofs, proof)
		node := p.nodes[index]
		api := predecessorText(node.profile, "router_api")
		url, err := privateAPI(api)
		if err != nil {
			return nil, nodeChainServerError
		}
		p.proofTargets = append(p.proofTargets, NodeChainServerProof{Proof: proof, API: api,
			Token: predecessorText(node.profile, "api_token"), Network: "tcp", Address: url.Host})
	}
	dnsRaw, err := json.Marshal(graph["dns"])
	if err != nil {
		return nil, nodeChainServerError
	}
	desktop, err := p.nodes[len(p.nodes)-1].DesktopCapture()
	if err != nil {
		return nil, nodeChainServerError
	}
	p.dns = NodeChainServerDNSCapture{PolicySHA256: p.descriptor.DNSPolicySHA256, PolicyJSON: string(policyRaw),
		RouterJSON: string(dnsRaw), ResolverTag: dns.ResolverTag, ResolverSHA256: dns.ResolverSHA256, FinalTag: dns.FinalTag}
	for _, resolver := range append([]ExternalDesktopDNS{desktop.SelectedDNS}, desktop.BootstrapDNS...) {
		network := "tcp"
		if resolver.Type == "udp" || resolver.Type == "h3" {
			network = "udp"
		}
		if resolver.Physical || resolver.Detour != "proxy" || resolver.Port < 1 || resolver.Port > 65535 {
			return nil, nodeChainServerError
		}
		p.dns.Destinations = append(p.dns.Destinations, NodeChainServerDestination{network, net.JoinHostPort(resolver.Host, strconv.Itoa(resolver.Port))})
	}
	p.seal = p.captureSeal()
	if err := p.validateCapture(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *NodeChainServerPolicy) captureSeal() string {
	if p == nil {
		return ""
	}
	carrierSeal := ""
	if p.carrier != nil {
		carrierSeal = p.carrier.seal
	}
	raw, err := json.Marshal([]any{"routervpn-server-node-chain-policy-v1", carrierSeal, p.sourceJSON, p.sourceSHA, p.config, p.configSHA,
		p.descriptor, p.proofs, p.proofTargets, p.dns, p.blockIPv6, p.blockedCIDRs})
	if err != nil {
		return ""
	}
	digest := externalDigest(raw)
	clear(raw)
	return digest
}

func (p *NodeChainServerPolicy) validateCapture() error {
	if p == nil || p.carrier != nil && !p.carrier.sealed() || p.seal == "" || p.captureSeal() != p.seal || p.descriptor.Validate() != nil ||
		len(p.nodes) != len(p.proofs) || len(p.proofs) != len(p.proofTargets) {
		return nodeChainServerError
	}
	for index, node := range p.nodes {
		proof := p.proofs[index]
		if node == nil || node.validateNodeDesktopCapture() != nil || proof.Position != index+1 || proof.SourceSHA256 != node.source ||
			proof.Mode != node.mode || proof.ProfileID != predecessorText(node.profile, "id") || proof.NodeID != predecessorText(node.profile, "node_proof_id") {
			return nodeChainServerError
		}
	}
	return nil
}

func (p *NodeChainServerPolicy) binding(capture multihoprelay.NodeChainCapture) (NodeChainServerBinding, error) {
	if p.validateCapture() != nil || capture.Validate() != nil || !reflect.DeepEqual(capture.Source, p.descriptor) {
		return NodeChainServerBinding{}, nodeChainServerError
	}
	digest, err := capture.Digest()
	if err != nil {
		return NodeChainServerBinding{}, nodeChainServerError
	}
	return NodeChainServerBinding{p.sourceSHA, digest, p.configSHA}, nil
}

func (p *NodeChainServerPolicy) Source() string       { return p.sourceJSON }
func (p *NodeChainServerPolicy) SourceSHA256() string { return p.sourceSHA }
func (p *NodeChainServerPolicy) Descriptor() multihoprelay.NodeChainDescriptor {
	return p.descriptor.Clone()
}
func (p *NodeChainServerPolicy) ProofInventory() []NodeChainProof {
	return append([]NodeChainProof(nil), p.proofs...)
}
func (p *NodeChainServerPolicy) NativeConfig(capture multihoprelay.NodeChainCapture) (string, error) {
	if _, err := p.binding(capture); err != nil {
		return "", err
	}
	return p.config, nil
}
func (p *NodeChainServerPolicy) ConfigSHA256(capture multihoprelay.NodeChainCapture) (string, error) {
	binding, err := p.binding(capture)
	return binding.ConfigSHA256, err
}
func (p *NodeChainServerPolicy) ProofTargets(capture multihoprelay.NodeChainCapture) ([]NodeChainServerProof, error) {
	binding, err := p.binding(capture)
	if err != nil {
		return nil, err
	}
	result := append([]NodeChainServerProof(nil), p.proofTargets...)
	for index := range result {
		result[index].Binding = binding
	}
	return result, nil
}
func (p *NodeChainServerPolicy) DNSCapture(capture multihoprelay.NodeChainCapture) (NodeChainServerDNSCapture, error) {
	binding, err := p.binding(capture)
	if err != nil {
		return NodeChainServerDNSCapture{}, err
	}
	result := p.dns
	result.Binding = binding
	result.Destinations = append([]NodeChainServerDestination(nil), result.Destinations...)
	return result, nil
}
func (p *NodeChainServerPolicy) FrontRoutes(capture multihoprelay.NodeChainCapture) ([]NodeChainServerFrontRoute, error) {
	binding, err := p.binding(capture)
	if err != nil {
		return nil, err
	}
	result := make([]NodeChainServerFrontRoute, len(p.proofs))
	for index, proof := range p.proofs {
		user, target := capture.Request.Users[index], p.proofTargets[index]
		route := NodeChainServerFrontRoute{Binding: binding, Position: proof.Position, Username: user.Username,
			Password: user.Password, Tag: proof.Tag, Final: index == len(p.proofs)-1,
			Destinations: []NodeChainServerDestination{{Network: target.Network, Address: target.Address}}}
		if route.Final {
			route.UDPOverTCPVersion = 2
			route.BlockIPv6, route.BlockedCIDRs = p.blockIPv6, append([]string(nil), p.blockedCIDRs...)
			route.Destinations = append(route.Destinations, p.dns.Destinations...)
		}
		result[index] = route
	}
	return result, nil
}
