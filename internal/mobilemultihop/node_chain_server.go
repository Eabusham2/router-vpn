package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// NodeChainServerSource is an operator-owned private source, never a client
// request. Nodes are complete original suffix launch inputs; the first client
// entry is identified separately and is not instantiated on this server.
type NodeChainServerSource struct {
	Schema          int                            `json:"schema"`
	EntryID         string                         `json:"entry_id"`
	EntryNodeID     string                         `json:"entry_node_id"`
	EntryMode       string                         `json:"entry_mode"`
	Nodes           []string                       `json:"nodes"`
	IdentitySources []string                       `json:"identity_sources"`
	OpenVPNPairing  *NodeChainOpenVPNServerPairing `json:"openvpn_pairing,omitempty"`
}

type NodeChainServerBinding struct {
	SourceSHA256  string `json:"source_sha256"`
	CaptureSHA256 string `json:"capture_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
}

// A proof target is private worker input. It cannot be published as capability
// metadata: its original API credential belongs only to this captured member.
type NodeChainServerProof struct {
	Binding          NodeChainServerBinding `json:"binding"`
	Proof            NodeChainProof         `json:"proof"`
	API              string                 `json:"api"`
	Token            string                 `json:"token"`
	Network          string                 `json:"network"`
	Address          string                 `json:"address"`
	ExpectedPublicIP string                 `json:"expected_public_ip,omitempty"`
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
// literal checked with AllowsResolvedDestination before the worker dispatches it.
type NodeChainServerFrontRoute struct {
	Binding             NodeChainServerBinding       `json:"binding"`
	Position            int                          `json:"position"`
	Username            string                       `json:"username"`
	Password            string                       `json:"password"`
	Tag                 string                       `json:"tag"`
	Final               bool                         `json:"final"`
	PublicPathBenchmark bool                         `json:"public_path_benchmark,omitempty"`
	UDPOverTCPVersion   int                          `json:"udp_over_tcp_version"`
	Destinations        []NodeChainServerDestination `json:"destinations"`
	BlockIPv6           bool                         `json:"block_ipv6"`
	BlockedCIDRs        []string                     `json:"blocked_cidrs"`
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

// AllowsResolvedDestination is a second check after the original selected
// resolver has returned. An imported benchmark may resolve only its one fixed
// HTTPS hostname; that result never becomes permission to request a raw IP or
// another hostname with the same prefix credential. Every answer is checked.
func (r NodeChainServerFrontRoute) AllowsResolvedDestination(network, original, resolved string) bool {
	if original == resolved || r.Final {
		return r.AllowsDestination(network, resolved)
	}
	if !r.PublicPathBenchmark || network != "tcp" || original != hopmeasure.PublicAddress || !r.AllowsDestination(network, original) {
		return false
	}
	host, port, err := net.SplitHostPort(resolved)
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || port != "443" || ip.String() != host || !externalPublicIP(host) || r.BlockIPv6 && ip.Is6() {
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
	multiple                                       *nodeChainMultipleImportedServerScope
	openvpnMiddle                                  *nodeChainOpenVPNMember
	openvpn                                        *nodeChainOpenVPNServerScope
	socks                                          *nodeChainSOCKSServerScope
	socksMiddle                                    *nodeChainSOCKSMember
	connect                                        *nodeChainCONNECTServerScope
	connectMiddle                                  *nodeChainCONNECTMember
	carrier                                        *NodeChainServerCarrier
	sourceJSON, sourceSHA, config, configSHA, seal string
	nodes                                          []*NodeProfile
	importedMiddle                                 *nodeChainImportedMember
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
	return newNodeChainServerPolicyCaptured(sourceJSON, carrier, false)
}

func newNodeChainServerPolicyCaptured(sourceJSON string, carrier *NodeChainServerCarrier, connect bool) (*NodeChainServerPolicy, error) {
	family := 0
	if connect {
		family = 4
	}
	return newNodeChainServerPolicyFamily(sourceJSON, carrier, family)
}

func newNodeChainServerPolicyFamily(sourceJSON string, carrier *NodeChainServerCarrier, family int) (*NodeChainServerPolicy, error) {
	connect, socks, openvpn, multiple := family == 4, family == 3, family == 5, family == 6
	if family != 0 && !connect && !socks && !openvpn && !multiple {
		return nil, nodeChainServerError
	}
	var source NodeChainServerSource
	if exactJSON([]byte(sourceJSON), &source, NodeChainInputLimit) != nil || (family == 0 && source.Schema != 1 && source.Schema != 2 || family != 0 && source.Schema != family) ||
		!exactID.MatchString(source.EntryID) || !proofID.MatchString(source.EntryNodeID) || !NodeChainPrefixMode(source.EntryMode) ||
		len(source.Nodes) < 1 || len(source.Nodes) > multihoprelay.NodeChainMaximumMembers || len(source.IdentitySources) != len(source.Nodes) {
		return nil, nodeChainServerError
	}
	var sourceFields map[string]json.RawMessage
	if json.Unmarshal([]byte(sourceJSON), &sourceFields) != nil {
		return nil, nodeChainServerError
	}
	_, hasOpenVPNPairing := sourceFields["openvpn_pairing"]
	if openvpn != hasOpenVPNPairing || openvpn != (source.OpenVPNPairing != nil) {
		return nil, nodeChainServerError
	}
	if source.Schema == 2 && (len(source.Nodes) < 2 || source.IdentitySources[len(source.Nodes)-2] != "" || source.IdentitySources[len(source.Nodes)-1] == "") {
		return nil, nodeChainServerError
	}
	if (source.Schema == 3 || source.Schema == 4 || source.Schema == 5) && (len(source.Nodes) < 2 || source.IdentitySources[len(source.Nodes)-2] != "" || source.IdentitySources[len(source.Nodes)-1] == "") {
		return nil, nodeChainServerError
	}
	if multiple && (len(source.Nodes) < 2 || source.IdentitySources[len(source.Nodes)-1] == "") {
		return nil, nodeChainServerError
	}
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, nodeChainServerError
	}
	p := &NodeChainServerPolicy{sourceJSON: string(raw)}
	if multiple {
		p.multiple = &nodeChainMultipleImportedServerScope{members: make([]*nodeChainImportedMember, len(source.Nodes))}
	}
	domain := "routervpn-server-node-chain-source-v1"
	if source.Schema == 2 {
		domain = "routervpn-server-node-chain-source-v2"
	} else if source.Schema == 3 {
		domain = "routervpn-server-node-chain-source-v3"
	} else if source.Schema == 4 {
		domain = "routervpn-server-node-chain-source-v4"
	} else if source.Schema == 5 {
		domain = "routervpn-server-node-chain-source-v5"
	} else if source.Schema == 6 {
		domain = "routervpn-server-node-chain-source-v6"
	}
	digest, _ := json.Marshal([]string{domain, p.sourceJSON})
	p.sourceSHA = externalDigest(digest)
	clear(digest)
	p.descriptor = multihoprelay.NodeChainDescriptor{Schema: source.Schema, EntryID: source.EntryID, EntryNodeID: source.EntryNodeID,
		EntryMode: source.EntryMode, SourceSHA256: p.sourceSHA}
	members := make([]nodeChainGraphMember, 0, len(source.Nodes))
	closures := make([]*externalPredecessor, 0, len(source.Nodes))
	blocked := map[string]bool{}
	for index, launch := range source.Nodes {

		if openvpn && index == len(source.Nodes)-2 {
			middle, err := parseNodeChainOpenVPNMember(launch)
			if err != nil {
				return nil, err
			}
			pairSHA, err := nodeChainOpenVPNServerPair(middle, source.OpenVPNPairing)
			if err != nil {
				return nil, err
			}
			closure, err := middle.closure()
			if err != nil {
				return nil, err
			}
			ipv6, ranges, err := externalDevicePolicy(middle.selection.Profile)
			if err != nil {
				return nil, err
			}
			p.blockIPv6 = p.blockIPv6 || ipv6 == "off"
			for _, value := range ranges {
				blocked[value] = true
			}
			p.openvpnMiddle = middle
			p.openvpn = &nodeChainOpenVPNServerScope{policy: p, middle: middle, pair: *source.OpenVPNPairing, pairSHA: pairSHA}
			p.openvpn.self = p.openvpn
			p.nodes = append(p.nodes, nil)
			p.descriptor.Members = append(p.descriptor.Members, multihoprelay.NodeChainMember{Position: index + 1, ProfileID: middle.id(), Mode: "openvpn", StartLayer: "off", NodeKind: "external", ProofKind: "public-path", SourceSHA256: middle.source, ExpectedPublicIP: middle.selection.ExpectedPublicIP, OpenVPNPairSHA256: pairSHA})
			members = append(members, nodeChainGraphMember{profile: middle.selection.Profile, source: middle.source, mode: "openvpn", imported: true})
			closures = append(closures, closure)
			continue
		}

		if socks && index == len(source.Nodes)-2 {
			middle, err := parseNodeChainSOCKSMember(launch)
			if err != nil {
				return nil, err
			}
			closure, err := middle.closure()
			if err != nil {
				return nil, err
			}
			ipv6, ranges, err := externalDevicePolicy(middle.selection.Profile)
			if err != nil {
				return nil, err
			}
			p.blockIPv6 = p.blockIPv6 || ipv6 == "off"
			for _, value := range ranges {
				blocked[value] = true
			}
			p.socksMiddle = middle
			p.socks = &nodeChainSOCKSServerScope{policy: p, middle: middle}
			p.socks.self = p.socks
			p.nodes = append(p.nodes, nil)
			p.descriptor.Members = append(p.descriptor.Members, multihoprelay.NodeChainMember{Position: index + 1, ProfileID: middle.selection.ExitID, Mode: "socks5", StartLayer: "off", NodeKind: "external", ProofKind: "public-path", SourceSHA256: middle.source, ExpectedPublicIP: middle.selection.ExpectedPublicIP})
			members = append(members, nodeChainGraphMember{profile: middle.selection.Profile, source: middle.source, mode: "socks5", imported: true})
			closures = append(closures, closure)
			continue
		}
		if connect && index == len(source.Nodes)-2 {
			middle, err := parseNodeChainCONNECTMember(launch)
			if err != nil {
				return nil, nodeChainServerError
			}
			closure, err := middle.closure()
			if err != nil {
				return nil, err
			}
			ipv6, ranges, err := externalDevicePolicy(middle.selection.Profile)
			if err != nil {
				return nil, err
			}
			p.blockIPv6 = p.blockIPv6 || ipv6 == "off"
			for _, value := range ranges {
				blocked[value] = true
			}
			p.connectMiddle = middle
			p.connect = &nodeChainCONNECTServerScope{policy: p, middle: middle}
			p.connect.self = p.connect
			p.nodes = append(p.nodes, nil)
			p.descriptor.Members = append(p.descriptor.Members, multihoprelay.NodeChainMember{Position: index + 1, ProfileID: middle.selection.ExitID, Mode: middle.selection.Protocol, StartLayer: "off", NodeKind: "external", ProofKind: "public-path", SourceSHA256: middle.source, ExpectedPublicIP: middle.selection.ExpectedPublicIP})
			members = append(members, nodeChainGraphMember{profile: middle.selection.Profile, source: middle.source, mode: middle.selection.Protocol, imported: true})
			closures = append(closures, closure)
			continue
		}
		if source.Schema == 2 && index == len(source.Nodes)-2 || multiple && source.IdentitySources[index] == "" {
			middle, err := parseNodeChainImportedMember(launch)
			// The hostname resolver must retain a preceding paired packet node
			// in this suffix. The native worker retains every configured DNS
			// transport; this never grants ambient or direct hostname DNS.
			if err != nil || middle.validate() != nil ||
				!multiple && !nodeChainImportedExecutionMemberSupported(middle, len(source.Nodes)+1) ||
				multiple && (index == len(source.Nodes)-1 || middle.hostname != nil) {
				return nil, nodeChainServerError
			}
			closure, err := middle.closure()
			if err != nil {
				return nil, err
			}
			ipv6, ranges, err := externalDevicePolicy(middle.selection.Profile)
			if err != nil {
				return nil, err
			}
			p.blockIPv6 = p.blockIPv6 || ipv6 == "off"
			for _, value := range ranges {
				blocked[value] = true
			}
			if multiple {
				p.multiple.members[index] = middle
			} else {
				p.importedMiddle = middle
			}
			p.nodes = append(p.nodes, nil)
			p.descriptor.Members = append(p.descriptor.Members, multihoprelay.NodeChainMember{
				Position: index + 1, ProfileID: middle.id(), Mode: "shadowsocks", StartLayer: "off", NodeKind: "external", ProofKind: "public-path",
				SourceSHA256: middle.source, ExpectedPublicIP: middle.selection.ExpectedPublicIP})
			members = append(members, nodeChainGraphMember{profile: middle.selection.Profile, source: middle.source, mode: "shadowsocks", imported: true})
			closures = append(closures, closure)
			continue
		}
		node, err := ParseNodeLaunchInput(launch)
		if err != nil || node == nil || validateNodeChainIdentity(source.IdentitySources[index], node) != nil ||
			index < len(source.Nodes)-1 && !NodeChainPrefixMode(node.mode) || index == len(source.Nodes)-1 && !nodeChainServerFinalCapture(source.Schema, node) {
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

		} else if socks {
			// SOCKS carries the final's UDP through its negotiated association,
			// never through CONNECT's UoT-v2 final authority.
			if !nodeChainSOCKSServerFinalClosure(node, closure) {
				return nil, nodeChainServerError
			}
		} else if connect {
			// This family retains the original concrete final and its exact
			// source/key-bound UoT-v2 service, including independent Start Layers.
			if !nodeChainCONNECTServerFinalClosure(node, closure) {
				return nil, nodeChainServerError
			}
		} else if node.mode == "hysteria2" {
			if source.Schema != 1 || !nodeChainFinalClosure(node, closure) {
				return nil, nodeChainServerError
			}
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
	var expected []PhysicalEgress
	if p.openvpn != nil {
		last := len(p.nodes) - 1
		p.openvpn.final = p.nodes[last]
		p.openvpn.prefixes = append([]*NodeProfile(nil), p.nodes[:last-1]...)
		if len(p.openvpn.prefixes) == 0 {
			expected, err = p.openvpn.middle.policy.DirectPhysicalEgress([]string{"tcp", "udp"})
		} else {
			expected, err = p.openvpn.prefixes[0].PhysicalEgress()
		}
	} else if p.socks != nil {
		last := len(p.nodes) - 1
		p.socks.final = p.nodes[last]
		p.socks.prefixes = append([]*NodeProfile(nil), p.nodes[:last-1]...)
		p.socks.closures = append([]*externalPredecessor(nil), closures...)
		// Only the fixed control tuple exists at compilation. The UDP relay
		// is negotiated and retained by this family's native association owner.
		if len(p.socks.prefixes) == 0 {
			expected, err = p.socks.middle.policy.DirectPhysicalEgress([]string{"tcp"})
		} else {
			expected, err = p.socks.prefixes[0].PhysicalEgress()
		}
	} else if p.connect != nil {
		last := len(p.nodes) - 1
		p.connect.final = p.nodes[last]
		p.connect.prefixes = append([]*NodeProfile(nil), p.nodes[:last-1]...)
		capability, captureErr := importedCONNECTCapture(closures[last].graph, closures[last].final, "", p.nodes[last].mode, p.nodes[last].profile, p.nodes[last].inputs.Files)
		if captureErr != nil || capability != "uot-v2" {
			return nil, nodeChainServerError
		}
		p.connect.closures = append([]*externalPredecessor(nil), closures...)
		if len(p.connect.prefixes) == 0 {
			expected, err = p.connect.middle.policy.DirectPhysicalEgress([]string{"tcp"})
		} else {
			expected, err = p.connect.prefixes[0].PhysicalEgress()
		}
	} else if first := p.importedSSMemberAt(0); first != nil && p.nodes[0] == nil {
		expected, err = first.policy.DirectPhysicalEgress([]string{"tcp", "udp"})
	} else {
		expected, err = p.nodes[0].PhysicalEgress()
	}
	if err != nil {
		return nil, nodeChainServerError
	}
	if carrier != nil {
		if carrier.sourceSHA != p.sourceSHA || carrier.source != p.sourceJSON || carrier.apply(p.nodes[0], closures[0]) != nil {
			return nil, nodeChainServerCarrierError
		}
		p.carrier = carrier
		if p.openvpn != nil {
			p.openvpn.carrier = carrier
		}
		if p.socks != nil {
			p.socks.carrier = carrier
		}
		if p.connect != nil {
			p.connect.carrier = carrier
		}
	}
	if p.multiple != nil && p.multiple.freeze(p, closures) != nil {
		return nil, nodeChainServerError
	}
	var scope nodeChainCapturedTransportScope
	if p.connect != nil {
		scope = p.connect
	} else if p.socks != nil {
		scope = p.socks
	}
	config, proofs, dns, _, err := compileNodeChainClosuresWithServerScope(members, closures, expected, scope, p.multiple)
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
		if p.openvpn != nil && index == len(p.nodes)-2 {
			p.proofTargets = append(p.proofTargets, NodeChainServerProof{Proof: proof, Network: "tcp", Address: "1.1.1.1:443", ExpectedPublicIP: p.openvpn.middle.selection.ExpectedPublicIP})
			continue
		}
		if p.socks != nil && index == len(p.nodes)-2 {
			p.proofTargets = append(p.proofTargets, NodeChainServerProof{Proof: proof, Network: "tcp", Address: "1.1.1.1:443", ExpectedPublicIP: p.socks.middle.selection.ExpectedPublicIP})
			continue
		}
		if p.connect != nil && index == len(p.nodes)-2 {
			p.proofTargets = append(p.proofTargets, NodeChainServerProof{Proof: proof, Network: "tcp", Address: "1.1.1.1:443", ExpectedPublicIP: p.connect.middle.selection.ExpectedPublicIP})
			continue
		}
		if middle := p.importedSSMemberAt(index); middle != nil {
			p.proofTargets = append(p.proofTargets, NodeChainServerProof{Proof: proof, Network: "tcp", Address: "1.1.1.1:443",
				ExpectedPublicIP: middle.selection.ExpectedPublicIP})
			continue
		}
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

	if p.descriptor.Schema == 6 {
		if !p.multiple.original() || p.multiple.policy != p {
			return nodeChainServerError
		}
	} else if p.multiple != nil {
		return nodeChainServerError
	}
	if p.descriptor.Schema == 5 {
		if !p.openvpn.original() {
			return nodeChainServerError
		}
	} else if p.openvpn != nil || p.openvpnMiddle != nil {
		return nodeChainServerError
	}
	if p.descriptor.Schema == 3 {
		if !p.socks.original() || p.connect != nil {
			return nodeChainServerError
		}
	} else if p.socks != nil || p.socksMiddle != nil {
		return nodeChainServerError
	}
	if p.descriptor.Schema == 4 {
		if !p.connect.original() {
			return nodeChainServerError
		}
	} else if p.connect != nil {
		return nodeChainServerError
	}
	for index, node := range p.nodes {
		proof := p.proofs[index]
		if p.openvpn != nil && index == len(p.nodes)-2 {
			middle, target := p.openvpn.middle, p.proofTargets[index]
			if node != nil || proof.Position != index+1 || proof.SourceSHA256 != middle.source || proof.ProfileID != middle.id() || proof.NodeID != "" || proof.NodeKind != "external" || proof.Kind != "public-path" || proof.Mode != "openvpn" || proof.StartLayer != "off" || target.API != "" || target.Token != "" || target.Network != "tcp" || target.Address != "1.1.1.1:443" || target.ExpectedPublicIP != middle.selection.ExpectedPublicIP || p.descriptor.Members[index].OpenVPNPairSHA256 != p.openvpn.pairSHA {
				return nodeChainServerError
			}
			continue
		}
		if p.socks != nil && index == len(p.nodes)-2 {
			middle, target := p.socks.middle, p.proofTargets[index]
			if node != nil || proof.Position != index+1 || proof.SourceSHA256 != middle.source || proof.ProfileID != middle.selection.ExitID || proof.NodeID != "" || proof.NodeKind != "external" || proof.Kind != "public-path" || proof.Mode != "socks5" || proof.StartLayer != "off" || target.API != "" || target.Token != "" || target.Network != "tcp" || target.Address != "1.1.1.1:443" || target.ExpectedPublicIP != middle.selection.ExpectedPublicIP {
				return nodeChainServerError
			}
			continue
		}
		if p.connect != nil && index == len(p.nodes)-2 {
			middle, target := p.connect.middle, p.proofTargets[index]
			if node != nil || proof.Position != index+1 || proof.SourceSHA256 != middle.source || proof.ProfileID != middle.selection.ExitID || proof.NodeID != "" || proof.NodeKind != "external" || proof.Kind != "public-path" || proof.Mode != middle.selection.Protocol || proof.StartLayer != "off" || target.API != "" || target.Token != "" || target.Network != "tcp" || target.Address != "1.1.1.1:443" || target.ExpectedPublicIP != middle.selection.ExpectedPublicIP {
				return nodeChainServerError
			}
			continue
		}
		if middle := p.importedSSMemberAt(index); middle != nil {
			target := p.proofTargets[index]
			if node != nil || middle.validate() != nil || proof.Position != index+1 || proof.SourceSHA256 != middle.source ||
				proof.ProfileID != middle.id() || proof.NodeID != "" || proof.NodeKind != "external" || proof.Kind != "public-path" ||
				proof.Mode != "shadowsocks" || proof.StartLayer != "off" || target.API != "" || target.Token != "" ||
				target.Network != "tcp" || target.Address != "1.1.1.1:443" || target.ExpectedPublicIP != middle.selection.ExpectedPublicIP {
				return nodeChainServerError
			}
			continue
		}
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
		if proof.NodeKind == "external" {
			// This is the existing explicitly labelled public path benchmark,
			// scoped to the imported prefix. It grants no arbitrary hostname,
			// UDP relay or direct resolver; the worker retains selected DNS.
			route.Destinations = append(route.Destinations, NodeChainServerDestination{Network: "tcp", Address: hopmeasure.PublicAddress})
			route.PublicPathBenchmark = true
			route.BlockIPv6, route.BlockedCIDRs = p.blockIPv6, append([]string(nil), p.blockedCIDRs...)
		}
		if route.Final {
			route.UDPOverTCPVersion = 2
			route.BlockIPv6, route.BlockedCIDRs = p.blockIPv6, append([]string(nil), p.blockedCIDRs...)
			route.Destinations = append(route.Destinations, p.dns.Destinations...)
		}
		result[index] = route
	}
	return result, nil
}
