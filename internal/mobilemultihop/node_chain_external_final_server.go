package mobilemultihop

import (
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"sync/atomic"

	"router-vpn/internal/multihoprelay"
)

// This worker owns only the independent stream suffix. It has no paired
// packet interface, private health target or credential for the client entry.
type nodeChainExternalFinalServerScope struct {
	original *nodeChainRegisteredServerSnapshot
	bound    atomic.Pointer[nodeChainRegisteredCaptureBinding]
	owner    *NodeChainServerPolicy
	members  []*nodeChainImportedMember
}

// Checked once from the canonical registered graph. Retain independent copies
// of every mutable value that participated in its original policy seal.
type nodeChainRegisteredServerSnapshot struct {
	source, sourceSHA, config, configSHA, seal string
	descriptor                                 multihoprelay.NodeChainDescriptor
	dns                                        NodeChainServerDNSCapture
	blockIPv6                                  bool
	cidrs                                      []string
	members                                    []*nodeChainImportedMember
	proofs                                     []NodeChainProof
	targets                                    []NodeChainServerProof
}

type nodeChainRegisteredCaptureBinding struct {
	capture multihoprelay.NodeChainCapture
	binding NodeChainServerBinding
}

func snapshotRegisteredServer(p *NodeChainServerPolicy, members []*nodeChainImportedMember) *nodeChainRegisteredServerSnapshot {
	dns := p.dns
	dns.Destinations = slices.Clone(dns.Destinations)
	if dns.EntryHome != nil {
		home := *dns.EntryHome
		dns.EntryHome = &home
	}
	return &nodeChainRegisteredServerSnapshot{
		source: p.sourceJSON, sourceSHA: p.sourceSHA, config: p.config, configSHA: p.configSHA, seal: p.seal,
		descriptor: p.descriptor.Clone(), dns: dns, blockIPv6: p.blockIPv6, cidrs: slices.Clone(p.blockedCIDRs),
		members: slices.Clone(members), proofs: slices.Clone(p.proofs), targets: slices.Clone(p.proofTargets),
	}
}

func (o *nodeChainRegisteredServerSnapshot) matches(p *NodeChainServerPolicy, members []*nodeChainImportedMember) bool {
	return o != nil && p.seal == o.seal && p.sourceJSON == o.source && p.sourceSHA == o.sourceSHA &&
		p.config == o.config && p.configSHA == o.configSHA && p.blockIPv6 == o.blockIPv6 &&
		p.carrier == nil && p.openvpn == nil && p.socks == nil && p.connect == nil && p.importedMiddle == nil &&
		p.socksMiddle == nil && p.openvpnMiddle == nil && p.connectMiddle == nil &&
		sameTypedSlice(p.blockedCIDRs, o.cidrs) && sameTypedSlice(members, o.members) && sameTypedSlice(p.proofs, o.proofs) &&
		sameTypedSlice(p.proofTargets, o.targets) && reflect.DeepEqual(p.descriptor, o.descriptor) && reflect.DeepEqual(p.dns, o.dns)
}

func (s *nodeChainExternalFinalServerScope) matches(p *NodeChainServerPolicy) bool {
	return s.owner == p && p.externalFinal == s && p.multiple == nil && s.original.matches(p, s.members) && s.current(p)
}

func (s *nodeChainExternalFinalServerScope) current(p *NodeChainServerPolicy) bool {
	if s == nil || s.owner != p || p.externalFinal != s || p.descriptor.Schema != 8 || p.descriptor.ExternalFinal == nil || p.carrier != nil || len(s.members) != len(p.descriptor.Members) || len(s.members) != len(p.nodes) {
		return false
	}
	for i, m := range s.members {
		d := p.descriptor.Members[i]
		if p.nodes[i] != nil || m == nil || m.hostname != nil || m.validate() != nil || d.ProfileID != m.id() || d.SourceSHA256 != m.source || d.ExpectedPublicIP != m.selection.ExpectedPublicIP {
			return false
		}
	}
	return true
}

func NewNodeChainExternalFinalServerPolicy(input string) (*NodeChainServerPolicy, error) {
	bad := nodeChainServerError
	var source nodeChainExternalFinalServerSource
	var fields map[string]any
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || exactJSON([]byte(input), &fields, NodeChainInputLimit) != nil || !nodeChainPlanKeys(fields, []string{"schema", "entry_id", "entry_node_id", "entry_mode", "external_final", "nodes", "dns_policy", "entry_block_ipv6", "entry_blocked_cidrs"}, nil) || source.Schema != 8 || len(source.Nodes) < 2 || len(source.Nodes) >= NodeChainExtendedLocalMaximumNodes || source.EntryBlockedCIDRs == nil || len(source.EntryBlockedCIDRs) > 32 {
		return nil, bad
	}
	original, err := json.Marshal(source)
	if err != nil || len(original) > NodeChainInputLimit {
		return nil, bad
	}
	digest, err := json.Marshal([]string{"routervpn-server-node-chain-source-v8", string(original)})
	if err != nil {
		return nil, err
	}
	p := &NodeChainServerPolicy{sourceJSON: string(original), sourceSHA: externalDigest(digest), nodes: make([]*NodeProfile, len(source.Nodes))}
	clear(original)
	clear(digest)
	p.externalFinal = &nodeChainExternalFinalServerScope{owner: p}
	p.descriptor = multihoprelay.NodeChainDescriptor{Schema: 8, EntryID: source.EntryID, EntryNodeID: source.EntryNodeID, EntryMode: source.EntryMode, SourceSHA256: p.sourceSHA, ExternalFinal: &source.ExternalFinal}
	// Revalidate canonical private CIDRs with the same policy used by Local.
	restriction := map[string]any{"home_lan_access": len(source.EntryBlockedCIDRs) == 0}
	var ranges []any
	for _, cidr := range source.EntryBlockedCIDRs {
		ranges = append(ranges, cidr)
	}
	if len(ranges) > 0 {
		restriction["home_lan_cidrs"] = ranges
	}
	if source.EntryBlockIPv6 {
		restriction["ipv6_mode"] = "off"
	}
	_, entryBlocked, err := externalDevicePolicy(restriction)
	if err != nil || !reflect.DeepEqual(source.EntryBlockedCIDRs, entryBlocked) {
		return nil, bad
	}
	profiles := []map[string]any{restriction}
	members := make([]nodeChainGraphMember, len(source.Nodes))
	closures := make([]*externalPredecessor, len(source.Nodes))
	for i, input := range source.Nodes {
		m, err := parseNodeChainImportedMember(input)
		if err != nil || m.hostname != nil {
			return nil, bad
		}
		closures[i], err = m.closure()
		if err != nil || m.rememberMultipleImportedMember() != nil {
			return nil, bad
		}
		p.externalFinal.members = append(p.externalFinal.members, m)
		p.descriptor.Members = append(p.descriptor.Members, multihoprelay.NodeChainMember{Position: i + 1, ProfileID: m.id(), Mode: "shadowsocks", StartLayer: "off", NodeKind: "external", ProofKind: "public-path", SourceSHA256: m.source, ExpectedPublicIP: m.selection.ExpectedPublicIP})
		members[i] = nodeChainGraphMember{profile: m.selection.Profile, source: m.source, mode: "shadowsocks", imported: true}
		profiles = append(profiles, m.selection.Profile)
	}
	if err := validateExtendedStreamTargets(closures, map[netip.AddrPort]bool{}, nil); err != nil {
		return nil, err
	}
	ipv6, blocked, err := externalDevicePolicy(profiles...)
	if err != nil {
		return nil, err
	}
	p.blockIPv6, p.blockedCIDRs = ipv6 == "off", blocked
	last := len(members) - 1
	final := p.externalFinal.members[last]
	transport, err := externalFinalStreamCommitment(final)
	if err != nil || transport != source.ExternalFinal.FinalTransportSHA256 {
		return nil, bad
	}
	var registered map[string]any
	if exactJSON(source.DNSPolicy, &registered, NodeChainInputLimit) != nil {
		return nil, bad
	}
	dns, home, err := externalFinalWorkerResolver(final.selection, ipv6, source.ExternalFinal.DNSOwner, p.sourceSHA, registered)
	if err != nil {
		return nil, err
	}
	policyRaw, err := json.Marshal(dns)
	if err != nil || string(policyRaw) != string(source.DNSPolicy) {
		return nil, bad
	}
	p.descriptor.DNSPolicySHA256 = externalDigest(policyRaw)
	if p.descriptor.Validate() != nil {
		return nil, bad
	}
	closures[last].graph["dns"] = dns
	for _, r := range dns["servers"].([]any) {
		row := r.(map[string]any)
		closures[last].resolvers[predecessorText(row, "tag")] = row
	}
	expected, err := p.externalFinal.members[0].policy.DirectPhysicalEgress([]string{"tcp", "udp"})
	if err != nil {
		return nil, err
	}
	if home != nil {
		addr, err := netip.ParseAddrPort(home.Address)
		if err != nil {
			return nil, bad
		}
		expected = append(expected, PhysicalEgress{addr.Addr().String(), int(addr.Port()), home.Network})
		sortPhysicalEgress(expected)
	}
	config, proofs, selected, _, err := compileNodeChainGraphWithHome(members, closures, expected, nil, nil, nil, home)
	if err != nil {
		return nil, err
	}
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return nil, bad
	}
	graph["inbounds"] = []any{}
	route := graph["route"].(map[string]any)
	route["rules"], route["final"] = []any{}, selected.FinalTag
	rows := graph["outbounds"].([]any)
	kept := make([]any, 0, len(rows)-1)
	for _, row := range rows {
		if row.(map[string]any)["tag"] != SelectorTag {
			kept = append(kept, row)
		}
	}
	graph["outbounds"] = kept
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 || len(raw) > NodeChainInputLimit/len(members) {
		return nil, bad
	}
	p.config, p.configSHA = string(raw), externalDigest(raw)
	for i, proof := range proofs {
		proof.Position = i + 1
		p.proofs = append(p.proofs, proof)
		p.proofTargets = append(p.proofTargets, NodeChainServerProof{Proof: proof, Network: "tcp", Address: "1.1.1.1:443", ExpectedPublicIP: p.descriptor.Members[i].ExpectedPublicIP})
	}
	router, err := json.Marshal(graph["dns"])
	if err != nil {
		return nil, err
	}
	p.dns = NodeChainServerDNSCapture{EntryHome: home, PolicySHA256: p.descriptor.DNSPolicySHA256, PolicyJSON: string(policyRaw), RouterJSON: string(router), ResolverTag: selected.ResolverTag, ResolverSHA256: selected.ResolverSHA256, FinalTag: selected.FinalTag}
	for _, item := range registered["servers"].([]any) {
		row := item.(map[string]any)
		port, ok := row["server_port"].(float64)
		if !ok || !externalPort(port) {
			return nil, bad
		}
		network := "tcp"
		if row["type"] == "udp" || row["type"] == "h3" {
			network = "udp"
		}
		p.dns.Destinations = append(p.dns.Destinations, NodeChainServerDestination{network, net.JoinHostPort(predecessorText(row, "server"), strconv.Itoa(int(port)))})
	}
	p.seal = p.captureSeal()
	if p.validateCapture() != nil {
		return nil, bad
	}
	p.externalFinal.original = snapshotRegisteredServer(p, p.externalFinal.members)
	return p, nil
}
