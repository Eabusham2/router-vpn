package mobilemultihop

import (
	"net/netip"

	"router-vpn/internal/multihoprelay"
)

// Family 7 is a co-located, paired SS entry and an all-SS unfinished prefix.
// The original Local schema-3 capture owns the real physical entry. Its
// companion identifies the node but is never an active packet transport pin.
func nodeChainPrefixProxyEntrySchemas(nodes []*NodeProfile, nextMode string) (int, int, error) {
	if len(nodes) < 1 || len(nodes) > multihoprelay.NodeChainPrefixMaximumMembers || nextMode != "shadowsocks" {
		return 0, 0, errNodeChainAppendExecution
	}
	for _, node := range nodes {
		if node == nil || node.mode != "shadowsocks" || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
			return 0, 0, errNodeChainAppendExecution
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil || !nodeChainCapturedSSClosure(closure) {
			return 0, 0, errNodeChainAppendExecution
		}
	}
	if _, err := nodeChainPrefixProxyEntryPeers(nodes[0]); err != nil {
		return 0, 0, err
	}
	return 3, 7, nil
}

func nodeChainPrefixProxyEntryMember(node *NodeProfile, identity string) (multihoprelay.NodeChainPrefixMember, error) {
	if node == nil || node.mode != "shadowsocks" {
		return multihoprelay.NodeChainPrefixMember{}, errNodeChainAppendExecution
	}
	// Reuse the exact existing SS transport and whole companion commitment.
	// Only this separately typed entry may occupy position zero.
	member, err := nodeChainPrefixCapturedMember(node, identity, 1, 2)
	if err != nil {
		return multihoprelay.NodeChainPrefixMember{}, err
	}
	member.Position = 0
	return member, nil
}

// The first supported proxy entry is the actual paired service co-located with
// its private Router API. The existing authenticated HTTP handler observes the
// peer; a changed route/source address refuses, never substitutes a WG address
// or opens a direct connection. No listen address or route is created here.
func nodeChainPrefixProxyEntryPeers(node *NodeProfile) ([]string, error) {
	if node == nil || node.mode != "shadowsocks" || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
		return nil, errNodeChainAppendExecution
	}
	if _, err := nodeChainPrefixStreamPhysical(node, 7); err != nil {
		return nil, err
	}
	api, err := privateAPI(predecessorText(node.profile, "router_api"))
	if err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(api.Hostname())
	if err != nil || address.Zone() != "" || !address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() || address.IsLinkLocalUnicast() {
		return nil, errNodeChainAppendExecution
	}
	return []string{address.Unmap().String()}, nil
}

func (p *NodeChainCandidateAppendExecutionPolicy) proxyEntryPeerMatches(peers []string) bool {
	if p == nil || p.original == nil || p.original.appendSource == nil || len(p.original.appendSource.nodes) == 0 {
		return false
	}
	expected, err := nodeChainPrefixProxyEntryPeers(p.original.appendSource.nodes[0])
	return err == nil && len(peers) == 1 && peers[0] == expected[0]
}

func nodeChainPrefixPlanEntry(entry *nodeChainPlanNode, proxy bool) (multihoprelay.NodeChainPrefixMember, []string, error) {
	var empty multihoprelay.NodeChainPrefixMember
	if entry == nil || entry.node == nil || !packetPairLayerOff(entry.node) {
		return empty, nil, errNodeChainAppendExecution
	}
	if proxy {
		member, err := nodeChainPrefixProxyEntryMember(entry.node, entry.identity)
		if err != nil {
			return empty, nil, err
		}
		peers, err := nodeChainPrefixProxyEntryPeers(entry.node)
		return member, peers, err
	}
	if !NodeChainPrefixMode(entry.mode) {
		return empty, nil, errNodeChainAppendExecution
	}
	member, err := nodeChainPrefixPacketMember(entry.node, 0)
	if err != nil {
		return empty, nil, err
	}
	peers, err := externalFinalPacketPeerAddresses(entry.node)
	return member, peers, err
}

func nodeChainPrefixCatalogDomain(schema int) string {
	if schema == 2 {
		return "routervpn-node-chain-prefix-selection-catalog-v2"
	}
	return "routervpn-node-chain-prefix-selection-catalog-v1"
}
