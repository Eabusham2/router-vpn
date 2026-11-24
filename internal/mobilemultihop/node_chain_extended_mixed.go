package mobilemultihop

import (
	"encoding/json"
	"net/netip"
)

// A deeper Local schema-six route has an unbroken packet prefix, literal
// independently keyed Shadowsocks imports and a paired Shadowsocks final.
// Raw captures establish every transport before graph composition adds detours.
func extendedImportedLocalClosures(registry *nodeChainImportedNodes, nodes []*NodeProfile, closures []*externalPredecessor) error {
	last := len(nodes) - 1
	if registry == nil || registry.customEntry || last <= 0 || len(closures) != len(nodes) || len(registry.members) != len(nodes) || nodes[last] == nil || nodes[last].mode != "shadowsocks" {
		return nodeChainError
	}
	packets := 0
	targets := map[netip.AddrPort]bool{}
	for packets < last && nodes[packets] != nil && NodeChainPrefixMode(nodes[packets].mode) {
		n, closure := nodes[packets], closures[packets]
		layer := predecessorText(n.profile, "start_layer")
		if layer != "" && layer != "off" || !NodeChainPrefixMode(n.mode) || registry.members[packets] != nil || closure == nil || closure.final == nil || closure.final["type"] != nodeChainPrefixType(n.mode) || closure.final["detour"] != nil {
			return nodeChainError
		}
		sockets, err := n.PhysicalEgress()
		if err != nil || len(sockets) != 1 {
			return nodeChainError
		}
		s := sockets[0]
		ip, err := netip.ParseAddr(s.Host)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || s.Port < 1 || s.Port > 65535 || s.Network != "udp" {
			return nodeChainError
		}
		target := netip.AddrPortFrom(ip, uint16(s.Port))
		if targets[target] {
			return nodeChainError
		}
		targets[target] = true
		packets++
	}
	if packets == 0 || packets >= last {
		return nodeChainError
	}
	imports := 0
	for i := packets; i < last; i++ {
		if node := nodes[i]; node != nil {
			layer := predecessorText(node.profile, "start_layer")
			if registry.members[i] != nil || node.mode != "shadowsocks" || layer != "" && layer != "off" {
				return nodeChainError
			}
		} else {
			if registry.members[i] == nil || registry.members[i].hostname != nil && (i != packets || len(nodes) < 4) {
				return nodeChainError
			}
			imports++
		}
	}
	if imports == 0 {
		return nodeChainError
	}
	layer := predecessorText(nodes[last].profile, "start_layer")
	if layer != "" && layer != "off" {
		return nodeChainError
	}
	var hostname *externalPredecessor
	if m := registry.members[packets]; m != nil && m.hostname != nil {
		hostname = closures[packets]
	}
	if err := validateExtendedStreamTargets(closures[packets:], targets, hostname); err != nil {
		return err
	}

	return nil
}

// Original roles retain an independent source hash at every position. A
// caller cannot promote the published prefix count to route authority.
func extendedImportedPacketCount(proofs []NodeChainProof) int {
	n := len(proofs)
	if n <= NodeChainMaximumNodes || n > NodeChainExtendedLocalMaximumNodes {
		return 0
	}
	packets, imports := 0, 0
	for i, p := range proofs {
		if p.Position != i || p.StartLayer != "off" || !proofID.MatchString(p.SourceSHA256) || !exactID.MatchString(p.ProfileID) {
			return 0
		}
		paired := p.Kind == "" && p.NodeKind == "" && proofID.MatchString(p.NodeID)
		if i == n-1 {
			if !paired || p.Mode != "shadowsocks" || packets == 0 || packets == i || imports == 0 {
				return 0
			}
			return packets
		}
		if paired && packets == i && NodeChainPrefixMode(p.Mode) {
			packets++
			continue
		}
		if paired && p.Mode == "shadowsocks" && packets > 0 {
			continue
		}
		if p.Mode != "shadowsocks" || p.Kind != "public-path" || p.NodeKind != "external" || p.NodeID != "" {
			return 0
		}
		imports++
	}
	return 0
}

// ExtendedMixedLocalPacketCount exposes the authenticated boundary only for
// the new mixed Local family. Legacy one-WG routes keep their existing wire.
func (c *NodeChain) ExtendedMixedLocalPacketCount() int {
	if c == nil || c.importedNodes == nil || c.importedNodes.customEntry || c.validateCapture() != nil {
		return 0
	}
	p := extendedImportedPacketCount(c.proofs)
	if p == 1 && c.proofs[0].Mode == "wg" && !c.hasPairedStreamInteriorValidated() {
		return 0
	}
	return p
}

// HasPairedStreamInterior distinguishes the Local-only source family from
// ordinary imported graphs which have a separately qualified remote runtime.
func (c *NodeChain) HasPairedStreamInterior() bool {
	return c != nil && c.validateCapture() == nil && c.hasPairedStreamInteriorValidated()
}
func (c *NodeChain) hasPairedStreamInteriorValidated() bool {
	if c.importedNodes == nil || c.importedNodes.customEntry {
		return false
	}
	for i := 1; i < len(c.nodes)-1; i++ {
		if c.nodes[i] != nil && c.nodes[i].mode == "shadowsocks" {
			return true
		}
	}
	return false
}

// This exact native inventory binds long Local latency and speed results to
// their independently authenticated private or public proof at each position.
func (c *NodeChain) ExtendedLocalRolesJSON() string {
	count := c.ExtendedLocalNodeCount()
	if count <= NodeChainMaximumNodes {
		return ""
	}
	roles := make([]string, count)
	for i := range roles {
		roles[i] = "private-node"
		if c.importedSSMemberAt(i) != nil {
			roles[i] = "public-path"
		}
	}
	raw, _ := json.Marshal(roles)
	return string(raw)
}

const nodeChainOriginalPeerExclusions = "routervpn_original_peer_exclusions"

func (r *nodeChainImportedNodes) hasHostname() bool {
	for _, m := range r.members {
		if m != nil && m.hostname != nil {
			return true
		}
	}
	return false
}

// The validated original graph includes all suffix sockets. No shortened
// preparation may recompute the exclusions from only its surviving members.
func (c *NodeChain) originalHostnameExclusions(position int) ([]string, error) {
	if c.importedNodes == nil || c.importedSSMemberAt(position) == nil || c.importedSSMemberAt(position).hostname == nil {
		return nil, nodeChainError
	}
	var graph struct {
		Outbounds []struct {
			Tag      string   `json:"tag"`
			Excluded []string `json:"routervpn_original_peer_exclusions"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(c.config), &graph); err != nil {
		return nil, err
	}
	for _, out := range graph.Outbounds {
		if out.Tag == c.proofs[position].Tag && out.Excluded != nil {
			return out.Excluded, nil
		}
	}
	return nil, nodeChainError
}
