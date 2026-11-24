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
			if registry.members[i] == nil || registry.members[i].hostname != nil {
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
	if err := validateExtendedStreamClosures(closures[packets:]); err != nil {
		return err
	}
	for _, closure := range closures[packets:] {
		out := closure.final
		ip, err := netip.ParseAddr(predecessorText(out, "server"))
		port, ok := out["server_port"].(float64)
		if err != nil || !ok || !externalPort(port) || targets[netip.AddrPortFrom(ip, uint16(port))] {
			return nodeChainError
		}
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
