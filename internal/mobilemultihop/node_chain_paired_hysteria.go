package mobilemultihop

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
)

// This owner belongs to one complete Local source. It cannot authorize an
// append preparation or a selected Server/Compare projection.
type nodeChainPairedHysteriaLocal struct {
	self                                 *nodeChainPairedHysteriaLocal
	owner                                *NodeChain
	nodes                                []*NodeProfile
	source, sourceSHA, originalConfigSHA string
	proofs                               []NodeChainProof
	physical                             []PhysicalEgress
	frozen                               bool
}

// Shape is descriptive only. Construction validates every original companion,
// private node capture, literal closure, credential and physical dependency.
func pairedHysteriaLocalNodes(nodes []*NodeProfile) bool {
	if len(nodes) < 3 || len(nodes) > NodeChainExtendedLocalMaximumNodes || nodes[0] == nil ||
		!NodeChainPrefixMode(nodes[0].mode) {
		return false
	}
	found := false
	for position, node := range nodes {
		if node == nil || predecessorText(node.profile, "start_layer") != "" && predecessorText(node.profile, "start_layer") != "off" {
			return false
		}
		if position == len(nodes)-1 {
			if node.mode != "shadowsocks" && node.mode != "hysteria2" {
				return false
			}
		} else if !NodeChainPrefixMode(node.mode) && node.mode != "shadowsocks" && node.mode != "hysteria2" {
			return false
		}
		found = found || position > 0 && position < len(nodes)-1 && node.mode == "hysteria2"
	}
	return found
}

// An internal graph/MTU scan still validates the whole concrete graph. This
// predicate only describes its already captured private positional proof rows.
func pairedHysteriaLocalProofs(proofs []NodeChainProof) bool {
	if len(proofs) < 3 || len(proofs) > NodeChainExtendedLocalMaximumNodes || !NodeChainPrefixMode(proofs[0].Mode) {
		return false
	}
	found := false
	for position, proof := range proofs {
		if proof.Position != position || proof.StartLayer != "off" || proof.Kind != "" || proof.NodeKind != "" ||
			!proofID.MatchString(proof.SourceSHA256) || !proofID.MatchString(proof.NodeID) || !exactID.MatchString(proof.ProfileID) {
			return false
		}
		if position == len(proofs)-1 {
			if proof.Mode != "shadowsocks" && proof.Mode != "hysteria2" {
				return false
			}
		} else if !NodeChainPrefixMode(proof.Mode) && proof.Mode != "shadowsocks" && proof.Mode != "hysteria2" {
			return false
		}
		found = found || position > 0 && position < len(proofs)-1 && proof.Mode == "hysteria2"
	}
	return found
}

func (owner *nodeChainPairedHysteriaLocal) current(c *NodeChain) bool {
	return owner != nil && owner.self == owner && owner.frozen && owner.owner == c && c != nil &&
		c.pairedHysteria == owner && c.typedOriginal == nil && c.extendedPairedOwner == nil && c.importedNodes == nil && c.importedMiddle == nil &&
		c.importedOwners == nil && c.openVPNMiddle == nil && c.openVPNOwners == nil && c.socksSource == nil && c.connectSource == nil &&
		owner.source == c.sourceJSON && owner.sourceSHA == c.sourceSHA && owner.originalConfigSHA == c.originalConfigSHA &&
		slices.Equal(owner.nodes, c.nodes) && slices.Equal(owner.proofs, c.proofs) && nodeChainSamePhysical(owner.physical, c.physical) &&
		pairedHysteriaLocalNodes(c.nodes) && pairedHysteriaLocalProofs(c.proofs)
}

func (owner *nodeChainPairedHysteriaLocal) freeze(c *NodeChain) error {
	if owner == nil || owner.self != owner || owner.frozen || owner.owner != c || c == nil || c.pairedHysteria != owner ||
		owner.source != c.sourceJSON || owner.sourceSHA != c.sourceSHA || !slices.Equal(owner.nodes, c.nodes) ||
		!pairedHysteriaLocalProofs(c.proofs) || c.originalConfigSHA == "" {
		return nodeChainError
	}
	owner.proofs = slices.Clone(c.proofs)
	owner.physical = slices.Clone(c.physical)
	owner.originalConfigSHA = c.originalConfigSHA
	owner.frozen = true
	if !owner.current(c) {
		return nodeChainError
	}
	return nil
}

// PairedHysteriaLocalNodeCount is descriptive readback of a complete original
// source. Count or equal metadata cannot create this owner or a native route.
func (c *NodeChain) PairedHysteriaLocalNodeCount() int {
	if c == nil || c.pairedHysteria == nil || c.validateCapture() != nil {
		return 0
	}
	return len(c.nodes)
}

type nodeChainPairedHysteriaGraphScope struct {
	owner    *nodeChainPairedHysteriaLocal
	closures []*externalPredecessor
}

func (scope *nodeChainPairedHysteriaGraphScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor, physical []PhysicalEgress) error {
	if scope == nil || scope.owner == nil || scope.owner.self != scope.owner || scope.owner.frozen ||
		scope.owner.owner == nil || scope.owner.owner.pairedHysteria != scope.owner || scope.owner.owner.seal != "" || scope.owner.owner.config != "" ||
		scope.owner.source != scope.owner.owner.sourceJSON || scope.owner.sourceSHA != scope.owner.owner.sourceSHA ||
		!slices.Equal(scope.owner.nodes, scope.owner.owner.nodes) || !pairedHysteriaLocalNodes(scope.owner.nodes) ||
		len(members) != len(scope.owner.nodes) || len(closures) != len(members) || len(scope.closures) != len(members) {
		return nodeChainError
	}
	for position, node := range scope.owner.nodes {
		if node.validateNodeDesktopCapture() != nil || closures[position] == nil || closures[position] != scope.closures[position] ||
			members[position].imported || members[position].externalHome || members[position].mode != node.mode ||
			members[position].source != node.source || !reflect.DeepEqual(members[position].profile, node.profile) {
			return nodeChainError
		}
	}
	expected, err := scope.owner.nodes[0].PhysicalEgress()
	if err != nil || !nodeChainSamePhysical(expected, physical) {
		return errors.Join(err, nodeChainError)
	}
	return nil
}

func (scope *nodeChainPairedHysteriaGraphScope) admitsProxy(position int, closure *externalPredecessor, mode string) bool {
	if scope == nil || scope.owner == nil || scope.owner.self != scope.owner || scope.owner.frozen ||
		scope.owner.owner == nil || scope.owner.owner.pairedHysteria != scope.owner || scope.owner.owner.seal != "" || scope.owner.owner.config != "" ||
		scope.owner.source != scope.owner.owner.sourceJSON || scope.owner.sourceSHA != scope.owner.owner.sourceSHA ||
		!slices.Equal(scope.owner.nodes, scope.owner.owner.nodes) || position <= 0 ||
		position >= len(scope.owner.nodes) || position >= len(scope.closures) || scope.closures[position] != closure ||
		scope.owner.nodes[position] == nil || scope.owner.nodes[position] != scope.owner.owner.nodes[position] ||
		scope.owner.nodes[position].mode != mode {
		return false
	}
	if mode == "hysteria2" {
		return nodeChainCapturedHysteriaClosure(scope.owner.nodes[position], closure)
	}
	return mode == "shadowsocks" && nodeChainCapturedSSClosure(closure)
}

func compileNodeChainPairedHysteria(c *NodeChain) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	fail := func(err error) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
		return "", nil, NodeChainDNSCapture{}, nil, errors.Join(err, nodeChainError)
	}
	if c == nil || c.pairedHysteria != nil || c.importedNodes != nil || c.importedMiddle != nil || c.openVPNMiddle != nil ||
		c.socksSource != nil || c.connectSource != nil || !pairedHysteriaLocalNodes(c.nodes) {
		return fail(nil)
	}
	var record NodeChainSource
	if exactJSON([]byte(c.sourceJSON), &record, NodeChainInputLimit) != nil || record.Schema != 1 || record.Execution != "local" ||
		len(record.Nodes) != len(c.nodes) || len(record.IdentitySources) != len(c.nodes) || slices.Contains(record.IdentitySources, "") {
		return fail(nil)
	}
	closures := make([]*externalPredecessor, len(c.nodes))
	members := make([]nodeChainGraphMember, len(c.nodes))
	targets := make(map[netip.AddrPort]bool)
	packetKeys := make(map[string]bool)
	var proxies []*externalPredecessor
	for position, node := range c.nodes {
		if node.validateNodeDesktopCapture() != nil || validateNodeChainIdentity(record.IdentitySources[position], node) != nil {
			return fail(nil)
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil || closure == nil || closure.final == nil || len(closure.nodes) != 1 {
			return fail(err)
		}
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return fail(nil)
		}
		switch node.mode {
		case "shadowsocks":
			if !nodeChainFinalClosure(node, closure) || !nodeChainCapturedSSClosure(closure) {
				return fail(nil)
			}
			proxies = append(proxies, closure)
		case "hysteria2":
			if !nodeChainCapturedHysteriaClosure(node, closure) {
				return fail(nil)
			}
			proxies = append(proxies, closure)
		default:
			if !NodeChainPrefixMode(node.mode) || closure.final["type"] != nodeChainPrefixType(node.mode) ||
				closure.final["detour"] != nil || closure.final["domain_resolver"] != nil {
				return fail(nil)
			}
			client, server, err := nodeChainPacketKeys(node)
			if err != nil || client == server || packetKeys[client] || packetKeys[server] {
				return fail(err)
			}
			packetKeys[client], packetKeys[server] = true, true
			sockets, err := node.PhysicalEgress()
			if err != nil || len(sockets) == 0 {
				return fail(err)
			}
			for _, socket := range sockets {
				ip, err := netip.ParseAddr(socket.Host)
				if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || socket.Port < 1 || socket.Port > 65535 {
					return fail(err)
				}
				target := netip.AddrPortFrom(ip, uint16(socket.Port))
				if targets[target] {
					return fail(pairedStreamConflict)
				}
				targets[target] = true
			}
		}
		closures[position] = closure
		members[position] = nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode}
	}
	if err := validateNodeChainCapturedProxyTargets(proxies, targets); err != nil {
		return fail(err)
	}
	if err := validateNodeChainCapturedHybridKeys(closures); err != nil {
		return fail(err)
	}
	physical, err := c.nodes[0].PhysicalEgress()
	if err != nil {
		return fail(err)
	}
	owner := &nodeChainPairedHysteriaLocal{owner: c, nodes: slices.Clone(c.nodes), source: c.sourceJSON, sourceSHA: c.sourceSHA}
	owner.self = owner
	c.pairedHysteria = owner
	scope := &nodeChainPairedHysteriaGraphScope{owner: owner, closures: slices.Clone(closures)}
	config, proofs, dns, egress, err := compileNodeChainGraphWithOwnedScopes(members, closures, physical, nil, nil, nil, nil, nil, scope)
	if err != nil || !nodeChainSamePhysical(physical, egress) {
		return fail(err)
	}
	if len(c.nodes) > NodeChainMaximumNodes && len(config) > NodeChainInputLimit/len(c.nodes) {
		return fail(nil)
	}
	return config, proofs, dns, egress, nil
}
