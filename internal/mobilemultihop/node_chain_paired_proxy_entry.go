package mobilemultihop

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
)

// This owner belongs to one complete all-paired Local path whose actual first
// transport is a literal Off SS/HY2 proxy. It grants neither append preparation
// nor selected Server/Compare authority, and never borrows a two-node owner.
type nodeChainPairedProxyEntryLocal struct {
	self                                 *nodeChainPairedProxyEntryLocal
	owner                                *NodeChain
	nodes                                []*NodeProfile
	source, sourceSHA, originalConfigSHA string
	proofs                               []NodeChainProof
	physical                             []PhysicalEgress
	frozen                               bool
}

// Shape is descriptive only. Construction validates every original companion,
// private node capture, literal closure, credential and physical dependency.
func pairedProxyEntryPrefixNodes(nodes []*NodeProfile) bool {
	if len(nodes) < 1 || len(nodes) > NodeChainExtendedLocalMaximumNodes || nodes[0] == nil || !nodeChainAppendProxyMode(nodes[0].mode) {
		return false
	}
	for _, node := range nodes {
		if node == nil || predecessorText(node.profile, "start_layer") != "" && predecessorText(node.profile, "start_layer") != "off" {
			return false
		}
		if nodeChainAppendProxyMode(node.mode) {
			address, err := netip.ParseAddr(predecessorText(node.profile, "endpoint"))
			if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
				return false
			}
		} else if !NodeChainPrefixMode(node.mode) {
			return false
		}
	}
	return true
}

func pairedProxyEntryLocalNodes(nodes []*NodeProfile) bool {
	return len(nodes) >= 2 && pairedProxyEntryPrefixNodes(nodes) && nodeChainAppendProxyMode(nodes[len(nodes)-1].mode)
}

// An internal graph/MTU scan still validates the whole concrete graph. This
// predicate only describes its already captured private positional proof rows.
func pairedProxyEntryLocalProofs(proofs []NodeChainProof) bool {
	if len(proofs) < 2 || len(proofs) > NodeChainExtendedLocalMaximumNodes || !nodeChainAppendProxyMode(proofs[0].Mode) {
		return false
	}
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
	}
	return true
}

func (owner *nodeChainPairedProxyEntryLocal) current(c *NodeChain) bool {
	return owner != nil && owner.self == owner && owner.frozen && owner.owner == c && c != nil &&
		c.pairedProxyEntry == owner && c.pairedHysteria == nil && c.typedOriginal == nil && c.extendedPairedOwner == nil && c.importedNodes == nil && c.importedMiddle == nil &&
		c.importedOwners == nil && c.openVPNMiddle == nil && c.openVPNOwners == nil && c.socksSource == nil && c.connectSource == nil &&
		owner.source == c.sourceJSON && owner.sourceSHA == c.sourceSHA && owner.originalConfigSHA == c.originalConfigSHA &&
		slices.Equal(owner.nodes, c.nodes) && slices.Equal(owner.proofs, c.proofs) && nodeChainSamePhysical(owner.physical, c.physical) &&
		pairedProxyEntryLocalNodes(c.nodes) && pairedProxyEntryLocalProofs(c.proofs)
}

func (owner *nodeChainPairedProxyEntryLocal) freeze(c *NodeChain) error {
	if owner == nil || owner.self != owner || owner.frozen || owner.owner != c || c == nil || c.pairedProxyEntry != owner ||
		owner.source != c.sourceJSON || owner.sourceSHA != c.sourceSHA || !slices.Equal(owner.nodes, c.nodes) ||
		!pairedProxyEntryLocalProofs(c.proofs) || c.originalConfigSHA == "" {
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

// PairedProxyEntryLocalNodeCount is descriptive readback of a complete original
// source. Count or equal metadata cannot create this owner or a native route.
func (c *NodeChain) PairedProxyEntryLocalNodeCount() int {
	if c == nil || c.pairedProxyEntry == nil || c.validateCapture() != nil {
		return 0
	}
	return len(c.nodes)
}

// Only the two private complete-source constructors implement this compiler
// scope. Each validates its original owner and concrete closure pointers.
type nodeChainCompleteLocalScope interface {
	validate([]nodeChainGraphMember, []*externalPredecessor, []PhysicalEgress) error
	admitsProxy(int, *externalPredecessor, string) bool
}

type nodeChainPairedProxyEntryGraphScope struct {
	owner    *nodeChainPairedProxyEntryLocal
	closures []*externalPredecessor
}

func (scope *nodeChainPairedProxyEntryGraphScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor, physical []PhysicalEgress) error {
	if scope == nil || scope.owner == nil || scope.owner.self != scope.owner || scope.owner.frozen ||
		scope.owner.owner == nil || scope.owner.owner.pairedProxyEntry != scope.owner || scope.owner.owner.seal != "" || scope.owner.owner.config != "" ||
		scope.owner.source != scope.owner.owner.sourceJSON || scope.owner.sourceSHA != scope.owner.owner.sourceSHA ||
		!slices.Equal(scope.owner.nodes, scope.owner.owner.nodes) || !pairedProxyEntryLocalNodes(scope.owner.nodes) ||
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

func (scope *nodeChainPairedProxyEntryGraphScope) admitsProxy(position int, closure *externalPredecessor, mode string) bool {
	if scope == nil || scope.owner == nil || scope.owner.self != scope.owner || scope.owner.frozen ||
		scope.owner.owner == nil || scope.owner.owner.pairedProxyEntry != scope.owner || scope.owner.owner.seal != "" || scope.owner.owner.config != "" ||
		scope.owner.source != scope.owner.owner.sourceJSON || scope.owner.sourceSHA != scope.owner.owner.sourceSHA ||
		!slices.Equal(scope.owner.nodes, scope.owner.owner.nodes) || position < 0 ||
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

func compileNodeChainPairedProxyEntry(c *NodeChain) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	fail := func(err error) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
		return "", nil, NodeChainDNSCapture{}, nil, errors.Join(err, nodeChainError)
	}
	if c == nil || c.pairedProxyEntry != nil || c.pairedHysteria != nil || c.typedOriginal != nil || c.extendedPairedOwner != nil || c.importedNodes != nil || c.importedMiddle != nil || c.openVPNMiddle != nil ||
		c.socksSource != nil || c.connectSource != nil || !pairedProxyEntryLocalNodes(c.nodes) {
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
	if err := validateNodeChainCapturedTransportKeys(closures); err != nil {
		return fail(err)
	}
	physical, err := c.nodes[0].PhysicalEgress()
	if err != nil {
		return fail(err)
	}
	owner := &nodeChainPairedProxyEntryLocal{owner: c, nodes: slices.Clone(c.nodes), source: c.sourceJSON, sourceSHA: c.sourceSHA}
	owner.self = owner
	c.pairedProxyEntry = owner
	scope := &nodeChainPairedProxyEntryGraphScope{owner: owner, closures: slices.Clone(closures)}
	config, proofs, dns, egress, err := compileNodeChainGraphWithOwnedScopes(members, closures, physical, nil, nil, nil, nil, nil, scope)
	if err != nil || !nodeChainSamePhysical(physical, egress) {
		return fail(err)
	}
	if len(c.nodes) > NodeChainMaximumNodes && len(config) > NodeChainInputLimit/len(c.nodes) {
		return fail(nil)
	}
	return config, proofs, dns, egress, nil
}

// A missing packet ancestor is meaningful only at this exact original physical
// proxy root. It is never inferred from a mode label or an empty envelope.
func nodeChainPhysicalProxyRoot(members []nodeChainGraphMember, closures []*externalPredecessor, appendScope *nodeChainAppendGraphScope, completeScope nodeChainCompleteLocalScope) bool {
	if len(members) == 0 || len(members) != len(closures) || !nodeChainAppendProxyMode(members[0].mode) || closures[0] == nil {
		return false
	}
	if appendScope != nil {
		if completeScope != nil || appendScope.owner == nil || appendScope.owner.record.Schema != 3 ||
			len(appendScope.owner.nodes) == 0 || appendScope.owner.nodes[0] == nil {
			return false
		}
		expected, err := appendScope.owner.nodes[0].PhysicalEgress()
		if err != nil || appendScope.validate(members, closures, expected) != nil {
			return false
		}
		if members[0].mode == "hysteria2" {
			return nodeChainCapturedHysteriaClosure(appendScope.owner.nodes[0], closures[0])
		}
		return nodeChainCapturedSSClosure(closures[0])
	}
	scope, ok := completeScope.(*nodeChainPairedProxyEntryGraphScope)
	if !ok || scope == nil || scope.owner == nil || len(scope.owner.nodes) == 0 || scope.owner.nodes[0] == nil {
		return false
	}
	expected, err := scope.owner.nodes[0].PhysicalEgress()
	return err == nil && scope.validate(members, closures, expected) == nil && scope.admitsProxy(0, closures[0], members[0].mode)
}

// Each projection contains the actual application paths, selected DNS and one
// original private proof. Only callers holding the validated complete proxy
// owner use this union. Every individual tuple must remain inside the captured
// first root, and all actual projections together must account for that root.
func nodeChainPairedProxyPhysical(projections [][]PhysicalEgress, expected []PhysicalEgress, count int) ([]PhysicalEgress, error) {
	if count < 2 || count > NodeChainExtendedLocalMaximumNodes || len(projections) != count || len(expected) < 1 || len(expected) > 2 {
		return nil, nodeChainError
	}
	allowed := make(map[PhysicalEgress]bool, len(expected))
	for _, tuple := range expected {
		if allowed[tuple] {
			return nil, nodeChainError
		}
		allowed[tuple] = true
	}
	seen := make(map[PhysicalEgress]bool, len(expected))
	for _, projection := range projections {
		if len(projection) == 0 || len(projection) > len(expected) {
			return nil, nodeChainError
		}
		local := make(map[PhysicalEgress]bool, len(projection))
		for _, tuple := range projection {
			if !allowed[tuple] || local[tuple] {
				return nil, nodeChainError
			}
			local[tuple], seen[tuple] = true, true
		}
	}
	actual := make([]PhysicalEgress, 0, len(seen))
	for tuple := range seen {
		actual = append(actual, tuple)
	}
	sortPhysicalEgress(actual)
	if !nodeChainSamePhysical(actual, expected) {
		return nil, nodeChainError
	}
	return actual, nil
}
