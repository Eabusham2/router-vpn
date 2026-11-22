package mobilemultihop

import (
	"encoding/json"
	"slices"
)

// Schema six retains imported interiors behind a paired physical entry. Schema
// seven retains two literal SS2022 sources at the entry and next position.
// Their paired final owns application DNS. Each registry belongs to exactly
// one constructed graph, including after a provider projection or child replay.
type nodeChainImportedNodes struct {
	localSeal       *nodeChainMultipleImportedLocalSeal
	inputSeal       *nodeChainMultipleImportedInputsSeal
	customEntry     bool
	self            *nodeChainImportedNodes
	owner           *NodeChain
	members         []*nodeChainImportedMember
	originalMembers []*nodeChainImportedMember
	nodes           []*NodeProfile
	policies        []*ExternalPolicy
	hostnames       []*nodeChainImportedHostname
	inputs          []string
	sourceJSON      string
	seal            string
}

func (r *nodeChainImportedNodes) freeze(c *NodeChain) error {
	if r == nil || r.self != nil || c == nil || c.importedNodes != r || len(r.members) != len(c.nodes) {
		return nodeChainError
	}
	r.owner, r.self, r.sourceJSON = c, r, c.sourceJSON
	r.originalMembers = append([]*nodeChainImportedMember(nil), r.members...)
	r.nodes = append([]*NodeProfile(nil), c.nodes...)
	r.policies = make([]*ExternalPolicy, len(r.members))
	r.hostnames = make([]*nodeChainImportedHostname, len(r.members))
	r.inputs = make([]string, len(r.members))
	for position, member := range r.members {
		if member != nil {
			r.policies[position], r.hostnames[position], r.inputs[position] = member.policy, member.hostname, member.input
		}
	}
	r.seal = r.captureSeal()
	r.rememberLocalSeal(c)
	if !r.customEntry {
		r.inputSeal = &nodeChainMultipleImportedInputsSeal{owner: r, source: r.sourceJSON, inputs: slices.Clone(r.inputs), seal: r.seal}
	}
	if !r.current(c) {
		return nodeChainError
	}
	return nil
}

func (r *nodeChainImportedNodes) captureSeal() string {
	if r == nil {
		return ""
	}
	if snapshot := r.inputSeal; !r.customEntry && snapshot != nil && snapshot.owner == r && snapshot.source == r.sourceJSON &&
		(snapshot.inputs == nil) == (r.inputs == nil) && slices.Equal(snapshot.inputs, r.inputs) {
		return snapshot.seal
	}
	kind := "routervpn-node-chain-imported-nodes-v1"
	if r.customEntry {
		kind = "routervpn-node-chain-imported-entry-v1"
	}
	raw, err := json.Marshal([]any{kind, r.sourceJSON, r.inputs})
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (r *nodeChainImportedNodes) current(c *NodeChain) bool {
	if !r.originalOwnersCurrent(c) {
		return false
	}
	for _, member := range r.members {
		if member != nil && member.validate() != nil {
			return false
		}
	}
	return true
}

// NodeChain.validateCapture validates every retained member in its positional
// proof loop. Check the original aggregate owners first without running the
// same full external-policy traversal twice during that one observation.
// Constructor freeze still uses current, which also validates every member.
func (r *nodeChainImportedNodes) originalOwnersCurrent(c *NodeChain) bool {
	if r == nil || r.self != r || r.owner != c || c == nil || c.importedNodes != r ||
		r.sourceJSON != c.sourceJSON || r.seal == "" || r.captureSeal() != r.seal ||
		len(r.members) < 3 || len(r.members) > NodeChainMaximumNodes || len(r.members) != len(c.nodes) ||
		len(r.nodes) != len(r.members) || len(r.originalMembers) != len(r.members) || len(r.inputs) != len(r.members) ||
		len(r.policies) != len(r.members) || len(r.hostnames) != len(r.members) {
		return false
	}
	if r.customEntry && (len(r.members) != 3 || r.members[0] == nil || r.members[1] == nil) {
		return false
	}
	count := 0
	for position, member := range r.members {
		if c.nodes[position] != r.nodes[position] || member != r.originalMembers[position] {
			return false
		}
		if member == nil {
			if c.nodes[position] == nil || r.inputs[position] != "" || r.policies[position] != nil || r.hostnames[position] != nil {
				return false
			}
			continue
		}
		if position == 0 && !r.customEntry || position == len(r.members)-1 || c.nodes[position] != nil ||
			member.input != r.inputs[position] ||
			member.policy != r.policies[position] || member.hostname != r.hostnames[position] || member.hostname != nil {
			return false
		}
		count++
	}
	return count != 0
}

// HasImportedEntry classifies only the original immutable three-position
// source. It is descriptive readback, not authority to start or measure a
// replacement graph. Run and measurement validate the complete source again.
func (c *NodeChain) HasImportedEntry() bool {
	if c == nil || c.importedNodes == nil {
		return false
	}
	r := c.importedNodes
	return r.customEntry && r.self == r && r.owner == c && r.sourceJSON == c.sourceJSON &&
		len(r.members) == 3 && len(r.originalMembers) == 3 && len(c.nodes) == 3 &&
		r.members[0] != nil && r.members[0] == r.originalMembers[0] &&
		r.members[1] != nil && r.members[1] == r.originalMembers[1] &&
		r.members[2] == nil && c.nodes[0] == nil && c.nodes[1] == nil && c.nodes[2] != nil
}

// Observations never reopen a source or borrow the last imported member. The
// caller validates the original complete capture before consulting a position.
func (c *NodeChain) importedSSMemberAt(position int) *nodeChainImportedMember {
	if c == nil || position < 0 || position >= len(c.nodes) {
		return nil
	}
	if c.importedNodes != nil {
		if len(c.importedNodes.members) != len(c.nodes) {
			return nil
		}
		return c.importedNodes.members[position]
	}
	if position == len(c.nodes)-2 {
		return c.importedMiddle
	}
	return nil
}

func (c *NodeChain) importedPublicIPAt(position int) (string, bool) {
	if member := c.importedSSMemberAt(position); member != nil {
		return member.selection.ExpectedPublicIP, true
	}
	if c != nil && position >= 0 && position == c.importedMiddlePosition() {
		return c.importedMiddlePublicIP(), true
	}
	return "", false
}

func (r *nodeChainImportedNodes) compile(nodes []*NodeProfile) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	fail := func(err error) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
		return "", nil, NodeChainDNSCapture{}, nil, err
	}
	imported := r.members
	if len(nodes) < 3 || len(nodes) > NodeChainMaximumNodes || len(imported) != len(nodes) ||
		r.customEntry && (len(nodes) != 3 || nodes[0] != nil || nodes[1] != nil || imported[0] == nil || imported[1] == nil) ||
		!r.customEntry && (nodes[0] == nil || imported[0] != nil) ||
		nodes[len(nodes)-1] == nil || imported[len(nodes)-1] != nil ||
		nodes[len(nodes)-1].mode != "shadowsocks" {
		return fail(nodeChainError)
	}
	closures := make([]*externalPredecessor, len(nodes))
	members := make([]nodeChainGraphMember, len(nodes))
	count := 0
	for position, node := range nodes {
		var err error
		if member := imported[position]; member != nil {
			if node != nil || member.validate() != nil || member.hostname != nil {
				return fail(nodeChainError)
			}
			closures[position], err = member.closure()
			members[position] = nodeChainGraphMember{profile: member.selection.Profile, source: member.source, mode: "shadowsocks", imported: true}
			count++
		} else {
			if node == nil || position < len(nodes)-1 && !NodeChainPrefixMode(node.mode) {
				return fail(nodeChainError)
			}
			closures[position], err = nodeMultihopPredecessor(node)
			members[position] = nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode}
		}
		if err != nil {
			return fail(err)
		}
		if services, _ := closures[position].graph["services"].([]any); len(services) != 0 {
			return fail(nodeChainError)
		}
		if node != nil && position < len(nodes)-1 && closures[position].final["type"] != nodeChainPrefixType(node.mode) {
			return fail(nodeChainError)
		}
	}
	last := closures[len(nodes)-1].final
	if count == 0 || (last["type"] != "shadowsocks" && last["type"] != "routervpn-aes-xor") || last["method"] != NativeStartLayerMethod {
		return fail(nodeChainError)
	}
	var physical []PhysicalEgress
	var err error
	if r.customEntry {
		physical, err = imported[0].policy.DirectPhysicalEgress([]string{"tcp", "udp"})
	} else {
		physical, err = nodes[0].PhysicalEgress()
	}
	if err != nil {
		return fail(err)
	}
	return compileNodeChainClosures(members, closures, physical)
}
