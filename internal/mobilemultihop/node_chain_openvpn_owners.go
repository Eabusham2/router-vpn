package mobilemultihop

// This receipt is private to the original schema-five compiler. Serialized
// values and equal replacement objects cannot transfer its paired authority.
// Authorized projection reconstructs a complete source and owns a fresh receipt.
type nodeChainOpenVPNOwners struct {
	owner  *NodeChain
	middle *nodeChainOpenVPNMember
	nodes  []*NodeProfile
}

func (r *nodeChainOpenVPNOwners) current(c *NodeChain) bool {
	if r == nil || r.owner != c || r.middle != c.openVPNMiddle || len(r.nodes) != len(c.nodes) {
		return false
	}
	for i, node := range r.nodes {
		if c.nodes[i] != node {
			return false
		}
	}
	return true
}
