package mobilemultihop

// Original schema-two authority is independent of serialization and transport
// equivalence. Authorized projections reconstruct and own a fresh capture.
type nodeChainImportedOwners struct {
	owner    *NodeChain
	middle   *nodeChainImportedMember
	policy   *ExternalPolicy
	hostname *nodeChainImportedHostname
	nodes    []*NodeProfile
}

func (r *nodeChainImportedOwners) current(c *NodeChain) bool {
	if r == nil || r.owner != c || r.middle != c.importedMiddle || r.middle == nil || r.policy != r.middle.policy || r.hostname != r.middle.hostname || len(r.nodes) != len(c.nodes) {
		return false
	}
	for i, node := range r.nodes {
		if c.nodes[i] != node {
			return false
		}
	}
	return true
}
