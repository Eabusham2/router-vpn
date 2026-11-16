package mobilemultihop

import "strconv"

// Original schema-two authority is independent of serialization and transport
// equivalence. Authorized projections reconstruct and own a fresh capture.
type nodeChainImportedOwners struct {
	self                          *nodeChainImportedOwners
	sourceJSON, middleInput, seal string
	count                         int
	owner                         *NodeChain
	middle                        *nodeChainImportedMember
	policy                        *ExternalPolicy
	hostname                      *nodeChainImportedHostname
	nodes                         []*NodeProfile
}

func (r *nodeChainImportedOwners) current(c *NodeChain) bool {
	if r == nil || r.self != r || r.owner != c || r.seal == "" || r.captureSeal() != r.seal || r.sourceJSON != c.sourceJSON || r.count < 3 || r.count > NodeChainMaximumNodes || r.count != len(c.nodes) || r.middle != c.importedMiddle || r.middle == nil || r.middleInput != r.middle.input || r.policy != r.middle.policy || r.hostname != r.middle.hostname || len(r.nodes) != len(c.nodes) {
		return false
	}
	for i, node := range r.nodes {
		if c.nodes[i] != node {
			return false
		}
	}
	return true
}

// Constructor-only input receipt. Projections create fresh owners by replaying
// the complete constructor; observations never reparse immutable source bytes.
func (r *nodeChainImportedOwners) captureSeal() string {
	if r == nil {
		return ""
	}
	return externalDigest([]byte(r.sourceJSON + "\x00" + r.middleInput + "\x00" + strconv.Itoa(r.count)))
}
