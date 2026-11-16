package mobilemultihop

import "strconv"

// This receipt is private to the original schema-five compiler. Serialized
// values and equal replacement objects cannot transfer its paired authority.
// Authorized projection reconstructs a complete source and owns a fresh receipt.
type nodeChainOpenVPNOwners struct {
	self                          *nodeChainOpenVPNOwners
	sourceJSON, middleInput, seal string
	count                         int
	owner                         *NodeChain
	middle                        *nodeChainOpenVPNMember
	policy                        *ExternalPolicy
	nodes                         []*NodeProfile
}

func (r *nodeChainOpenVPNOwners) current(c *NodeChain) bool {
	if r == nil || c == nil || r.self != r || r.owner != c || r.seal == "" || r.captureSeal() != r.seal || r.sourceJSON != c.sourceJSON || r.count < 3 || r.count > NodeChainMaximumNodes || r.count != len(c.nodes) || r.middle != c.openVPNMiddle || r.middle == nil || r.middleInput != r.middle.input || r.policy != r.middle.policy || len(r.nodes) != len(c.nodes) {
		return false
	}
	for i, node := range r.nodes {
		if c.nodes[i] != node {
			return false
		}
	}
	return true
}

// The constructor already parsed these exact immutable source bytes. Each
// observation compares them and the original owner pointers freshly; it does
// not retain a validity, connected-generation or network-policy result.
func (r *nodeChainOpenVPNOwners) captureSeal() string {
	if r == nil {
		return ""
	}
	return externalDigest([]byte(r.sourceJSON + "\x00" + r.middleInput + "\x00" + strconv.Itoa(r.count)))
}
