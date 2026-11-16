package mobilemultihop

import "router-vpn/internal/multihoprelay"

// NodeChainServerCandidateTarget is a connect-only target compiled from the
// original private server policy. It is not a proof exception or a front route.
// Native admission still needs the original worker, operation and live endpoint.
type NodeChainServerCandidateTarget struct {
	self    *NodeChainServerCandidateTarget
	policy  *NodeChainServerPolicy
	node    *NodeProfile
	capture multihoprelay.NodeChainCandidateCapture
	tag     string
}

func (p *NodeChainServerPolicy) CandidateTarget(c multihoprelay.NodeChainCandidateCapture) (*NodeChainServerCandidateTarget, error) {
	if c.Validate() != nil {
		return nil, nodeChainServerError
	}
	if _, err := p.binding(c.Lease); err != nil {
		return nil, err
	}
	index := c.Request.Position - 1
	if index < 0 || index >= len(p.nodes)-1 || index >= len(p.proofs) || p.nodes[index] == nil || c.Member != p.descriptor.Members[index] {
		return nil, nodeChainServerError
	}
	node := p.nodes[index]
	if node.mode != "wg" && node.mode != "awg2-fast" && node.mode != "awg2-strong" {
		return nil, nodeChainServerError
	}
	// No Destinations: an original API/DNS proof exception must never override
	// the selected application LAN/IPv6 policy for an arbitrary candidate.
	policy := NodeChainServerFrontRoute{Final: true, BlockIPv6: p.blockIPv6, BlockedCIDRs: append([]string(nil), p.blockedCIDRs...)}
	if !policy.AllowsDestination("tcp", c.Request.Address) {
		return nil, nodeChainServerError
	}
	target := &NodeChainServerCandidateTarget{policy: p, node: node, capture: c.Clone(), tag: p.proofs[index].Tag}
	target.self = target
	return target, nil
}

// Read returns only the exact original packet tag and literal TCP destination.
// The receiver must perform connect-and-close; this grants no payload forwarding.
func (t *NodeChainServerCandidateTarget) Read(p *NodeChainServerPolicy, c multihoprelay.NodeChainCandidateCapture) (string, string, error) {
	if t == nil || t.self != t || p == nil || p != t.policy {
		return "", "", nodeChainServerError
	}
	want, err := t.capture.Digest()
	got, other := c.Digest()
	if err != nil || other != nil || want != got {
		return "", "", nodeChainServerError
	}
	fresh, err := p.CandidateTarget(c)
	if err != nil || fresh.node != t.node || fresh.tag != t.tag || t.tag == "" {
		return "", "", nodeChainServerError
	}
	return t.tag, t.capture.Request.Address, nil
}
