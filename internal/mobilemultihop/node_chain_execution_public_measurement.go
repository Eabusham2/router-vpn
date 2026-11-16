package mobilemultihop

// This private receipt captures pointers only at original preparation creation.
// An equal serialized replacement is not the original measurement source.
type nodeChainExecutionImportedPublicCapture struct {
	preparation    *NodeChainExecutionPreparation
	chain          *NodeChain
	middle         *nodeChainImportedMember
	policy         *ExternalPolicy
	hostname       *nodeChainImportedHostname
	nodes          []*NodeProfile
	source, config string
}

func captureNodeChainExecutionImportedPublic(p *NodeChainExecutionPreparation) *nodeChainExecutionImportedPublicCapture {
	if p == nil || p.connect != nil || p.socks != nil || p.source.Schema != 1 || p.local == nil ||
		!nodeChainImportedExecutionMemberSupported(p.local.importedMiddle, len(p.local.nodes)) ||
		p.local.openVPNMiddle != nil || p.local.socksSource != nil || p.local.connectSource != nil {
		return nil
	}
	return &nodeChainExecutionImportedPublicCapture{preparation: p, chain: p.local, middle: p.local.importedMiddle,
		policy: p.local.importedMiddle.policy, hostname: p.local.importedMiddle.hostname,
		nodes: append([]*NodeProfile(nil), p.local.nodes...), source: p.sourceSHA, config: p.configSHA}
}

func (c *nodeChainExecutionImportedPublicCapture) current(p *NodeChainExecutionPreparation) bool {
	if c == nil || p == nil || c.preparation != p || c.chain == nil || p.local != c.chain ||
		c.middle == nil || c.chain.importedMiddle != c.middle || c.middle.policy != c.policy || c.middle.hostname != c.hostname ||
		!nodeChainImportedExecutionMemberSupported(c.middle, len(c.nodes)) || c.source != p.sourceSHA || c.config != p.configSHA ||
		(len(c.nodes) < 3 || len(c.nodes) > 8) || len(c.chain.nodes) != len(c.nodes) {
		return false
	}
	for position, original := range c.nodes {
		if c.chain.nodes[position] != original {
			return false
		}
	}
	return true
}

// ImportedPublicMeasurementCapture exposes only the original generic SS2022
// path's original public measurement prefix and captured aggregate IPv6 policy.
// The native adapter must still prove its original Box, selector, resolver and
// current execution. This receipt grants no physical or arbitrary-host dial.
func (p *NodeChainExecutionProjection) ImportedPublicMeasurementCapture(execution string) (tag string, ipv6 bool, err error) {
	if p.validateCapture() != nil || p.preparation.connect != nil || p.policy.connect != nil || p.preparation.socks != nil || p.policy.socks != nil ||
		p.preparation.source.Schema != 1 || p.policy.source.Server.Schema != 2 ||
		!p.preparation.importedPublic.current(p.preparation) {
		return "", false, nodeChainExecutionError
	}
	original := p.preparation.local
	if original == nil || !nodeChainImportedExecutionMemberSupported(original.importedMiddle, len(original.nodes)) || original.openVPNMiddle != nil ||
		original.socksSource != nil || original.connectSource != nil {
		return "", false, nodeChainExecutionError
	}
	position := len(original.nodes) - 2
	localTag, ipv6, err := original.PublicMeasurementCapture()
	if err != nil || localTag == "" || localTag != original.proofs[position].Tag {
		return "", false, nodeChainExecutionError
	}
	proofs, err := p.policy.ProofInventory(execution)
	if err != nil || len(proofs) != len(original.nodes) {
		return "", false, nodeChainExecutionError
	}
	proof, captured := proofs[position], original.proofs[position]
	if proof.Position != position || proof.Kind != "public-path" || proof.NodeKind != "external" ||
		proof.Mode != "shadowsocks" || proof.NodeID != "" || proof.SourceSHA256 != captured.SourceSHA256 ||
		proof.ProfileID != captured.ProfileID || proof.Tag == "" {
		return "", false, nodeChainExecutionError
	}
	return proof.Tag, ipv6, nil
}
