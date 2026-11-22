package mobilemultihop

import (
	"encoding/json"
	"slices"
)

// Copies only immutable string headers and independent short proof/egress slices.
// Every field originally hashed by captureSeal is compared byte-for-byte before
// its original digest can be reused. Mutated or derived inputs use the ordinary
// serializer. The saved digest supplies no live native or connection authority.
type nodeChainMultipleImportedPreparationSeal struct {
	owner                                          *NodeChainExecutionPreparation
	sourceJSON, sourceSHA, config, configSHA, seal string
	source                                         NodeChainExecutionPreparationSource
	discovery                                      NodeChainExecutionDiscoveryCapture
	dns                                            NodeChainExecutionDNSCapture
	physical                                       []PhysicalEgress
}

func (s *nodeChainMultipleImportedPreparationSeal) matches(p *NodeChainExecutionPreparation) bool {
	return s != nil && s.owner == p && p.mobile == nil && p.multiple.desktop == nil &&
		p.source == s.source && p.sourceJSON == s.sourceJSON && p.sourceSHA == s.sourceSHA &&
		p.config == s.config && p.configSHA == s.configSHA && p.discovery == s.discovery && p.dns == s.dns &&
		(p.physical == nil) == (s.physical == nil) && slices.Equal(p.physical, s.physical)
}

func (p *NodeChainExecutionPreparation) rememberMultipleImportedSeal() {
	if p.multiple != nil && p.mobile == nil && p.multiple.desktop == nil && p.source.Desktop == nil &&
		p.source.DesktopCONNECT == nil && p.source.DesktopSOCKS == nil && p.source.DesktopOpenVPN == nil && p.source.DesktopMultipleImported == nil {
		p.multiple.originalSeal = &nodeChainMultipleImportedPreparationSeal{
			owner: p, sourceJSON: p.sourceJSON, sourceSHA: p.sourceSHA, config: p.config, configSHA: p.configSHA,
			seal: p.seal, source: p.source, discovery: p.discovery, dns: p.dns, physical: slices.Clone(p.physical),
		}
	}
}

// The original imported parser has verified both the member and its standalone
// policy before this snapshot is issued. Dynamic private maps are serialized on
// every read, while immutable strings are compared directly without escaping them.
type nodeChainMultipleImportedMemberSeal struct {
	owner                                                           *nodeChainImportedMember
	policy                                                          *ExternalPolicy
	input, source, seal, policySeal, config, metadata, policySource string
	mutable                                                         string
}

func (m *nodeChainImportedMember) rememberMultipleImportedMember() error {
	if m == nil || m.hostname != nil || m.policy == nil || m.validate() != nil {
		return nodeChainError
	}
	raw, err := json.Marshal([2]externalPolicyCapture{m.selection, m.policy.capture})
	if err != nil {
		return err
	}
	m.multipleSeal = &nodeChainMultipleImportedMemberSeal{
		owner: m, policy: m.policy, input: m.input, source: m.source, seal: m.seal, policySeal: m.policySeal,
		config: m.policy.config, metadata: m.policy.metadata, policySource: m.policy.source, mutable: string(raw),
	}
	return nil
}

func (s *nodeChainMultipleImportedMemberSeal) matches(m *nodeChainImportedMember) bool {
	if s == nil || s.owner != m || m.hostname != nil || s.policy == nil || m.policy != s.policy || m.policyOwner != s.policy ||
		m.input != s.input || m.source != s.source || m.seal != s.seal || m.policySeal != s.policySeal || s.policy.desktopSeal != s.policySeal ||
		m.policy.config != s.config || m.policy.metadata != s.metadata || m.policy.source != s.policySource {
		return false
	}
	raw, err := json.Marshal([2]externalPolicyCapture{m.selection, m.policy.capture})
	return err == nil && string(raw) == s.mutable
}

type nodeChainMultipleImportedInputsSeal struct {
	owner  *nodeChainImportedNodes
	source string
	inputs []string
	seal   string
}

type nodeChainMultipleImportedLocalSeal struct {
	owner                                                            *NodeChain
	sourceJSON, sourceSHA, config, metadata, originalConfigSHA, seal string
	proofs                                                           []NodeChainProof
	dns                                                              NodeChainDNSCapture
	physical                                                         []PhysicalEgress
	projection                                                       nodeChainProjection
}

func (s *nodeChainMultipleImportedLocalSeal) matches(c *NodeChain) bool {
	return s != nil && s.owner == c && c.sourceJSON == s.sourceJSON && c.sourceSHA == s.sourceSHA && c.config == s.config &&
		c.metadata == s.metadata && c.originalConfigSHA == s.originalConfigSHA && c.dns == s.dns && c.projection == s.projection &&
		(c.proofs == nil) == (s.proofs == nil) && slices.Equal(c.proofs, s.proofs) && (c.physical == nil) == (s.physical == nil) && slices.Equal(c.physical, s.physical)
}

func (r *nodeChainImportedNodes) rememberLocalSeal(c *NodeChain) {
	if !r.customEntry {
		r.localSeal = &nodeChainMultipleImportedLocalSeal{
			owner: c, sourceJSON: c.sourceJSON, sourceSHA: c.sourceSHA, config: c.config, metadata: c.metadata,
			originalConfigSHA: c.originalConfigSHA, seal: c.seal, proofs: slices.Clone(c.proofs), dns: c.dns,
			physical: slices.Clone(c.physical), projection: c.projection,
		}
	}
}
