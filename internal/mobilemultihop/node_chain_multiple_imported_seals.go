package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"slices"

	"router-vpn/internal/hopmeasure"
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
	desktop                                        *nodeChainMultipleImportedExecutionDesktop
	metadata                                       *DesktopNodeChainMetadata
}

func (s *nodeChainMultipleImportedPreparationSeal) matches(p *NodeChainExecutionPreparation) bool {
	return s != nil && s.owner == p && p.mobile == nil && p.multiple.desktop == s.desktop &&
		reflect.DeepEqual(p.source.DesktopMultipleImported, s.metadata) &&
		p.source == s.source && p.sourceJSON == s.sourceJSON && p.sourceSHA == s.sourceSHA &&
		p.config == s.config && p.configSHA == s.configSHA && p.discovery == s.discovery && p.dns == s.dns &&
		(p.physical == nil) == (s.physical == nil) && slices.Equal(p.physical, s.physical)
}

func (p *NodeChainExecutionPreparation) rememberMultipleImportedSeal() {
	if p.multiple != nil && p.mobile == nil && p.source.Desktop == nil &&
		p.source.DesktopCONNECT == nil && p.source.DesktopSOCKS == nil && p.source.DesktopOpenVPN == nil &&
		(p.multiple.desktop == nil) == (p.source.DesktopMultipleImported == nil) {
		var metadata *DesktopNodeChainMetadata
		if original := p.source.DesktopMultipleImported; original != nil {
			copy := original.clone()
			metadata = &copy
		}
		p.multiple.originalSeal = &nodeChainMultipleImportedPreparationSeal{
			owner: p, sourceJSON: p.sourceJSON, sourceSHA: p.sourceSHA, config: p.config, configSHA: p.configSHA,
			seal: p.seal, source: p.source, discovery: p.discovery, dns: p.dns, physical: slices.Clone(p.physical),
			desktop: p.multiple.desktop, metadata: metadata,
		}
	}
}

// The original imported parser has verified both the member and its standalone
// policy before this snapshot is issued. Each live map is compared to an independent
// decoded copy of its canonical bytes. A different Go representation falls
// back to the original canonical encoder.
type nodeChainMultipleImportedMemberSeal struct {
	owner                                                           *nodeChainImportedMember
	policy                                                          *ExternalPolicy
	input, source, seal, policySeal, config, metadata, policySource string
	mutable                                                         string
	original                                                        *[2]externalPolicyCapture
}

func (m *nodeChainImportedMember) rememberMultipleImportedMember() error {
	if m == nil || m.hostname != nil || m.policy == nil || m.validate() != nil {
		return nodeChainError
	}
	raw, err := json.Marshal([2]externalPolicyCapture{m.selection, m.policy.capture})
	if err != nil {
		return err
	}
	original := decodeMultipleImportedOriginal[[2]externalPolicyCapture](raw)
	m.multipleSeal = &nodeChainMultipleImportedMemberSeal{
		owner: m, policy: m.policy, input: m.input, source: m.source, seal: m.seal, policySeal: m.policySeal,
		config: m.policy.config, metadata: m.policy.metadata, policySource: m.policy.source, mutable: string(raw), original: original,
	}
	return nil
}

func (s *nodeChainMultipleImportedMemberSeal) matches(m *nodeChainImportedMember) bool {
	if s == nil || s.owner != m || m.hostname != nil || s.policy == nil || m.policy != s.policy || m.policyOwner != s.policy ||
		m.input != s.input || m.source != s.source || m.seal != s.seal || m.policySeal != s.policySeal || s.policy.desktopSeal != s.policySeal ||
		m.policy.config != s.config || m.policy.metadata != s.metadata || m.policy.source != s.policySource {
		return false
	}
	if s.original != nil && sameMultipleImportedCapture(m.selection, s.original[0]) && sameMultipleImportedCapture(m.policy.capture, s.original[1]) {
		return true
	}
	raw, err := json.Marshal([2]externalPolicyCapture{m.selection, m.policy.capture})
	return err == nil && string(raw) == s.mutable
}

// A decoded number can lose its initial spelling or integer precision. Use a
// decoded snapshot only when it reproduces every original serialized byte.
func decodeMultipleImportedOriginal[T any](raw []byte) *T {
	var original T
	if json.Unmarshal(raw, &original) != nil {
		return nil
	}
	check, err := json.Marshal(original)
	defer clear(check)
	if err != nil || !bytes.Equal(check, raw) {
		return nil
	}
	return &original
}

// The original cannot alias the live maps or slices. Compare the exact JSON
// value tree, including object keys and array order. Values of a different Go
// type take the caller's canonical fallback (e.g. int(7) can encode like 7.0).
func sameMultipleImportedJSON(value, original any) bool {
	switch want := original.(type) {
	case nil:
		return value == nil
	case bool:
		got, ok := value.(bool)
		return ok && got == want
	case string:
		got, ok := value.(string)
		return ok && got == want
	case float64:
		got, ok := value.(float64)
		return ok && math.Float64bits(got) == math.Float64bits(want)
	case []any:
		got, ok := value.([]any)
		if !ok || (got == nil) != (want == nil) || len(got) != len(want) {
			return false
		}
		for i, v := range want {
			if !sameMultipleImportedJSON(got[i], v) {
				return false
			}
		}
		return true
	case map[string]any:
		got, ok := value.(map[string]any)
		if !ok || (got == nil) != (want == nil) || len(got) != len(want) {
			return false
		}
		for k, v := range want {
			actual, ok := got[k]
			if !ok || !sameMultipleImportedJSON(actual, v) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func sameMultipleImportedCapture(current, original externalPolicyCapture) bool {
	if current.DNSBootstrap != nil || original.DNSBootstrap != nil || current.Execution != nil || original.Execution != nil {
		return false
	}
	if !sameMultipleImportedJSON(current.Profile, original.Profile) || !sameMultipleImportedJSON(current.Entry, original.Entry) {
		return false
	}
	return current.Schema == original.Schema && current.ExitID == original.ExitID && current.Protocol == original.Protocol &&
		current.ExpectedPublicIP == original.ExpectedPublicIP && current.EntryTag == original.EntryTag && current.PredecessorConfig == original.PredecessorConfig
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
	packets                                                          []*nodeChainMultipleImportedPacketSeal
	extendedProofs                                                   bool
}

func (s *nodeChainMultipleImportedLocalSeal) matches(c *NodeChain) bool {
	return s != nil && s.owner == c && c.sourceJSON == s.sourceJSON && c.sourceSHA == s.sourceSHA && c.config == s.config &&
		c.metadata == s.metadata && c.originalConfigSHA == s.originalConfigSHA && c.dns == s.dns && c.projection == s.projection &&
		(c.proofs == nil) == (s.proofs == nil) && slices.Equal(c.proofs, s.proofs) && (c.physical == nil) == (s.physical == nil) && slices.Equal(c.physical, s.physical)
}

// The original WG/AWG constructor seals its exact immutable strings and its
// decoded profile map. Compare each mutable value against an independent
// snapshot, keeping canonical serialization as the fallback.
type nodeChainMultipleImportedPacketSeal struct {
	owner                                         *NodeProfile
	config, source, metadata, mode, seal, profile string
	inputs                                        nodeProfileInputs
	original                                      *map[string]any
}

func newNodeChainMultipleImportedPacketSeal(p *NodeProfile) *nodeChainMultipleImportedPacketSeal {
	if p == nil || p.validateNodeDesktopCapture() != nil {
		return nil
	}
	raw, err := json.Marshal(p.profile)
	if err != nil {
		return nil
	}
	original := decodeMultipleImportedOriginal[map[string]any](raw)
	return &nodeChainMultipleImportedPacketSeal{p, p.config, p.source, p.metadata, p.mode, p.desktopSeal, string(raw), p.inputs, original}
}

func (s *nodeChainMultipleImportedPacketSeal) matches(node *NodeProfile) bool {
	if s == nil || node == nil || node != s.owner || node.config != s.config || node.source != s.source || node.metadata != s.metadata || node.mode != s.mode || node.inputs != s.inputs || node.desktopSeal != s.seal {
		return false
	}
	if s.original != nil && sameMultipleImportedJSON(node.profile, *s.original) {
		return true
	}
	raw, err := json.Marshal(node.profile)
	return err == nil && string(raw) == s.profile
}

func (c *NodeChain) validateOriginalPacket(position int, node *NodeProfile) error {
	original := c.typedOriginal
	if r := c.importedNodes; r != nil {
		original = r.localSeal
	}
	if original != nil && original.owner == c && position < len(original.packets) {
		if s := original.packets[position]; s != nil {
			if !s.matches(node) {
				return nodeLaunchInputError
			}
			return nil
		}
	}
	return node.validateNodeDesktopCapture()
}

func snapshotOriginalNodeChain(c *NodeChain) *nodeChainMultipleImportedLocalSeal {
	packets := make([]*nodeChainMultipleImportedPacketSeal, len(c.nodes))
	for i, node := range c.nodes {
		packets[i] = newNodeChainMultipleImportedPacketSeal(node)
	}
	return &nodeChainMultipleImportedLocalSeal{
		owner: c, sourceJSON: c.sourceJSON, sourceSHA: c.sourceSHA, config: c.config, metadata: c.metadata,
		originalConfigSHA: c.originalConfigSHA, seal: c.seal, proofs: slices.Clone(c.proofs), dns: c.dns,
		physical: slices.Clone(c.physical), projection: c.projection, packets: packets, extendedProofs: extendedLocalProofs(c.proofs),
	}
}

func (r *nodeChainImportedNodes) rememberLocalSeal(c *NodeChain) {
	if !r.customEntry {
		r.localSeal = snapshotOriginalNodeChain(c)
	}
}

type nodeChainExecutionPolicySeal struct {
	packet                                         *nodeChainMultipleImportedLocalSeal
	owner                                          *NodeChainExecutionPolicy
	sourceJSON, sourceSHA, config, configSHA, seal string
	source                                         NodeChainExecutionSource
	front                                          NodeChainExecutionFront
	local, server                                  []NodeChainProof
	dns                                            NodeChainDNSCapture
	physical                                       []PhysicalEgress
}

func (p *NodeChainExecutionPolicy) rememberPolicySeal() {
	source := p.source
	source.Server = p.source.Server.Clone()
	source.Request = p.source.Request.Clone()
	front := p.front
	front.Users = slices.Clone(front.Users)
	p.originalSeal = &nodeChainExecutionPolicySeal{owner: p, sourceJSON: p.sourceJSON, sourceSHA: p.sourceSHA, config: p.config, configSHA: p.configSHA, seal: p.seal, source: source, front: front, local: slices.Clone(p.localProofs), server: slices.Clone(p.serverProofs), dns: p.dns, physical: slices.Clone(p.physical)}
	if p.connect == nil && p.socks == nil && p.openvpn == nil && p.multiple == nil && ordinaryExecutionPacketGraph(p.local) {
		p.originalSeal.packet = snapshotOriginalNodeChain(p.local)
	}
}

func (s *nodeChainExecutionPolicySeal) localPacketCurrent(p *NodeChainExecutionPolicy) bool {
	return s != nil && s.owner == p && s.packet != nil && currentDesktopPacketGraph(s.packet, p.local)
}

func (s *nodeChainExecutionPolicySeal) matches(p *NodeChainExecutionPolicy) bool {
	return s != nil && s.owner == p &&
		p.sourceJSON == s.sourceJSON && p.sourceSHA == s.sourceSHA && p.config == s.config && p.configSHA == s.configSHA && p.dns == s.dns &&
		reflect.DeepEqual(p.source, s.source) && reflect.DeepEqual(p.front, s.front) && reflect.DeepEqual(p.localProofs, s.local) &&
		reflect.DeepEqual(p.serverProofs, s.server) && reflect.DeepEqual(p.physical, s.physical)
}

type nodeChainExecutionProjectionSeal struct {
	owner              *NodeChainExecutionProjection
	config, hash, seal string
	transition         NodeChainExecutionTransition
}

func (p *NodeChainExecutionProjection) rememberProjectionSeal() {
	if p.policy == nil {
		return
	}
	transition := p.transition
	transition.AddedOutbounds = slices.Clone(transition.AddedOutbounds)
	p.originalSeal = &nodeChainExecutionProjectionSeal{p, p.config, p.hash, p.seal, transition}
}

func (s *nodeChainExecutionProjectionSeal) matches(p *NodeChainExecutionProjection) bool {
	return s != nil && s.owner == p && p.policy != nil && p.config == s.config && p.hash == s.hash && reflect.DeepEqual(p.transition, s.transition)
}

type nodeChainMultipleCandidatePlanSeal struct {
	owner                                                            *NodeChainCandidatePlan
	original                                                         *nodeChainCandidateMultipleOriginal
	chain                                                            *NodeChain
	source, config, inventory, revision, capture, originalSeal, seal string
	prefix                                                           NodeChainProof
	targets                                                          []hopmeasure.CandidateTarget
	measurement                                                      string
	responses                                                        []candidateResponseSource
	publicResponses                                                  []candidatePublicResponseSource
}

func (p *NodeChainCandidatePlan) rememberMultipleCandidateSeal() {
	// The ordinary inventory is immutable too. Retain independent original
	// values so each of the fifty handshakes need not encode every linked
	// candidate again. Live chain/owner checks still run for every observation.
	originalSeal := ""
	if p.multiple != nil {
		originalSeal = p.multiple.seal
	}
	p.multipleSeal = &nodeChainMultipleCandidatePlanSeal{p, p.multiple, p.chain, p.chain.SourceSHA256(), p.chain.ConfigSHA256(), p.inventory, p.revision, p.capture, originalSeal, p.seal, p.prefix, slices.Clone(p.targets), p.measurement, slices.Clone(p.responses), slices.Clone(p.publicResponses)}
}

func (s *nodeChainMultipleCandidatePlanSeal) matches(p *NodeChainCandidatePlan) bool {
	return s != nil && s.owner == p && p.chain == s.chain && p.multiple == s.original &&
		(p.multiple == nil && s.originalSeal == "" || p.multiple != nil && p.multiple.seal == s.originalSeal) &&
		p.chain.SourceSHA256() == s.source && p.chain.ConfigSHA256() == s.config && p.inventory == s.inventory && p.revision == s.revision &&
		p.measurement == s.measurement && slices.Equal(s.responses, p.responses) && (s.publicResponses == nil) == (p.publicResponses == nil) && slices.Equal(s.publicResponses, p.publicResponses) && p.capture == s.capture && p.prefix == s.prefix && (p.targets == nil) == (s.targets == nil) && slices.Equal(p.targets, s.targets)
}
