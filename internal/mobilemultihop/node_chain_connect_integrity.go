package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

// These receipts cache no native observation. The original constructors still
// compile and validate the complete graph. Each later read compares every
// retained input against a private deep copy, without serializing the same
// immutable source/config strings or traversing the same graph again.
type nodeChainCONNECTIntegrity struct {
	owner                *NodeChainCONNECTSource
	source, config, seal string
	metadata             NodeChainCONNECTSourceMetadata
	pair                 *NodeChain
	paired               nodeChainCONNECTPairIntegrity
	middle               *nodeChainCONNECTMember
	imported             nodeChainCONNECTMemberIntegrity
	desktop              *nodeChainCONNECTDesktopBinding
	binding              nodeChainCONNECTBindingIntegrity
}

type nodeChainCONNECTPairIntegrity struct {
	sourceJSON, sourceSHA, config, metadata, seal, originalConfigSHA string
	proofs                                                           []NodeChainProof
	dns                                                              NodeChainDNSCapture
	physical                                                         []PhysicalEgress
	projection                                                       nodeChainProjection
	nodes                                                            [2]*NodeProfile
	values                                                           [2]NodeProfile
}

type nodeChainCONNECTMemberIntegrity struct {
	input, source, seal string
	selection           externalPolicyCapture
	policy              *ExternalPolicy
	compiled            ExternalPolicy
}

type nodeChainCONNECTBindingIntegrity struct {
	original       *NodeChainCONNECTSource
	projection     nodeChainProjection
	metadata       DesktopNodeChainCONNECTMetadata
	nativeMetadata NodeChainCONNECTSourceMetadata
	seal           string
}

func nodeChainCONNECTIntegrityCopy[T any](value T) (T, error) {
	var copied T
	raw, err := json.Marshal(value)
	if err != nil {
		return copied, err
	}
	defer clear(raw)
	err = json.Unmarshal(raw, &copied)
	return copied, err
}

// Called only after the original complete constructor/derivation validation.
// No read can install, refresh or replace this receipt.
func (p *NodeChainCONNECTSource) retainIntegrity() error {
	if p == nil || p.integrity != nil || p.validateCompiled() != nil ||
		p.pair.importedMiddle != nil || p.pair.socksSource != nil || p.pair.connectSource != nil || len(p.pair.nodes) != 2 {
		return nodeChainCONNECTSourceError
	}
	saved := &nodeChainCONNECTIntegrity{
		owner: p, source: p.sourceJSON, config: p.config, seal: p.seal,
		pair: p.pair, middle: p.middle, desktop: p.desktop,
	}
	var err error
	saved.metadata, err = nodeChainCONNECTIntegrityCopy(p.metadata)
	if err != nil {
		return nodeChainCONNECTSourceError
	}
	pair := p.pair
	saved.paired = nodeChainCONNECTPairIntegrity{
		sourceJSON: pair.sourceJSON, sourceSHA: pair.sourceSHA, config: pair.config,
		metadata: pair.metadata, seal: pair.seal, originalConfigSHA: pair.originalConfigSHA,
		dns: pair.dns, projection: pair.projection,
		proofs:   append([]NodeChainProof(nil), pair.proofs...),
		physical: append([]PhysicalEgress(nil), pair.physical...),
	}
	for i, node := range pair.nodes {
		if node == nil {
			return nodeChainCONNECTSourceError
		}
		saved.paired.nodes[i], saved.paired.values[i] = node, *node
		saved.paired.values[i].profile, err = nodeChainCONNECTIntegrityCopy(node.profile)
		if err != nil {
			return nodeChainCONNECTSourceError
		}
	}
	middle := p.middle
	saved.imported = nodeChainCONNECTMemberIntegrity{
		input: middle.input, source: middle.source, seal: middle.seal, policy: middle.policy,
		compiled: *middle.policy,
	}
	saved.imported.selection, err = nodeChainCONNECTIntegrityCopy(middle.selection)
	if err != nil {
		return nodeChainCONNECTSourceError
	}
	saved.imported.compiled.capture, err = nodeChainCONNECTIntegrityCopy(middle.policy.capture)
	if err != nil {
		return nodeChainCONNECTSourceError
	}
	if p.desktop != nil {
		binding := p.desktop
		saved.binding = nodeChainCONNECTBindingIntegrity{
			original: binding.original, projection: binding.projection, seal: binding.seal,
		}
		saved.binding.metadata, err = nodeChainCONNECTIntegrityCopy(binding.metadata)
		if err != nil {
			return nodeChainCONNECTSourceError
		}
		saved.binding.nativeMetadata, err = nodeChainCONNECTIntegrityCopy(binding.nativeMetadata)
		if err != nil {
			return nodeChainCONNECTSourceError
		}
	}
	if !saved.current(p) {
		return nodeChainCONNECTSourceError
	}
	p.integrity = saved
	return nil
}

func (saved *nodeChainCONNECTIntegrity) current(p *NodeChainCONNECTSource) bool {
	if saved == nil || p == nil || saved.owner != p ||
		p.sourceJSON != saved.source || p.config != saved.config || p.seal != saved.seal ||
		p.pair != saved.pair || p.middle != saved.middle || p.desktop != saved.desktop ||
		!reflect.DeepEqual(p.metadata, saved.metadata) {
		return false
	}
	pair, old := p.pair, &saved.paired
	if pair == nil || pair.importedMiddle != nil || pair.socksSource != nil || pair.connectSource != nil ||
		pair.sourceJSON != old.sourceJSON || pair.sourceSHA != old.sourceSHA ||
		pair.config != old.config || pair.metadata != old.metadata || pair.seal != old.seal ||
		pair.originalConfigSHA != old.originalConfigSHA || pair.dns != old.dns ||
		pair.projection != old.projection || len(pair.nodes) != len(old.nodes) ||
		!reflect.DeepEqual(pair.proofs, old.proofs) || !reflect.DeepEqual(pair.physical, old.physical) {
		return false
	}
	for i, node := range pair.nodes {
		if node != old.nodes[i] || node == nil || !reflect.DeepEqual(*node, old.values[i]) {
			return false
		}
	}
	middle, imported := p.middle, &saved.imported
	if middle == nil || middle.policy == nil || middle.policy != imported.policy ||
		middle.input != imported.input || middle.source != imported.source || middle.seal != imported.seal ||
		!reflect.DeepEqual(middle.selection, imported.selection) ||
		!reflect.DeepEqual(*middle.policy, imported.compiled) {
		return false
	}
	if p.desktop != nil {
		binding, prior := p.desktop, &saved.binding
		if binding.original == nil || binding.original != prior.original ||
			binding.original.desktop != nil || binding.original.validate() != nil ||
			binding.projection != prior.projection || binding.seal != prior.seal ||
			!reflect.DeepEqual(binding.metadata, prior.metadata) ||
			!reflect.DeepEqual(binding.nativeMetadata, prior.nativeMetadata) {
			return false
		}
	}
	return true
}
