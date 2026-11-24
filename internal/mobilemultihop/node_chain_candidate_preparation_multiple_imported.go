package mobilemultihop

import "encoding/json"

const nodeChainMultipleImportedCandidatePreparationKind = "routervpn-node-chain-multiple-imported-candidate-preparation"

// A complete schema-six source is retained even when only its first packet
// prefix will run. This adjunct is construction authority, not live proof.
// Copies of the registry or this adjunct cannot substitute for their owners.
type nodeChainCandidateMultipleOriginal struct {
	self     *nodeChainCandidateMultipleOriginal
	original *NodeChain
	registry *nodeChainImportedNodes
	seal     string
}

func newNodeChainCandidateMultipleOriginal(original *NodeChain) (*nodeChainCandidateMultipleOriginal, error) {
	if original == nil || original.validateCapture() != nil || original.importedNodes == nil || original.importedNodes.customEntry ||
		original.importedMiddle != nil || original.openVPNMiddle != nil || original.socksSource != nil || original.connectSource != nil {
		return nil, nodeChainCandidatePreparationError
	}
	p := &nodeChainCandidateMultipleOriginal{original: original, registry: original.importedNodes, seal: original.seal}
	p.self = p
	return p, nil
}

// The caller has just validated the complete original NodeChain. Retain its
// exact scope without repeating the full graph walk during that observation.
func (p *nodeChainCandidateMultipleOriginal) currentValidated(original *NodeChain) bool {
	return p != nil && p.self == p && original != nil && original == p.original &&
		p.registry != nil && original.importedNodes == p.registry && p.registry.owner == original &&
		p.registry.self == p.registry && p.seal != "" && p.seal == original.seal
}

// NewMultipleImportedCandidatePlan measures candidate TCP establishment only
// through an original WG/AWG prefix. Earlier imported SS transports may carry
// that packet prefix; choosing an SS stream itself retains a separate timing
// boundary because an upstream lazy socket is not a destination handshake.
func (c *NodeChain) NewMultipleImportedCandidatePlan(position int, inventory string) (*NodeChainCandidatePlan, error) {
	owner, err := newNodeChainCandidateMultipleOriginal(c)
	if err != nil {
		return nil, err
	}
	return c.newPacketCandidatePlanOwned(position, inventory, owner)
}

// NewNodeChainMultipleImportedCandidatePreparation keeps the full saved source
// for an explicit chooser Save. Its executable graph stops at the selected
// paired packet prefix; application and DNS ingress stay closed throughout.
func NewNodeChainMultipleImportedCandidatePreparation(source string, position int, inventory string) (*NodeChainCandidatePreparation, error) {
	original, err := NewNodeChain(source)
	if err != nil {
		return nil, err
	}
	owner, err := newNodeChainCandidateMultipleOriginal(original)
	if err != nil {
		return nil, err
	}
	return newNodeChainCandidatePreparationOwned(original, nil, owner, position, inventory)
}

func ParseNodeChainMultipleImportedCandidatePreparation(input string) (*NodeChainCandidatePreparation, error) {
	var source nodeChainCandidatePreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil ||
		source.Kind != nodeChainMultipleImportedCandidatePreparationKind || source.Schema != 1 {
		return nil, nodeChainCandidatePreparationError
	}
	p, err := NewNodeChainMultipleImportedCandidatePreparation(source.OriginalSource, source.PrefixPosition, source.Inventory)
	if err != nil || p == nil || p.source != input {
		return nil, nodeChainCandidatePreparationError
	}
	return p, nil
}

// An explicit source-kind query lets native adapters choose this closed
// constructor without turning a host-provided boolean into route authority.
func (p *NodeChainCandidatePreparation) IsMultipleImported() bool {
	return p != nil && p.validate() == nil && p.multipleOriginal != nil
}

// Copy-out lists exactly the imported proofs in the runnable prefix. It has
// no credentials and grants no permission to dial any other public address.
func (p *NodeChainCandidatePreparation) ImportedPrefixProofs() []NodeChainProof {
	if p == nil || p.validate() != nil || p.multipleOriginal == nil && p.candidates.measurement == "" {
		return nil
	}
	var result []NodeChainProof
	for position, proof := range p.proofs {
		if p.original.importedSSMemberAt(position) != nil {
			result = append(result, proof)
		}
	}
	return result
}

func nodeChainMultipleCandidateDomain(original *nodeChainCandidateMultipleOriginal) string {
	if original == nil {
		return "routervpn-node-chain-candidate-capture-v1"
	}
	return "routervpn-node-chain-multiple-imported-candidate-capture-v1"
}

// Retain the complete source discriminator in a descriptive seal, never a
// serialized substitute for the original process-owned registry above.
func (p *nodeChainCandidateMultipleOriginal) digest() string {
	if p == nil {
		return ""
	}
	raw, _ := json.Marshal([]string{nodeChainMultipleImportedCandidatePreparationKind, p.seal})
	return externalDigest(raw)
}
