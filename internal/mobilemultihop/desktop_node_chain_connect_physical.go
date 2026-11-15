package mobilemultihop

import "reflect"

// Reconstruct the exact private CONNECT/UoT proof from the captured original
// members before adapting only the TUN and physical owner. Neither inline UoT
// options nor a generic desktop graph can supply this authority. The original
// final's declaration, credentials and namespace remain mandatory.
func desktopNodeChainCONNECTPhysicalProof(original *NodeChainCONNECTSource, projected string) (*nodeChainCONNECTPhysicalProof, error) {
	if original == nil || original.desktop != nil || original.validate() != nil {
		return nil, desktopNodeChainCONNECTPolicyError
	}
	pair, middle := original.pair, original.middle
	members, closures, err := nodeChainCONNECTMembers(pair, middle)
	if err != nil {
		return nil, err
	}
	scope, err := newNodeChainCONNECTProofScope(pair, middle, closures)
	if err != nil {
		return nil, err
	}
	config, proofs, dns, physical, err := compileNodeChainClosuresWithCONNECT(members, closures, original.metadata.Physical, scope)
	if err != nil || config != original.config || !reflect.DeepEqual(proofs, original.metadata.Proofs) ||
		!reflect.DeepEqual(physical, original.metadata.Physical) {
		return nil, desktopNodeChainCONNECTPolicyError
	}
	// Compiler results gain source/config identity only after construction.
	dns.SourceSHA256, dns.ConfigSHA256 = original.metadata.DNS.SourceSHA256, original.metadata.DNS.ConfigSHA256
	if dns != original.metadata.DNS {
		return nil, desktopNodeChainCONNECTPolicyError
	}
	return scope.capturePhysical(projected, proofs)
}
