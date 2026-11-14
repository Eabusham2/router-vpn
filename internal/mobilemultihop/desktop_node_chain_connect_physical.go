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
	first, err := nodeMultihopPredecessor(pair.nodes[0])
	if err != nil {
		return nil, err
	}
	custom, err := middle.closure()
	if err != nil {
		return nil, err
	}
	final, err := nodeMultihopPredecessor(pair.nodes[1])
	if err != nil {
		return nil, err
	}
	closures := []*externalPredecessor{first, custom, final}
	scope, err := newNodeChainCONNECTProofScope(pair, middle, closures)
	if err != nil {
		return nil, err
	}
	members := []nodeChainGraphMember{
		{profile: pair.nodes[0].profile, source: pair.nodes[0].source, mode: pair.nodes[0].mode},
		{profile: middle.selection.Profile, source: middle.source, mode: middle.selection.Protocol, imported: true},
		{profile: pair.nodes[1].profile, source: pair.nodes[1].source, mode: "shadowsocks"},
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
