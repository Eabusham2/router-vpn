package main

import "context"

// Ordered DNS belongs to the sealed whole graph and its actual selected
// execution. A source-shaped hint selects a strict refusal path only; passing
// requires the original process, full source and current native proof.
func proveDesktopOrderedDNS(ctx context.Context, a *app, observed observedConnection, runtimeID string) (dnsProofState, bool) {
	result := dnsProofState{Status: "failed", Reason: "ordered DNS lost its original native source"}
	if a == nil {
		return result, false
	}
	graph, graphOK := getActiveMultihopGraph(a)
	raw, found := nativeMultihopOwners.Load(a)
	retained, typed := raw.(*nativeMultihopRuntime)
	ordered := graphOK && graph.ChainNodes >= 2 || observed.Mode == "multihop" && len(observed.Profile.MultihopNodes) >= 2
	if found && typed && retained != nil && (retained.launch != nil && retained.launch.chain != nil ||
		retained.selection.Native != nil && retained.selection.Native.chain != nil) {
		ordered = true
	}
	if registered, exists := desktopNodeOwners.Load(a); exists {
		if launch, ok := registered.(*desktopNodeLaunch); ok && launch != nil && launch.chain != nil {
			ordered = true
		}
	}
	if !ordered {
		return result, false
	}
	if ctx == nil || ctx.Err() != nil || !graphOK || !found || !typed || retained == nil || retained.launch == nil ||
		retained.launch.chain == nil || !retained.launch.chain.hasPolicy() {
		return result, true
	}
	owner, err := capturedNativeMultihopRuntimeContext(ctx, a, retained.launch.command, graph)
	if err != nil || owner != retained {
		return result, true
	}
	selection := owner.selection
	if !observed.Connected || observed.Phase != "connected" || observed.Mode != "multihop" || observed.RouterID != selection.Control.ID ||
		runtimeID != selection.ExitMode ||
		mtuProfileSnapshotToken(observed.Profile) != mtuProfileSnapshotToken(selection.Control) ||
		graph.ChainNodes != len(selection.Nodes) {
		return result, true
	}
	_, meta, capture, err := owner.launch.chain.readPolicy()
	if err != nil || !owner.launch.chain.metadataMatchesSelection(meta) || len(meta.Prefixes) != len(selection.Nodes) ||
		meta.ExternalFinal != nil && graph.ControlID != selection.Control.ID || meta.ExternalFinal == nil && graph.ControlID != "" {
		return result, true
	}
	result.Mode, result.Host = capture.SelectedDNS.Mode, capture.SelectedDNS.Host
	if err := proveDesktopNodeChainContext(ctx, a, selection, owner.launch.command); err != nil {
		return result, true
	}
	// The heartbeat validates the original DNS config, proof generation, reader
	// and process. It does not publish a new query time or pretend to run Retest.
	result.Status = "passed"
	result.Reason = "the original native route verified the captured final DNS policy; its source, selected execution, proof generation and reader remain current"
	return result, true
}
