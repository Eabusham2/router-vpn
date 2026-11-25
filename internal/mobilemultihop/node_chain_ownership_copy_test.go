package mobilemultihop

// nodeChainOwnershipCopy retains the same captured values and aliased owners
// at a different graph address. Ownership refusal tests must not copy a used
// mutex or atomic, nor manufacture a different source instead of that alias.
func nodeChainOwnershipCopy(original *NodeChain) *NodeChain {
	original.runtime.mu.Lock()
	defer original.runtime.mu.Unlock()
	copy := &NodeChain{
		sourceJSON: original.sourceJSON, sourceSHA: original.sourceSHA,
		config: original.config, metadata: original.metadata, seal: original.seal,
		nodes: original.nodes, importedMiddle: original.importedMiddle,
		importedOwners: original.importedOwners, importedNodes: original.importedNodes,
		openVPNMiddle: original.openVPNMiddle, openVPNOwners: original.openVPNOwners,
		socksSource: original.socksSource, connectSource: original.connectSource,
		extendedPairedOwner:   original.extendedPairedOwner,
		extendedPairedMembers: original.extendedPairedMembers,
		typedOriginal:         original.typedOriginal, proofs: original.proofs,
		dns: original.dns, physical: original.physical,
		originalConfigSHA: original.originalConfigSHA, projection: original.projection,
		runtime: nodeChainRuntime{
			openVPN: original.runtime.openVPN, engine: original.runtime.engine,
			identity: original.runtime.identity, cancel: original.runtime.cancel,
			startDone: original.runtime.startDone, observeDone: original.runtime.observeDone,
			closed: original.runtime.closed, progress: original.runtime.progress,
			checkedAt: original.runtime.checkedAt, testTLS: original.runtime.testTLS,
			testInterval: original.runtime.testInterval,
		},
	}
	copy.runtime.generation.Store(original.runtime.generation.Load())
	return copy
}

func nodeChainOpenVPNBindingOwnershipCopy(original *nodeChainOpenVPNExecutionBinding) *nodeChainOpenVPNExecutionBinding {
	original.mu.Lock()
	defer original.mu.Unlock()
	return &nodeChainOpenVPNExecutionBinding{
		desktop: original.desktop, self: original.self, preparation: original.preparation,
		source: original.source, local: original.local, middle: original.middle,
		pair: original.pair, server: original.server, pairSHA: original.pairSHA,
		sourceSeal: original.sourceSeal, launch: original.launch, valuesSeal: original.valuesSeal,
		capture: original.capture, connected: original.connected, connectedEngine: original.connectedEngine,
	}
}
