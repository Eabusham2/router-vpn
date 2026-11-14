package main

// This selects the target from the exact retained concrete policy. It does not
// observe a process, network, interface, or proof, and cannot replace Current.
// Reading the launch also checks its original source pointer, so a parsed copy
// with equal bytes cannot acquire the captured policy's authority.
func orderedPerformanceSnapshotTarget(captured *mtuNodeChainSnapshot) string {
	if captured == nil || captured.Chain == nil || captured.Execution != nil || captured.Chain.execution != nil ||
		captured.Policy != captured.Chain.policy ||
		captured.SOCKSPolicy != captured.Chain.socksPolicy ||
		captured.CONNECTPolicy != captured.Chain.connectPolicy ||
		desktopNodeChainConcretePolicyCount(captured.Policy, captured.SOCKSPolicy, captured.CONNECTPolicy) != 1 {
		return ""
	}
	_, meta, _, err := captured.Chain.readLaunchPolicy()
	if err != nil {
		return ""
	}
	return meta.TargetOS
}
