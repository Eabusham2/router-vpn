package main

import "errors"

// Each captured process retains a separate generation and failure latch for
// its latency mailbox. DNS and fresh-proof requests cannot acknowledge it.
func capturedDesktopLatencyRuntime(launch *desktopNodeLaunch) (desktopDNSRuntimeIdentity, error) {
	identity, err := capturedDesktopDNSRuntime(launch)
	if err != nil {
		return identity, err
	}
	if owner := launch.external; owner != nil {
		identity.lock, identity.generation, identity.failed = &owner.latencyMu, &owner.latencyGeneration, &owner.latencyFailed
	} else if owner := launch.tor; owner != nil {
		identity.lock, identity.generation, identity.failed = &owner.latencyMu, &owner.latencyGeneration, &owner.latencyFailed
	} else {
		return desktopDNSRuntimeIdentity{}, errors.New("latency has no captured native external runtime")
	}
	return identity, nil
}
