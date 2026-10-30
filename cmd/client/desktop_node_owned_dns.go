package main

import "context"

// This reports the native query already required before Connected. It never
// performs an unrelated OS lookup or calls an old query a new Retest result.
func proveDesktopOwnedNodeDNS(ctx context.Context, a *app, observed observedConnection, runtimeID string, selected dnsSelection, launch *desktopNodeLaunch) dnsProofState {
	result := dnsProofState{Mode: selected.Mode, Host: selected.Host, Status: "failed"}
	if ctx == nil || ctx.Err() != nil || launch == nil || launch.ownedNode == nil || !observed.Connected || observed.Phase != "connected" ||
		observed.RouterID != launch.profileID || runtimeID != launch.mode || desktopOwnedNodeProfileToken(observed.Profile) != launch.ownedNode.profileToken {
		result.Reason = "selected native DNS proof no longer belongs to this connection"
		return result
	}
	a.mu.Lock()
	connected := a.state.Connected && a.state.Phase == "connected" && a.cmd == launch.command
	a.mu.Unlock()
	if !connected {
		result.Reason = "selected native DNS path is not connected"
		return result
	}
	record, err := a.readDesktopOwnedNodeReady(launch, false)
	if err != nil || ctx.Err() != nil {
		result.Reason = "selected native DNS query has lost its captured running owner"
		return result
	}
	result.Status, result.LatencyMs = "passed", record.DNSMilliseconds
	result.Reason = "a fresh query through the captured native DNS router proved the selected resolver before connection; the same source and process remain current"
	return result
}
