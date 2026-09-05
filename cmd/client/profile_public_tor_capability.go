package main

import "router-vpn/internal/common"

// publicCapabilityForProfile keeps the generic protocol capability table for
// ordinary external nodes, but Tor must be resolved against the exact saved PT
// set. This prevents a machine with only legacy obfs4proxy from advertising a
// Snowflake/WebTunnel node as runnable merely because the broad Tor family has
// some supported transport.
func publicCapabilityForProfile(p common.RouterProfile, caps []standardExitCapability) (standardExitCapability, bool) {
	if p.External != nil && normalizeStandardExitProtocol(p.External.Protocol) == "tor-bridge" {
		return torBridgeProfileRuntimeCapability(p), true
	}
	return publicCapabilityForProtocol(caps, func() string {
		if p.External == nil {
			return ""
		}
		return p.External.Protocol
	}())
}
