//go:build windows && routervpn_windows_node_composition

package mobiletor

import "net/netip"

// The real TCP import proves Getpeername and its exact connected ALE remote.
// The WG/AWG lower instead owns an unconnected UDP socket and uses WriteTo:
// its independently read ALE peer remains unspecified:0 after sending. Its
// destination is proved by the complete WFP filter readback and the fresh
// encrypted exchange with the separately retained peer, not by Getpeername.
// This predicate is test-only and does not create a production socket grant.
func desktopWindowsNodeCompositionPeerMatches(network string, actual, permitted netip.AddrPort, connected bool) bool {
	if !permitted.IsValid() || permitted.Port() == 0 || permitted.Addr().IsUnspecified() {
		return false
	}
	switch network {
	case "tcp":
		return connected && actual == permitted
	case "udp":
		return !connected && actual.IsValid() && actual.Port() == 0 && actual.Addr().IsUnspecified() && actual.Addr().Is4() == permitted.Addr().Is4()
	default:
		return false
	}
}
