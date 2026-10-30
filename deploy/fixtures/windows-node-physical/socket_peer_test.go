//go:build windows && routervpn_windows_node_composition

package mobiletor

import (
	"net/netip"
	"testing"
)

// These executable predicate cases complement the actual kernel/peer test.
// They do not model successful socket ownership or encrypted network traffic.
func TestWindowsNodeObserverTransportPeer(t *testing.T) {
	for _, addresses := range [][3]string{{"192.0.2.1:4567", "192.0.2.2:4567", "0.0.0.0:0"}, {"[2001:db8::1]:4567", "[2001:db8::2]:4567", "[::]:0"}} {
		permitted, other, unset := netip.MustParseAddrPort(addresses[0]), netip.MustParseAddrPort(addresses[1]), netip.MustParseAddrPort(addresses[2])
		wrongFamily := netip.MustParseAddrPort("0.0.0.0:0")
		if permitted.Addr().Is4() {
			wrongFamily = netip.MustParseAddrPort("[::]:0")
		}
		t.Run(permitted.String(), func(t *testing.T) {
			for _, test := range []struct {
				name, network string
				actual, peer  netip.AddrPort
				connected     bool
				want          bool
			}{
				{"connected-tcp", "tcp", permitted, permitted, true, true},
				{"unconnected-udp", "udp", unset, permitted, false, true},
				{"tcp-not-connected", "tcp", permitted, permitted, false, false},
				{"tcp-wrong-peer", "tcp", other, permitted, true, false},
				{"tcp-missing-peer", "tcp", unset, permitted, true, false},
				{"udp-connected", "udp", permitted, permitted, true, false},
				{"udp-invented-peer", "udp", permitted, permitted, false, false},
				{"udp-wrong-peer", "udp", other, permitted, false, false},
				{"udp-peer-port", "udp", netip.AddrPortFrom(unset.Addr(), 4567), permitted, false, false},
				{"udp-wrong-family", "udp", wrongFamily, permitted, false, false},
				{"udp-missing-readback", "udp", netip.AddrPort{}, permitted, false, false},
				{"missing-permit", "udp", unset, netip.AddrPort{}, false, false},
				{"unspecified-permit", "udp", unset, netip.AddrPortFrom(unset.Addr(), 4567), false, false},
				{"portless-permit", "udp", unset, netip.AddrPortFrom(permitted.Addr(), 0), false, false},
				{"unknown-transport", "other", permitted, permitted, true, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					if got := desktopWindowsNodeCompositionPeerMatches(test.network, test.actual, test.peer, test.connected); got != test.want {
						t.Fatalf("transport-specific peer readback changed: got %t, want %t", got, test.want)
					}
				})
			}
		})
	}
}
