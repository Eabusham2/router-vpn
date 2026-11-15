//go:build windows && routervpn_windows_candidate_prefix_native

package routervpnamnezia

import (
	"errors"
	"net"
	"net/netip"
)

// This adapter grants only the same-host Windows provider's actual selected
// physical interface. The two private relay addresses must be assigned to that
// exact interface; a global successful socket or a requested address is not
// evidence that the retained provider is bound there.
func connectExecutionPhysicalPeer(local, remote netip.Addr) error {
	bad := errors.New("Windows execution peer lost original physical interface and private aliases")
	if !local.Is4() || !local.IsPrivate() || local != remote || !desktopWindowsPrefixReferenceAddressPair(local.String(), remote.String()) {
		return bad
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	selected, aliases := 0, map[netip.Addr]int{}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return err
			}
			ip := prefix.Addr().Unmap()
			if ip == local {
				if selected != 0 || iface.Index <= 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
					return bad
				}
				selected = iface.Index
			}
			if ip == netip.MustParseAddr("10.78.0.1") || ip == netip.MustParseAddr("10.78.0.2") {
				if aliases[ip] != 0 || prefix.Bits() != 32 {
					return bad
				}
				aliases[ip] = iface.Index
			}
		}
	}
	if selected == 0 || aliases[netip.MustParseAddr("10.78.0.1")] != selected || aliases[netip.MustParseAddr("10.78.0.2")] != selected {
		return bad
	}
	return nil
}
