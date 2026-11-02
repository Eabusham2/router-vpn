//go:build darwin

package desktopnetwork

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

func DesktopDarwinNetworkAddress(address syscall.Sockaddr) netip.Addr {
	switch value := address.(type) {
	case *syscall.SockaddrInet4:
		return netip.AddrFrom4(value.Addr)
	case *syscall.SockaddrInet6:
		address := value.Addr
		if netip.AddrFrom16(address).IsLinkLocalUnicast() {
			address[2], address[3] = 0, 0
		}
		return netip.AddrFrom16(address)
	}
	return netip.Addr{}
}

func ParseDesktopDarwinNetworkObject(message *syscall.RouteMessage) (DesktopNetworkObject, error) {
	bad := errors.New("Darwin route has no complete native identity")
	if message == nil || message.Header.Version != syscall.RTM_VERSION || message.Header.Errno != 0 || message.Header.Index == 0 {
		return DesktopNetworkObject{}, bad
	}
	addresses, err := syscall.ParseRoutingSockaddr(message)
	if err != nil || len(addresses) <= syscall.RTAX_NETMASK {
		return DesktopNetworkObject{}, bad
	}
	destination := DesktopDarwinNetworkAddress(addresses[syscall.RTAX_DST])
	if !destination.IsValid() {
		return DesktopNetworkObject{}, bad
	}
	bits := destination.BitLen()
	if message.Header.Flags&syscall.RTF_HOST == 0 {
		mask := DesktopDarwinNetworkAddress(addresses[syscall.RTAX_NETMASK])
		if !mask.IsValid() || mask.BitLen() != bits {
			return DesktopNetworkObject{}, bad
		}
		var size int
		bits, size = net.IPMask(mask.AsSlice()).Size()
		if size != destination.BitLen() {
			return DesktopNetworkObject{}, bad
		}
	}
	family := 6
	if destination.Is4() {
		family = 4
	}
	object := DesktopNetworkObject{Kind: "route", Family: family, Index: uint32(message.Header.Index), Destination: netip.PrefixFrom(destination, bits).Masked().String(), Priority: message.Header.Rmx.Hopcount, MTU: message.Header.Rmx.Mtu, Flags: uint32(message.Header.Flags) &^ uint32(syscall.RTF_UP|syscall.RTF_DONE)}
	gateway := DesktopDarwinNetworkAddress(addresses[syscall.RTAX_GATEWAY])
	if gateway.IsValid() && !gateway.IsUnspecified() {
		object.Gateway = gateway.String()
	}
	if object.Validate("darwin") != nil {
		return DesktopNetworkObject{}, bad
	}
	return object, nil
}
