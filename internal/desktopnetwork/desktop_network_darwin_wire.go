//go:build darwin

package desktopnetwork

import (
	"encoding/binary"
	"errors"
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
		bits, err = desktopDarwinNetworkMask(message.Header.Addrs, message.Data, bits)
		if err != nil {
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

// The observer and generated native TUN consume the same original DUMP2
// observation. The older DUMP format does not carry the reference/parent
// fields required to classify an idle cache row, so it is never a fallback.
func desktopDarwinReadRouteDump2(read func(int, int) ([]byte, error)) ([]DesktopNetworkObject, error) {
	if read == nil {
		return nil, errors.New("Darwin route inventory has no original native reader")
	}
	raw, err := read(syscall.NET_RT_DUMP2, 0)
	if err != nil || len(raw) > 4<<20 {
		return nil, errors.Join(errors.New("Darwin network inventory is unavailable or unbounded"), err)
	}
	return darwinRouteDump2(raw)
}

// rt_msghdr2 has the same public native size as rt_msghdr, but its middle
// fields are refcnt/parentflags/reserved, not pid/seq/errno. Decode them by value
// rather than aliasing either Go pointer-bearing RoutingMessage structure.
// XNU rtsock.c sysctl_dumpentry fills these under the original route lock.
type desktopDarwinRouteHeader2 struct {
	Msglen                            uint16
	Version, Type                     uint8
	Index                             uint16
	Padding                           [2]byte
	Flags, Addrs                      int32
	References, ParentFlags, Reserved int32
	Use                               int32
	Inits                             uint32
	Rmx                               syscall.RtMetrics
}

func darwinRouteDump2(raw []byte) ([]DesktopNetworkObject, error) {
	bad := errors.New("Darwin DUMP2 inventory has an incomplete native route observation")
	if len(raw) > 4<<20 || binary.Size(desktopDarwinRouteHeader2{}) != syscall.SizeofRtMsghdr {
		return nil, bad
	}
	var objects []DesktopNetworkObject
	for len(raw) > 0 {
		if len(raw) < 4 || len(objects) >= 32768 {
			return nil, bad
		}
		length := int(binary.LittleEndian.Uint16(raw))
		if length < syscall.SizeofRtMsghdr || length > len(raw) || raw[2] != syscall.RTM_VERSION || raw[3] != syscall.RTM_GET2 {
			return nil, bad
		}
		frame := raw[:length]
		raw = raw[length:]
		var header desktopDarwinRouteHeader2
		count, err := binary.Decode(frame[:syscall.SizeofRtMsghdr], binary.LittleEndian, &header)
		if err != nil || count != syscall.SizeofRtMsghdr || header.Reserved != 0 || header.Index == 0 {
			return nil, bad
		}
		data := make([]byte, len(frame)-syscall.SizeofRtMsghdr)
		copy(data, frame[syscall.SizeofRtMsghdr:])
		if !darwinDump2AddressesComplete(header.Addrs, data) {
			return nil, bad
		}
		message := &syscall.RouteMessage{Header: syscall.RtMsghdr{Msglen: header.Msglen, Version: header.Version, Type: header.Type,
			Index: header.Index, Flags: header.Flags, Addrs: header.Addrs, Use: header.Use, Inits: header.Inits, Rmx: header.Rmx}, Data: data}
		object, err := ParseDesktopDarwinNetworkObject(message)
		if err != nil {
			return nil, bad
		}
		object = desktopDarwinCaptureCacheObservation(object, uint32(header.Flags), uint32(header.ParentFlags), header.References, header.Rmx.Expire)
		objects = append(objects, object)
	}
	return objects, nil
}

// The native routing ABI rounds sockaddr records to four bytes, including an
// empty default-route mask. Account for every declared address before the Go
// sockaddr adapter reads it; additional/truncated native bytes remain refused.
func darwinDump2AddressesComplete(addrs int32, data []byte) bool {
	if addrs <= 0 || uint32(addrs)&^uint32((1<<syscall.RTAX_MAX)-1) != 0 {
		return false
	}
	for index := 0; index < syscall.RTAX_MAX; index++ {
		if addrs&(1<<index) == 0 {
			continue
		}
		if len(data) < 4 {
			return false
		}
		length := int(data[0])
		if index == syscall.RTAX_DST && data[1] != syscall.AF_INET && data[1] != syscall.AF_INET6 {
			return false
		}
		switch data[1] {
		case syscall.AF_INET:
			if length < syscall.SizeofSockaddrInet4 {
				return false
			}
		case syscall.AF_INET6:
			if length < syscall.SizeofSockaddrInet6 {
				return false
			}
		case syscall.AF_LINK:
			if length < 8 || len(data) < 8 || 8+int(data[5])+int(data[6])+int(data[7]) > length {
				return false
			}
		}
		padded := (length + 3) &^ 3
		if padded == 0 {
			padded = 4
		}
		if length > len(data) || padded > len(data) {
			return false
		}
		data = data[padded:]
	}
	return len(data) == 0
}
