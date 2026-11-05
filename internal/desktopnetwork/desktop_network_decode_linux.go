//go:build linux

package desktopnetwork

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// These decoded values contain observation only. Keeping the pure parser apart
// from native event subscriptions lets no-TUN helpers share exact validation
// without importing tracker, receipt, or mutation authority.
type linuxLinkValue struct {
	Index    uint32
	Name     string
	MTU      int
	Flags    uint32
	Hardware string
}
type linuxAddressValue struct {
	Index  uint32
	Prefix string
}

func linuxAttributes(body []byte, offset int) (map[uint16][]byte, error) {
	attributes := make(map[uint16][]byte)
	for offset < len(body) {
		if len(body)-offset < 4 {
			return nil, errors.New("Linux network attribute is truncated")
		}
		length := int(binary.LittleEndian.Uint16(body[offset:]))
		kind := binary.LittleEndian.Uint16(body[offset+2:])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(body)-offset || attributes[kind] != nil {
			return nil, errors.New("Linux network attribute has invalid size or duplicate identity")
		}
		attributes[kind] = append([]byte(nil), body[offset+4:offset+length]...)
		offset += aligned
	}
	return attributes, nil
}

func decodeLinuxLink(body []byte) (linuxLinkValue, error) {
	if len(body) < 16 {
		return linuxLinkValue{}, errors.New("Linux link notification is incomplete")
	}
	attrs, err := linuxAttributes(body, 16)
	if err != nil {
		return linuxLinkValue{}, err
	}
	name := attrs[3]
	if len(name) < 2 || name[len(name)-1] != 0 || len(attrs[4]) != 4 {
		return linuxLinkValue{}, errors.New("Linux link notification lost its name or MTU")
	}
	for _, b := range name[:len(name)-1] {
		if b == 0 {
			return linuxLinkValue{}, errors.New("Linux link name is not canonical")
		}
	}
	return linuxLinkValue{Index: binary.LittleEndian.Uint32(body[4:]), Name: string(name[:len(name)-1]), MTU: int(binary.LittleEndian.Uint32(attrs[4])), Flags: binary.LittleEndian.Uint32(body[8:]), Hardware: net.HardwareAddr(attrs[1]).String()}, nil
}

func decodeLinuxAddress(body []byte) (linuxAddressValue, error) {
	if len(body) < 8 {
		return linuxAddressValue{}, errors.New("Linux address notification is incomplete")
	}
	attrs, err := linuxAttributes(body, 8)
	if err != nil {
		return linuxAddressValue{}, err
	}
	address := attrs[2] // IFA_LOCAL, or IFA_ADDRESS for IPv6
	if address == nil {
		address = attrs[1]
	}
	ip, ok := netip.AddrFromSlice(address)
	if !ok || body[0] != syscall.AF_INET && body[0] != syscall.AF_INET6 || ip.Is4() != (body[0] == syscall.AF_INET) || int(body[1]) > ip.BitLen() {
		return linuxAddressValue{}, errors.New("Linux address notification changed its family or prefix")
	}
	return linuxAddressValue{Index: binary.LittleEndian.Uint32(body[4:]), Prefix: netip.PrefixFrom(ip, int(body[1])).String()}, nil
}
