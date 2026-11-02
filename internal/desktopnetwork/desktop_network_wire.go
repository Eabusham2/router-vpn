package desktopnetwork

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
)

// The supported desktop Linux architectures are little endian. These parsers
// are also compiled on the other hosts so canonical receipts can be checked
// without loading a platform library or consulting a mutable network.
func ParseDesktopLinuxNetworkObject(kind string, body []byte) (DesktopNetworkObject, error) {
	bad := errors.New("Linux routing notification is incomplete or ambiguous")
	if kind != "route" && kind != "rule" || len(body) < 12 || len(body) > 8192 {
		return DesktopNetworkObject{}, bad
	}
	family, bits := 0, 0
	switch body[0] {
	case 2:
		family, bits = 4, 32
	case 10:
		family, bits = 6, 128
	default:
		return DesktopNetworkObject{}, bad
	}
	if int(body[1]) > bits || int(body[2]) > bits {
		return DesktopNetworkObject{}, bad
	}
	type attribute struct {
		kind  uint16
		value []byte
	}
	var attrs []attribute
	seen := make(map[uint16]bool)
	for offset := 12; offset < len(body); {
		if len(body)-offset < 4 {
			return DesktopNetworkObject{}, bad
		}
		length := int(binary.LittleEndian.Uint16(body[offset:]))
		id := binary.LittleEndian.Uint16(body[offset+2:])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(body)-offset || seen[id] {
			return DesktopNetworkObject{}, bad
		}
		seen[id] = true
		for _, padding := range body[offset+length : offset+aligned] {
			if padding != 0 {
				return DesktopNetworkObject{}, bad
			}
		}
		// Cache ages and remaining expiry times change without a route change.
		// Their eventual delete notification is still a separate latched event.
		if !(kind == "route" && (id == 12 || id == 23)) {
			attrs = append(attrs, attribute{id, append([]byte(nil), body[offset+4:offset+length]...)})
		}
		offset += aligned
	}
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].kind < attrs[j].kind })
	canonical := append([]byte(nil), body[:12]...)
	o := DesktopNetworkObject{Kind: kind, Family: family, Table: uint32(body[4]), Flags: binary.LittleEndian.Uint32(body[8:])}
	var destination []byte
	for _, attr := range attrs {
		length := 4 + len(attr.value)
		encoded := make([]byte, (length+3)&^3)
		binary.LittleEndian.PutUint16(encoded, uint16(length))
		binary.LittleEndian.PutUint16(encoded[2:], attr.kind)
		copy(encoded[4:], attr.value)
		canonical = append(canonical, encoded...)
		switch {
		case attr.kind == 15: // RTA_TABLE and FRA_TABLE share their UAPI value.
			if len(attr.value) != 4 {
				return DesktopNetworkObject{}, bad
			}
			table := binary.LittleEndian.Uint32(attr.value)
			// RT_TABLE_COMPAT is the kernel header sentinel when the full
			// table ID is carried in RTA_TABLE/FRA_TABLE. Preserve both bytes.
			if o.Table != 0 && o.Table != 252 && o.Table != table {
				return DesktopNetworkObject{}, bad
			}
			o.Table = table
		case attr.kind == 6:
			if len(attr.value) != 4 {
				return DesktopNetworkObject{}, bad
			}
			o.Priority = binary.LittleEndian.Uint32(attr.value)
		case kind == "route" && attr.kind == 4:
			if len(attr.value) != 4 {
				return DesktopNetworkObject{}, bad
			}
			o.Index = binary.LittleEndian.Uint32(attr.value)
		case kind == "route" && attr.kind == 1:
			destination = attr.value
		case kind == "route" && attr.kind == 5:
			address, ok := netip.AddrFromSlice(attr.value)
			if !ok || address.Is4() != (family == 4) {
				return DesktopNetworkObject{}, bad
			}
			o.Gateway = address.String()
		}
	}
	if kind == "route" {
		if destination == nil {
			if body[1] != 0 {
				return DesktopNetworkObject{}, bad
			}
			destination = make([]byte, bits/8)
		}
		address, ok := netip.AddrFromSlice(destination)
		if !ok || address.Is4() != (family == 4) {
			return DesktopNetworkObject{}, bad
		}
		prefix := netip.PrefixFrom(address, int(body[1]))
		if prefix != prefix.Masked() {
			return DesktopNetworkObject{}, bad
		}
		o.Destination = prefix.String()
	}
	o.Native = base64.StdEncoding.EncodeToString(canonical)
	return o, nil
}
