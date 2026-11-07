package desktopnetwork

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// Darwin's radix masks are sockaddr-shaped byte prefixes, not necessarily
// complete IP sockaddrs. XNU rtm_scrub keeps the trimmed length for GET/GET2
// and rn_addmask may fill the pre-address header with ones. Use the original
// destination width and fixed address offset; neither the mask family byte
// nor the distance back from its trimmed end identifies the mask bytes.
// This std-only decoder is also copied into the native TUN module.
func desktopDarwinNetworkMask(addrs int32, data []byte, width int) (int, error) {
	bad := fmt.Errorf("Darwin route has no complete contiguous native mask")
	const netmaskIndex, addressCount = 2, 8
	if width != 32 && width != 128 || uint32(addrs)&^uint32((1<<addressCount)-1) != 0 || addrs&(1<<netmaskIndex) == 0 || len(data) > 8192 {
		return 0, bad
	}
	var record []byte
	for index := 0; index < addressCount; index++ {
		if addrs&(1<<index) == 0 {
			continue
		}
		if len(data) < 4 {
			return 0, bad
		}
		length := int(data[0])
		padded := max(4, (length+3)&^3)
		if padded > len(data) {
			return 0, bad
		}
		if index == netmaskIndex {
			record = data[:padded]
		}
		data = data[padded:]
	}
	if len(data) != 0 || record == nil {
		return 0, bad
	}
	length := int(record[0])
	if length == 0 {
		return 0, nil
	}
	offset, maximum := 4, 16 // Darwin sockaddr_in.sin_addr / sizeof(sockaddr_in)
	if width == 128 {
		offset, maximum = 8, 28 // sockaddr_in6.sin6_addr / sizeof(sockaddr_in6)
	}
	if length <= offset || length > maximum {
		return 0, bad
	}
	mask := make(net.IPMask, width/8)
	copy(mask, record[offset:min(length, offset+len(mask))])
	for _, value := range record[min(length, offset+len(mask)):length] {
		if value != 0 { // A native scope or other suffix cannot become mask bits.
			return 0, bad
		}
	}
	ones, bits := mask.Size()
	if bits != width {
		return 0, bad
	}
	return ones, nil
}

// The supported desktop Linux architectures are little endian. These parsers
// are also compiled on the other hosts so canonical receipts can be checked
// without loading a platform library or consulting a mutable network.
func ParseDesktopLinuxNetworkObject(kind string, body []byte) (DesktopNetworkObject, error) {
	bad := fmt.Errorf("Linux routing notification is incomplete or ambiguous (kind=%s bytes=%d family=%d)", kind, len(body), func() byte {
		if len(body) != 0 {
			return body[0]
		}
		return 0
	}())
	if kind != "route" && kind != "rule" || len(body) < 12 || len(body) > 8192 {
		return DesktopNetworkObject{}, bad
	}
	family, bits := 0, 0
	switch body[0] {
	case 2:
		family, bits = 4, 32
	case 10:
		family, bits = 6, 128
	case 128: // RTNL_FAMILY_IPMR: a distinct multicast FIB, not IPv4 ownership.
		family, bits = 128, 32
	case 129: // RTNL_FAMILY_IP6MR: a distinct multicast FIB, not IPv6 ownership.
		family, bits = 129, 128
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
			if !ok || address.Is4() != (bits == 32) {
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
		if !ok || address.Is4() != (bits == 32) {
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

// DesktopLinuxRuleResolvedBy recognizes only the kernel's resolution of one
// otherwise byte-identical GOTO after its exact same-family NOP target exists.
// The caller must separately prove both successful installs belong to its
// original native TUN; this predicate carries no policy mutation authority.
func DesktopLinuxRuleResolvedBy(before, after, target DesktopNetworkObject) bool {
	if before.Kind != "rule" || after.Kind != "rule" || target.Kind != "rule" ||
		before.Family != 4 && before.Family != 6 || after.Family != before.Family || target.Family != before.Family ||
		before.Flags&4 == 0 || after.Flags&4 != 0 || before.Flags^after.Flags != 4 || target.Priority <= before.Priority ||
		before.Validate("linux") != nil || after.Validate("linux") != nil || target.Validate("linux") != nil {
		return false
	}
	old, _ := base64.StdEncoding.Strict().DecodeString(before.Native)
	current, _ := base64.StdEncoding.Strict().DecodeString(after.Native)
	to, _ := base64.StdEncoding.Strict().DecodeString(target.Native)
	if len(old) < 12 || len(current) < 12 || len(to) < 12 || old[7] != 2 /* FR_ACT_GOTO */ || to[7] != 3 /* FR_ACT_NOP */ {
		return false
	}
	binary.LittleEndian.PutUint32(old[8:12], after.Flags)
	if !bytes.Equal(old, current) {
		return false
	}
	for offset := 12; offset < len(current); {
		length := int(binary.LittleEndian.Uint16(current[offset:]))
		id := binary.LittleEndian.Uint16(current[offset+2:])
		if id == 4 /* FRA_GOTO */ {
			return length == 8 && binary.LittleEndian.Uint32(current[offset+4:]) == target.Priority
		}
		offset += (length + 3) &^ 3
	}
	return false
}
