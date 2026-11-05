package dnsmeasure

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// PublicIPv4Answers extracts only the usable answers belonging to the exact
// fresh A question (including its bounded CNAME chain). The caller still owns
// and proves the selected resolver transport; this function never resolves.
func PublicIPv4Answers(query, response []byte) ([]netip.Addr, error) {
	if err := validateAnswer(query, response); err != nil {
		return nil, err
	}
	name, end, _ := wireName(query, 12)
	if binary.BigEndian.Uint16(query[end:end+2]) != 1 || binary.BigEndian.Uint16(query[end+2:end+4]) != 1 {
		return nil, errors.New("public address extraction requires its original IN A question")
	}
	_, offset, _ := wireName(response, 12)
	offset += 4
	addresses, aliases := map[string][]netip.Addr{}, map[string]string{}
	for i := 0; i < int(binary.BigEndian.Uint16(response[6:8])); i++ {
		owner, end, _ := wireName(response, offset)
		kind, class, size := binary.BigEndian.Uint16(response[end:end+2]), binary.BigEndian.Uint16(response[end+2:end+4]), int(binary.BigEndian.Uint16(response[end+8:end+10]))
		data := end + 10
		offset = data + size
		if class != 1 {
			continue
		}
		switch kind {
		case 1:
			ip := netip.AddrFrom4([4]byte(response[data:offset]))
			if ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() {
				addresses[owner] = append(addresses[owner], ip)
			}
		case 5:
			aliases[owner], _, _ = wireName(response, data)
		}
	}
	for i := 0; i < 16; i++ {
		if aliases[name] != "" {
			name = aliases[name]
			continue
		}
		var result []netip.Addr
		seen := map[netip.Addr]bool{}
		for _, ip := range addresses[name] {
			if !seen[ip] {
				result = append(result, ip)
				seen[ip] = true
			}
		}
		if len(result) == 0 || len(result) > 16 {
			return nil, errors.New("selected DNS returned no bounded public address set")
		}
		return result, nil
	}
	return nil, errors.New("selected DNS alias chain exceeded its original bound")
}
