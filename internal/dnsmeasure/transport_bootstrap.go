package dnsmeasure

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// TransportBootstrapQuery is exclusively a captured outer transport hostname
// question. It does not select a resolver or change payload/selected DNS policy.
func TransportBootstrapQuery(host string, ipv6 bool) ([]byte, error) {
	if len(host) == 0 || len(host) > 253 || strings.TrimSpace(host) != host || strings.HasSuffix(host, ".") {
		return nil, errors.New("invalid captured bootstrap hostname")
	}
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, errors.New("invalid bootstrap label")
		}
		q = append(q, byte(len(label)))
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return nil, errors.New("invalid bootstrap label")
			}
			q = append(q, c)
		}
	}
	kind := byte(1)
	if ipv6 {
		kind = 28
	}
	q = append(q, 0, 0, kind, 0, 1)
	_, err := rand.Read(q[:2])
	return q, err
}

// TransportBootstrapAnswers accepts only the exact original IN A/AAAA question
// and its bounded CNAME chain. Empty NOERROR is a valid family result; NXDOMAIN,
// truncation, unrelated records, malformed framing and ambiguous aliases cannot
// supply an address. Private unicast remains allowed for private Node endpoints.
func TransportBootstrapAnswers(q, r []byte) ([]netip.Addr, error) {
	bad := errors.New("invalid captured transport bootstrap answer")
	if len(q) < 17 || len(r) < 12 || len(r) > 16<<10 || !bytes.Equal(q[:2], r[:2]) || r[2]&0xfa != 0x80 || r[3]&0x4f != 0 || binary.BigEndian.Uint16(r[4:6]) != 1 {
		return nil, bad
	}
	name, end, err := wireName(q, 12)
	if err != nil || end+4 != len(q) {
		return nil, bad
	}
	kind := binary.BigEndian.Uint16(q[end : end+2])
	if kind != 1 && kind != 28 || binary.BigEndian.Uint16(q[end+2:]) != 1 {
		return nil, bad
	}
	got, offset, err := wireName(r, 12)
	if err != nil || offset+4 > len(r) || got != name || !bytes.Equal(q[end:], r[offset:offset+4]) {
		return nil, bad
	}
	offset += 4
	answers := int(binary.BigEndian.Uint16(r[6:8]))
	total := answers + int(binary.BigEndian.Uint16(r[8:10])) + int(binary.BigEndian.Uint16(r[10:12]))
	if answers > 128 || total > 256 {
		return nil, bad
	}
	aliases := map[string]string{}
	addresses := map[string][]netip.Addr{}
	for i := 0; i < total; i++ {
		owner, e, err := wireName(r, offset)
		if err != nil || e+10 > len(r) {
			return nil, bad
		}
		typ, class, size := binary.BigEndian.Uint16(r[e:e+2]), binary.BigEndian.Uint16(r[e+2:e+4]), int(binary.BigEndian.Uint16(r[e+8:e+10]))
		data := e + 10
		offset = data + size
		if offset > len(r) {
			return nil, bad
		}
		if typ == 1 && size != 4 || typ == 28 && size != 16 {
			return nil, bad
		}
		var alias string
		if typ == 5 {
			var next int
			alias, next, err = wireName(r, data)
			if err != nil || next != offset {
				return nil, bad
			}
		}
		if i >= answers || class != 1 {
			continue
		}
		if typ == 5 {
			if previous := aliases[owner]; previous != "" && previous != alias {
				return nil, bad
			}
			aliases[owner] = alias
		}
		if typ == kind {
			ip, ok := netip.AddrFromSlice(r[data:offset])
			if !ok || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() {
				return nil, bad
			}
			addresses[owner] = append(addresses[owner], ip)
		}
	}
	if offset != len(r) {
		return nil, bad
	}
	seen := map[string]bool{}
	for hop := 0; hop < 16; hop++ {
		if seen[name] {
			return nil, bad
		}
		seen[name] = true
		if next := aliases[name]; next != "" {
			if len(addresses[name]) != 0 {
				return nil, bad
			}
			name = next
			continue
		}
		result := []netip.Addr{}
		unique := map[netip.Addr]bool{}
		for _, ip := range addresses[name] {
			if !unique[ip] {
				unique[ip] = true
				result = append(result, ip)
			}
		}
		if len(result) > 32 {
			return nil, bad
		}
		return result, nil
	}
	return nil, bad
}
