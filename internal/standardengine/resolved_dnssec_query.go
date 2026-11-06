package standardengine

import (
	"encoding/binary"
	"errors"
	"strings"
)

// ResolvedDNSSECQuestionFromWire permits only the captured address question and
// DS/DNSKEY queries for its exact ancestor names. It grants no resolver or
// socket authority. A CNAME/DNAME target needs its own captured original plan;
// neither a sibling name nor an arbitrary type inherits the first name's grant.
func ResolvedDNSSECQuestionFromWire(originalName string, originalType uint16, wire []byte) (ResolvedDNSSECQuestion, error) {
	bad := errors.New("DNSSEC query escaped its captured name, type or bounded wire shape")
	var result ResolvedDNSSECQuestion
	if !ResolvedName(originalName, false) || originalType != 1 && originalType != 28 || len(wire) < 17 || len(wire) > 12+255+4+11 {
		return result, bad
	}
	if wire[2] != 1 || wire[3]&^byte(0x30) != 0 || binary.BigEndian.Uint16(wire[4:6]) != 1 || binary.BigEndian.Uint16(wire[6:8]) != 0 || binary.BigEndian.Uint16(wire[8:10]) != 0 || binary.BigEndian.Uint16(wire[10:12]) > 1 {
		return result, bad
	}
	var labels []string
	offset := 12
	for {
		if offset >= len(wire) {
			return result, bad
		}
		size := int(wire[offset])
		offset++
		if size == 0 {
			break
		}
		if size > 63 || offset+size >= len(wire) {
			return result, bad
		}
		label := string(wire[offset : offset+size])
		if !ResolvedName(label, false) || strings.Contains(label, ".") {
			return result, bad
		}
		labels = append(labels, strings.ToLower(label))
		offset += size
	}
	if offset-12 > 255 || offset+4 > len(wire) || binary.BigEndian.Uint16(wire[offset+2:offset+4]) != 1 {
		return result, bad
	}
	result.Name = strings.Join(labels, ".") + "."
	result.Type = binary.BigEndian.Uint16(wire[offset : offset+2])
	offset += 4
	if wire[11] == 1 {
		if offset+11 != len(wire) {
			return ResolvedDNSSECQuestion{}, bad
		}
		opt := wire[offset:]
		size := binary.BigEndian.Uint16(opt[3:5])
		// The pinned validator supplies no arbitrary EDNS options. DO/CD are
		// validation signaling, not permission to trust an upstream AD bit.
		if opt[0] != 0 || binary.BigEndian.Uint16(opt[1:3]) != 41 || size < 512 || size > 4096 || opt[5] != 0 || opt[6] != 0 || opt[7]&^byte(0x80) != 0 || opt[8] != 0 || opt[9] != 0 || opt[10] != 0 {
			return ResolvedDNSSECQuestion{}, bad
		}
		offset += 11
	}
	if offset != len(wire) {
		return ResolvedDNSSECQuestion{}, bad
	}
	originalName = strings.ToLower(strings.TrimSuffix(originalName, ".")) + "."
	switch result.Type {
	case 1, 28:
		if result.Type != originalType || result.Name != originalName {
			return ResolvedDNSSECQuestion{}, bad
		}
	case 43, 48:
		if result.Name != "." && result.Name != originalName && !strings.HasSuffix(originalName, "."+result.Name) {
			return ResolvedDNSSECQuestion{}, bad
		}
	default:
		return ResolvedDNSSECQuestion{}, bad
	}
	return result, nil
}
