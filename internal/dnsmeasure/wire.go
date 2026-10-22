package dnsmeasure

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

func newQuery() ([]byte, error) {
	query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	_, err := rand.Read(query[:2])
	return query, err
}

// This is a matching usable A-answer proof, not merely a DNS packet or an
// NXDOMAIN response. Every section must be bounded and completely framed.
func validateAnswer(query, response []byte) error {
	bad := errors.New("invalid matching DNS answer")
	if len(query) < 12 || len(response) < 12 || len(response) > maxDNSMessage || !bytes.Equal(query[:2], response[:2]) || response[2]&0xfa != 0x80 || response[3]&0x4f != 0 || binary.BigEndian.Uint16(response[4:6]) != 1 {
		return bad
	}
	qname, qend, err := wireName(query, 12)
	if err != nil || qend+4 != len(query) {
		return bad
	}
	rname, offset, err := wireName(response, 12)
	if err != nil || offset+4 > len(response) || rname != qname || !bytes.Equal(query[qend:], response[offset:offset+4]) {
		return bad
	}
	offset += 4
	answers := int(binary.BigEndian.Uint16(response[6:8]))
	total := answers + int(binary.BigEndian.Uint16(response[8:10])) + int(binary.BigEndian.Uint16(response[10:12]))
	if answers == 0 || answers > 128 || total > 256 {
		return bad
	}
	usable, aliases := map[string]bool{}, map[string]string{}
	for index := 0; index < total; index++ {
		name, end, err := wireName(response, offset)
		if err != nil || end+10 > len(response) {
			return bad
		}
		kind, class, size := binary.BigEndian.Uint16(response[end:end+2]), binary.BigEndian.Uint16(response[end+2:end+4]), int(binary.BigEndian.Uint16(response[end+8:end+10]))
		data := end + 10
		offset = data + size
		if offset > len(response) {
			return bad
		}
		if index >= answers || class != 1 {
			continue
		}
		switch kind {
		case 1:
			if size != 4 {
				return bad
			}
			ip := netip.AddrFrom4([4]byte(response[data:offset]))
			if ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() {
				usable[name] = true
			}
		case 5:
			target, next, err := wireName(response, data)
			if err != nil || next != offset || aliases[name] != "" && aliases[name] != target {
				return bad
			}
			aliases[name] = target
		}
	}
	if offset != len(response) {
		return bad
	}
	seen := map[string]bool{}
	for hop := 0; hop < 16 && qname != "" && !seen[qname]; hop++ {
		seen[qname] = true
		if usable[qname] && aliases[qname] == "" {
			return nil
		}
		qname = aliases[qname]
	}
	return bad
}

// Preserve label boundaries and compare ASCII names case-insensitively.
// Compression only points backward and has bounded expansion and traversal.
func wireName(packet []byte, offset int) (string, int, error) {
	name := make([]byte, 0, 32)
	next := -1
	for steps := 0; steps < 256; steps++ {
		if offset < 12 || offset >= len(packet) {
			break
		}
		size := int(packet[offset])
		if size&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				break
			}
			pointer := (size&63)<<8 | int(packet[offset+1])
			if pointer < 12 || pointer >= offset {
				break
			}
			if next < 0 {
				next = offset + 2
			}
			offset = pointer
			continue
		}
		if size > 63 || offset+1+size > len(packet) || len(name)+1+size > 255 {
			break
		}
		offset++
		name = append(name, byte(size))
		for _, value := range packet[offset : offset+size] {
			if value >= 'A' && value <= 'Z' {
				value += 'a' - 'A'
			}
			name = append(name, value)
		}
		offset += size
		if size == 0 {
			if next < 0 {
				next = offset
			}
			return string(name), next, nil
		}
	}
	return "", 0, errors.New("malformed DNS name")
}
