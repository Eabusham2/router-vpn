package common

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ValidateDNSProbeResponse matches one standard DNS question and validates the
// complete response framing. The connected probe socket must separately bind
// source/destination addresses and ports (RFC 5452 section 9.1). This is query
// matching, not DNSSEC authentication or proof of a usable A/AAAA answer.
func ValidateDNSProbeResponse(query, response []byte) error {
	if len(query) < 12 || len(response) < 12 || len(query) > 65535 || len(response) > 65535 {
		return errors.New("invalid DNS probe message size")
	}
	if query[2]&0xf8 != 0 || binary.BigEndian.Uint16(query[4:6]) != 1 ||
		response[2]&0xf8 != 0x80 || response[2]&2 != 0 ||
		!bytes.Equal(query[:2], response[:2]) || binary.BigEndian.Uint16(response[4:6]) != 1 {
		return errors.New("DNS response does not match the probe transaction")
	}
	if rcode := response[3] & 15; rcode != 0 && rcode != 3 {
		return errors.New("DNS probe returned an unsuccessful response code")
	}
	qname, qend, err := dnsProbeName(query, 12)
	if err != nil || qend+4 > len(query) {
		return errors.New("invalid DNS probe question")
	}
	rname, rend, err := dnsProbeName(response, 12)
	if err != nil || rend+4 > len(response) || !bytes.Equal(qname, rname) ||
		!bytes.Equal(query[qend:qend+4], response[rend:rend+4]) {
		return errors.New("DNS response question differs from the probe")
	}
	// Do not accept a truncated datagram whose header claims records that never
	// arrived. Compression is allowed for record names, with bounded expansion.
	offset := rend + 4
	records := int(binary.BigEndian.Uint16(response[6:8])) + int(binary.BigEndian.Uint16(response[8:10])) + int(binary.BigEndian.Uint16(response[10:12]))
	for i := 0; i < records; i++ {
		_, end, err := dnsProbeName(response, offset)
		if err != nil || end+10 > len(response) {
			return errors.New("invalid DNS probe resource record")
		}
		offset = end + 10 + int(binary.BigEndian.Uint16(response[end+8:end+10]))
		if offset > len(response) {
			return errors.New("truncated DNS probe resource data")
		}
	}
	if offset != len(response) {
		return errors.New("unexpected trailing DNS probe data")
	}
	return nil
}

// DNS labels compare case-insensitively for ASCII only, preserving label
// boundaries. RFC 1035 section 4.1.4 compression points to an earlier name.
func dnsProbeName(packet []byte, offset int) ([]byte, int, error) {
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
		for _, c := range packet[offset : offset+size] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			name = append(name, c)
		}
		offset += size
		if size == 0 {
			if next < 0 {
				next = offset
			}
			return name, next, nil
		}
	}
	return nil, 0, errors.New("malformed or cyclic DNS probe name")
}
