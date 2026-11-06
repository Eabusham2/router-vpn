package common

import (
	"encoding/binary"
	"errors"
)

// ValidateUnsignedDSNegativeResponse checks a dependency's wire shape only.
// It supplies no DNSSEC authentication or permission to adopt an address.
// The caller must establish its original scope and completed parent proof.
func ValidateUnsignedDSNegativeResponse(question, response []byte) error {
	bad := errors.New("private DS dependency is not an exact unsigned empty IN DS response")
	if len(question) > 512 || len(response) > 4096 {
		return bad
	}
	if err := ValidateDNSForwardQuery(question); err != nil {
		return err
	}
	if err := ValidateDNSProbeResponse(question, response); err != nil {
		return err
	}
	_, end, err := dnsProbeName(question, 12)
	if err != nil || binary.BigEndian.Uint16(question[end:]) != 43 || binary.BigEndian.Uint16(question[end+2:]) != 1 || binary.BigEndian.Uint16(response[6:]) != 0 {
		return bad
	}
	if question[2] != 1 || question[3]&^byte(0x30) != 0 || binary.BigEndian.Uint16(question[6:]) != 0 || binary.BigEndian.Uint16(question[8:]) != 0 || binary.BigEndian.Uint16(question[10:]) > 1 {
		return bad
	}
	qend := end + 4
	if question[11] == 1 {
		if qend+11 != len(question) {
			return bad
		}
		opt := question[qend:]
		size := binary.BigEndian.Uint16(opt[3:5])
		if opt[0] != 0 || binary.BigEndian.Uint16(opt[1:3]) != 41 || size < 512 || size > 4096 || opt[5] != 0 || opt[6] != 0 || opt[7]&^byte(0x80) != 0 || opt[8] != 0 || opt[9] != 0 || opt[10] != 0 {
			return bad
		}
	} else if qend != len(question) {
		return bad
	}
	offset, err := matchDNSResponseQuestion(question, response)
	if err != nil {
		return err
	}
	// Do not mistake a referral, positive DS, signature, alias, or malformed
	// denial material for a completed empty dependency. An unsigned SOA is
	// ordinary negative metadata; an OPT may carry only an empty base EDNS0.
	for section := 1; section < 3; section++ {
		count := int(binary.BigEndian.Uint16(response[6+2*section:]))
		if count > 1 {
			return bad
		}
		for i := 0; i < count; i++ {
			name, next, e := dnsProbeName(response, offset)
			if e != nil {
				return e
			}
			kind := binary.BigEndian.Uint16(response[next:])
			class := binary.BigEndian.Uint16(response[next+2:])
			size := int(binary.BigEndian.Uint16(response[next+8:]))
			offset = next + 10 + size
			if section == 1 {
				if kind != 6 || class != 1 {
					return bad
				}
				_, first, e := dnsProbeName(response, next+10)
				if e != nil || first > offset {
					return bad
				}
				_, last, e := dnsProbeName(response, first)
				if e != nil || last+20 != offset {
					return bad
				}
			} else {
				if kind != 41 || len(name) != 1 || name[0] != 0 || size != 0 || response[next+4] != 0 || response[next+5] != 0 || binary.BigEndian.Uint16(response[next+6:]) & ^uint16(0x8000) != 0 {
					return bad
				}
			}
		}
	}
	return nil
}
