//go:build linux

package systembootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"router-vpn/internal/common"
	"strings"
)

// ResolvedPrivateTLDCandidate is an inert, exact unsigned two-label address
// answer. It is not a DNSSEC verdict. Adoption still requires a separately
// authenticated denial proof and joined ownership/policy checkpoints.
type ResolvedPrivateTLDCandidate struct {
	name             string
	kind             uint16
	question, packet []byte
	digest           string
}

func NewResolvedPrivateTLDCandidate(question, packet []byte) (*ResolvedPrivateTLDCandidate, error) {
	bad := errors.New("private-TLD candidate is not an exact unsigned two-label positive address answer")
	if err := common.ValidateDNSProbeResponse(question, packet); err != nil {
		return nil, err
	}
	name, end, err := dnsName(question, 12)
	if err != nil || !validName(name) || len(strings.Split(name, ".")) != 2 {
		return nil, bad
	}
	kind := binary.BigEndian.Uint16(question[end:])
	if binary.BigEndian.Uint16(question[end+2:]) != 1 || kind != 1 && kind != 28 || packet[3]&15 != 0 {
		return nil, bad
	}
	count := int(binary.BigEndian.Uint16(packet[6:]))
	if count < 1 || count > 32 {
		return nil, bad
	}
	_, offset, err := dnsName(packet, 12)
	if err != nil {
		return nil, err
	}
	offset += 4
	for section := 0; section < 3; section++ {
		n := int(binary.BigEndian.Uint16(packet[6+2*section:]))
		for i := 0; i < n; i++ {
			owner, next, err := dnsName(packet, offset)
			if err != nil {
				return nil, err
			}
			rtype := binary.BigEndian.Uint16(packet[next:])
			class := binary.BigEndian.Uint16(packet[next+2:])
			size := int(binary.BigEndian.Uint16(packet[next+8:]))
			offset = next + 10 + size
			if rtype == 46 || rtype == 5 || rtype == 39 {
				return nil, bad
			}
			if section == 0 && (owner != name || rtype != kind || class != 1) {
				return nil, bad
			}
			if section == 0 {
				address, ok := netip.AddrFromSlice(packet[next+10 : offset])
				if !ok || kind == 1 && size != 4 || kind == 28 && size != 16 || !address.IsGlobalUnicast() || address.IsLoopback() || address.Is4In6() {
					return nil, bad
				}
			}
		}
	}
	if _, err := addressesFor(question, packet); err != nil {
		return nil, err
	}
	h := sha256.Sum256(packet)
	return &ResolvedPrivateTLDCandidate{name, kind, bytes.Clone(question), bytes.Clone(packet), hex.EncodeToString(h[:])}, nil
}
func (c *ResolvedPrivateTLDCandidate) Name() string {
	if c == nil {
		return ""
	}
	return c.name
}
func (c *ResolvedPrivateTLDCandidate) Type() uint16 {
	if c == nil {
		return 0
	}
	return c.kind
}
func (c *ResolvedPrivateTLDCandidate) SHA256() string {
	if c == nil {
		return ""
	}
	return c.digest
}

// UnsignedAnswer returns only a copy; caller owns the proof and final checks.
func (c *ResolvedPrivateTLDCandidate) UnsignedAnswer() []byte {
	if c == nil {
		return nil
	}
	out := bytes.Clone(c.packet)
	out[3] &^= 0x20
	return out
}
