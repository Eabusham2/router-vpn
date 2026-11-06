package standardengine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
)

// ResolvedAnchorResult is an observation of the original daemon's loaded trust
// store. It is not itself a trust capability or a DNSSEC validation verdict.
// The original authority must remain live and re-observe it before adoption.
type ResolvedAnchorResult struct {
	PolicySHA256 string   `json:"policy_sha256"`
	Index        int32    `json:"index"`
	Name         string   `json:"name"`
	Type         uint16   `json:"type"`
	Present      bool     `json:"present"`
	Records      [][]byte `json:"records"`
	Flags        uint64   `json:"flags"`
}

const ResolvedAnchorFlags = uint64(1 | 1<<9 | 1<<18 | 1<<22)
const MaxResolvedAnchor = 64 << 10

func (r ResolvedAnchorResult) Canonical() ([]byte, error) {
	bad := errors.New("resolved anchor has no exact bounded original trust-store observation")
	if !resolvedDigest(r.PolicySHA256, 32) || r.Index < 0 || !ResolvedName(r.Name, true) || (r.Type != 43 && r.Type != 48) {
		return nil, bad
	}
	if !r.Present {
		if len(r.Records) != 0 || r.Flags != 0 {
			return nil, bad
		}
	} else {
		// Protocol bits and unrelated origin flags are not substitutes for the
		// authenticated trust-anchor origin (in particular upstream AD is absent).
		if r.Flags != ResolvedAnchorFlags || len(r.Records) == 0 || len(r.Records) > 32 {
			return nil, bad
		}
		seen := map[string]bool{}
		for _, rr := range r.Records {
			if !resolvedAnchorRecord(rr, r.Name, r.Type) || seen[string(rr)] {
				return nil, bad
			}
			seen[string(rr)] = true
		}
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxResolvedAnchor {
		return nil, bad
	}
	return raw, nil
}

// ResolveRecord supplies complete standalone wire RRs. Compression pointers
// cannot reference a separate DNS packet and are never accepted here.
func resolvedAnchorRecord(rr []byte, name string, kind uint16) bool {
	if len(rr) > 8192 {
		return false
	}
	var labels []string
	pos := 0
	for {
		if pos >= len(rr) {
			return false
		}
		n := int(rr[pos])
		pos++
		if n == 0 {
			break
		}
		if n > 63 || pos+n > len(rr) {
			return false
		}
		labels = append(labels, string(rr[pos:pos+n]))
		pos += n
	}
	owner := strings.Join(labels, ".")
	if len(labels) == 0 {
		owner = "."
	}
	if !ResolvedName(owner, true) || !strings.EqualFold(strings.TrimSuffix(owner, "."), strings.TrimSuffix(name, ".")) || pos > 255 || pos+10 > len(rr) {
		return false
	}
	if binary.BigEndian.Uint16(rr[pos:]) != kind || binary.BigEndian.Uint16(rr[pos+2:]) != 1 || int(binary.BigEndian.Uint16(rr[pos+8:])) != len(rr)-pos-10 {
		return false
	}
	data := rr[pos+10:]
	if kind == 43 { // DS: preserve unknown algorithms/digests for validator policy.
		return len(data) >= 5 && len(data) <= 68
	}
	// DNSKEY protocol 3, zone-key bit, no revoke bit. A revoked anchor must not
	// become live merely because an authenticated daemon returned malformed data.
	return len(data) >= 5 && data[2] == 3 && binary.BigEndian.Uint16(data)&0x100 != 0 && binary.BigEndian.Uint16(data)&0x80 == 0
}

func DecodeResolvedAnchor(raw []byte, policy string, index int32, name string, kind uint16) (ResolvedAnchorResult, error) {
	var r ResolvedAnchorResult
	if len(raw) == 0 || len(raw) > MaxResolvedAnchor || json.Unmarshal(raw, &r) != nil {
		return r, errors.New("malformed resolved anchor frame")
	}
	canonical, err := r.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) || r.PolicySHA256 != policy || r.Index != index || r.Name != name || r.Type != kind {
		return ResolvedAnchorResult{}, errors.New("resolved anchor belongs to another original policy or query")
	}
	return r, nil
}
