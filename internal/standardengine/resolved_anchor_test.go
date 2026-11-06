package standardengine

import (
	"encoding/binary"
	"strings"
	"testing"
)

func resolvedAnchorFixture(kind uint16) ResolvedAnchorResult {
	rr := []byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(rr[1:], kind)
	data := []byte{1, 1, 3, 13, 1, 2, 3, 4}
	if kind == 43 {
		data = append([]byte{0x4f, 0x66, 8, 2}, make([]byte, 32)...)
	}
	binary.BigEndian.PutUint16(rr[9:], uint16(len(data)))
	return ResolvedAnchorResult{PolicySHA256: strings.Repeat("ab", 32), Name: ".", Type: kind, Present: true, Records: [][]byte{append(rr, data...)}, Flags: ResolvedAnchorFlags}
}
func TestResolvedAnchorOriginalLoadedRecord(t *testing.T) {
	for _, kind := range []uint16{43, 48} {
		original := resolvedAnchorFixture(kind)
		raw, err := original.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeResolvedAnchor(raw, original.PolicySHA256, 0, ".", kind); err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeResolvedAnchor(raw, strings.Repeat("cd", 32), 0, ".", kind); err == nil {
			t.Fatal("foreign policy accepted")
		}
		if _, err = DecodeResolvedAnchor(raw, original.PolicySHA256, 7, ".", kind); err == nil {
			t.Fatal("foreign selected link accepted")
		}
		if _, err = DecodeResolvedAnchor(raw, original.PolicySHA256, 0, "private.example", kind); err == nil {
			t.Fatal("foreign name accepted")
		}
	}
}
func TestResolvedAnchorRejectsUnprovenOrigin(t *testing.T) {
	cases := map[string]func(*ResolvedAnchorResult){
		"upstream-ad-only": func(r *ResolvedAnchorResult) { r.Flags = 1 << 9 },
		"cache":            func(r *ResolvedAnchorResult) { r.Flags |= 1 << 20 },
		"network":          func(r *ResolvedAnchorResult) { r.Flags |= 1 << 23 },
		"synthesis":        func(r *ResolvedAnchorResult) { r.Flags |= 1 << 19 },
		"unsigned":         func(r *ResolvedAnchorResult) { r.Flags &^= 1 << 9 },
		"empty":            func(r *ResolvedAnchorResult) { r.Records = nil },
		"duplicate":        func(r *ResolvedAnchorResult) { r.Records = append(r.Records, r.Records[0]) },
		"compressed":       func(r *ResolvedAnchorResult) { r.Records[0][0] = 0xc0 },
		"wrong-type":       func(r *ResolvedAnchorResult) { r.Records[0][2] = 48 },
		"wrong-class":      func(r *ResolvedAnchorResult) { r.Records[0][4] = 3 },
		"truncated":        func(r *ResolvedAnchorResult) { r.Records[0] = r.Records[0][:12] },
		"absent-records":   func(r *ResolvedAnchorResult) { r.Present = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := resolvedAnchorFixture(43)
			mutate(&r)
			if _, err := r.Canonical(); err == nil {
				t.Fatal("unproven anchor accepted")
			}
		})
	}
	r := resolvedAnchorFixture(48)
	r.Records[0][12] |= 0x80
	if _, err := r.Canonical(); err == nil {
		t.Fatal("revoked key accepted")
	}
}
func TestResolvedAnchorAbsenceIsNotTrust(t *testing.T) {
	r := resolvedAnchorFixture(43)
	r.Present = false
	r.Records = nil
	r.Flags = 0
	raw, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeResolvedAnchor(raw, r.PolicySHA256, 0, ".", 43)
	if err != nil || got.Present {
		t.Fatal("absence became active trust", err)
	}
}
