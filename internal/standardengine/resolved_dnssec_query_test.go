package standardengine

import (
	"encoding/binary"
	"strings"
	"testing"
)

func resolvedDNSSECWire(name string, kind uint16, edns bool) []byte {
	q := []byte{0x42, 0x51, 1, 0x10, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label != "" {
			q = append(q, byte(len(label)))
			q = append(q, label...)
		}
	}
	q = append(q, 0, byte(kind>>8), byte(kind), 0, 1)
	if edns {
		q[11] = 1
		q = append(q, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0)
	}
	return q
}

func TestResolvedDNSSECQueryOriginalAncestors(t *testing.T) {
	for _, kind := range []uint16{1, 28, 43, 48} {
		for _, name := range []string{"vpn.signed.example.", "signed.example.", "example.", "."} {
			for _, edns := range []bool{false, true} {
				for _, cd := range []byte{0, 0x10, 0x20, 0x30} {
					query := resolvedDNSSECWire(name, kind, edns)
					query[3] = cd
					originalType := uint16(1)
					if kind == 28 {
						originalType = 28
					}
					row, err := ResolvedDNSSECQuestionFromWire("VPN.Signed.Example", originalType, query)
					want := kind == 43 || kind == 48 || name == "vpn.signed.example."
					if (err == nil) != want || want && (row.Name != name || row.Type != kind) {
						t.Fatalf("captured question/ancestor %s %d %t %x: %+v %v", name, kind, edns, cd, row, err)
					}
				}
			}
		}
	}
}

func TestResolvedDNSSECQueryRejectsExpandedAuthority(t *testing.T) {
	for _, name := range []string{"sibling.example.", "example.attacker.", "ample.", "other.vpn.signed.example."} {
		for _, kind := range []uint16{1, 28, 43, 48, 255, 16, 2, 6} {
			if _, err := ResolvedDNSSECQuestionFromWire("vpn.signed.example", 1, resolvedDNSSECWire(name, kind, true)); err == nil {
				t.Fatalf("foreign validation authority %s %d", name, kind)
			}
		}
	}
	for _, kind := range []uint16{28, 255, 16, 2, 6} {
		if _, err := ResolvedDNSSECQuestionFromWire("vpn.signed.example", 1, resolvedDNSSECWire("vpn.signed.example.", kind, true)); err == nil {
			t.Fatal("changed captured address type", kind)
		}
	}
}

func TestResolvedDNSSECQueryRejectsMalformedWire(t *testing.T) {
	mutations := map[string]func([]byte) []byte{
		"response":           func(q []byte) []byte { q[2] |= 0x80; return q },
		"opcode":             func(q []byte) []byte { q[2] |= 8; return q },
		"multiple-questions": func(q []byte) []byte { q[5] = 2; return q },
		"answer":             func(q []byte) []byte { q[7] = 1; return q },
		"authority":          func(q []byte) []byte { q[9] = 1; return q },
		"multiple-edns":      func(q []byte) []byte { q[11] = 2; return q },
		"compressed-name":    func(q []byte) []byte { q[12] = 0xc0; return q },
		"class":              func(q []byte) []byte { q[len(q)-12] = 3; return q },
		"edns-version":       func(q []byte) []byte { q[len(q)-5] = 1; return q },
		"edns-options":       func(q []byte) []byte { q[len(q)-1] = 1; return append(q, 0) },
		"edns-flags":         func(q []byte) []byte { q[len(q)-3] = 1; return q },
		"edns-size":          func(q []byte) []byte { binary.BigEndian.PutUint16(q[len(q)-8:], 65535); return q },
		"trailing":           func(q []byte) []byte { return append(q, 0) },
		"truncated":          func(q []byte) []byte { return q[:len(q)-1] },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			q := mutate(resolvedDNSSECWire("vpn.signed.example.", 43, true))
			if _, err := ResolvedDNSSECQuestionFromWire("vpn.signed.example", 1, q); err == nil {
				t.Fatal("malformed validation question accepted")
			}
		})
	}
}

func FuzzResolvedDNSSECQuestion(f *testing.F) {
	for _, kind := range []uint16{1, 43, 48} {
		f.Add(resolvedDNSSECWire("vpn.signed.example.", kind, true))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = ResolvedDNSSECQuestionFromWire("vpn.signed.example.", 1, wire)
	})
}
