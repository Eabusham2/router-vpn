package dnsmeasure

import (
	"encoding/binary"
	"testing"
)

func TestDNSAnswersRequireExactFramingQuestionAndUsableData(t *testing.T) {
	query, err := newQuery()
	if err != nil {
		t.Fatal(err)
	}
	valid := answer(query)
	if err := validateAnswer(query, valid); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"id":                  func(b []byte) []byte { b[0] ^= 1; return b },
		"query":               func(b []byte) []byte { b[2] &= 0x7f; return b },
		"opcode":              func(b []byte) []byte { b[2] |= 8; return b },
		"truncated-flag":      func(b []byte) []byte { b[2] |= 2; return b },
		"reserved":            func(b []byte) []byte { b[3] |= 0x40; return b },
		"nxdomain":            func(b []byte) []byte { b[3] |= 3; return b },
		"servfail":            func(b []byte) []byte { b[3] |= 2; return b },
		"question-count":      func(b []byte) []byte { b[5] = 2; return b },
		"question-name":       func(b []byte) []byte { b[13] = 'x'; return b },
		"question-type":       func(b []byte) []byte { b[len(query)-3] = 28; return b },
		"question-class":      func(b []byte) []byte { b[len(query)-1] = 3; return b },
		"zero-answer":         func(b []byte) []byte { b[7] = 0; return b },
		"missing-answer":      func(b []byte) []byte { b[7] = 2; return b },
		"many-records":        func(b []byte) []byte { b[9] = 255; b[11] = 255; return b },
		"forward-pointer":     func(b []byte) []byte { b[len(query)+1] = byte(len(query) + 2); return b },
		"self-pointer":        func(b []byte) []byte { b[len(query)+1] = byte(len(query)); return b },
		"wrong-answer-class":  func(b []byte) []byte { b[len(query)+5] = 3; return b },
		"answer-rdata-short":  func(b []byte) []byte { return b[:len(b)-1] },
		"answer-rdata-length": func(b []byte) []byte { b[len(query)+11] = 3; return b },
		"private-answer":      func(b []byte) []byte { copy(b[len(b)-4:], []byte{10, 1, 2, 3}); return b },
		"sinkhole-answer":     func(b []byte) []byte { copy(b[len(b)-4:], []byte{0, 0, 0, 0}); return b },
		"loopback-answer":     func(b []byte) []byte { copy(b[len(b)-4:], []byte{127, 0, 0, 1}); return b },
		"trailing":            func(b []byte) []byte { return append(b, 0) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			if validateAnswer(query, change(append([]byte(nil), valid...))) == nil {
				t.Fatal("invalid DNS answer accepted")
			}
		})
	}
	for length := 0; length < len(valid); length++ {
		if validateAnswer(query, valid[:length]) == nil {
			t.Fatalf("truncated frame %d accepted", length)
		}
	}
}

func TestBoundedCNAMEChainMustLeadToTheQuestionAnswer(t *testing.T) {
	query, _ := newQuery()
	response := append([]byte(nil), query...)
	response[2], response[3], response[7] = 0x81, 0x80, 2
	target := []byte{3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	response = append(response, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, byte(len(target)))
	targetOffset := len(response)
	response = append(response, target...)
	response = append(response, 0xc0, byte(targetOffset), 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 216, 34)
	if err := validateAnswer(query, response); err != nil {
		t.Fatal("valid CNAME rejected", err)
	}
	wrong := append([]byte(nil), response...)
	wrong[targetOffset+len(target)+1] = 12
	if validateAnswer(query, wrong) == nil {
		t.Fatal("unrelated A record accepted as CNAME target")
	}
	cycle := append([]byte(nil), query...)
	cycle[2], cycle[3], cycle[7] = 0x81, 0x80, 1
	cycle = append(cycle, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 2, 0xc0, 12)
	if validateAnswer(query, cycle) == nil {
		t.Fatal("cyclic CNAME accepted")
	}
	trailing := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(trailing[len(query)+10:len(query)+12], uint16(len(target)-1))
	if validateAnswer(query, trailing) == nil {
		t.Fatal("CNAME data framing accepted")
	}
}

func TestClosedCatalogCannotDialPrivateHostnamesOrUnownedPorts(t *testing.T) {
	for _, address := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:853", "8.8.8.8:443"} {
		if !AllowedPublicAddress(address) {
			t.Fatal("catalog address rejected", address)
		}
	}
	for _, address := range []string{"10.77.0.1:53", "localhost:53", "dns.google:443", "1.1.1.1:5353", "1.1.1.1:0053", "[::ffff:1.1.1.1]:53", "[2606:4700:4700::1111%en0]:53", "93.184.216.34:443"} {
		if AllowedPublicAddress(address) {
			t.Fatal("unowned public dial allowed", address)
		}
	}
}
