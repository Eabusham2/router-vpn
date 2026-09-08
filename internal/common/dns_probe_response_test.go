package common

import "testing"

func probeQueryFixture() []byte {
	return []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
}

func TestDNSProbeResponseMatchesExactQuestionAndFraming(t *testing.T) {
	query := probeQueryFixture()
	for _, tc := range []struct {
		name string
		change func([]byte) []byte
		valid bool
	}{
		{"nodata", func(b []byte) []byte { return b }, true},
		{"nxdomain", func(b []byte) []byte { b[3] = 3; return b }, true},
		{"case-insensitive", func(b []byte) []byte { b[13] = 'E'; return b }, true},
		{"compressed-answer", func(b []byte) []byte { b[7] = 1; return append(b, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1) }, true},
		{"wrong-id", func(b []byte) []byte { b[0]++; return b }, false},
		{"query-echo", func(b []byte) []byte { b[2] = 1; return b }, false},
		{"wrong-opcode", func(b []byte) []byte { b[2] |= 8; return b }, false},
		{"truncated", func(b []byte) []byte { b[2] |= 2; return b }, false},
		{"servfail", func(b []byte) []byte { b[3] = 2; return b }, false},
		{"wrong-name", func(b []byte) []byte { b[13] = 'a'; return b }, false},
		{"wrong-type", func(b []byte) []byte { b[len(b)-3] = 28; return b }, false},
		{"wrong-class", func(b []byte) []byte { b[len(b)-1] = 3; return b }, false},
		{"no-question", func(b []byte) []byte { b[5] = 0; return b }, false},
		{"multiple-questions", func(b []byte) []byte { b[5] = 2; return b }, false},
		{"short-question", func(b []byte) []byte { return b[:len(b)-1] }, false},
		{"short-record", func(b []byte) []byte { b[7] = 1; return b }, false},
		{"short-rdata", func(b []byte) []byte { b[7] = 1; return append(b, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1) }, false},
		{"self-pointer", func(b []byte) []byte { b[12] = 0xc0; b[13] = 12; return b }, false},
		{"forward-pointer", func(b []byte) []byte { b[12] = 0xc0; b[13] = 20; return b }, false},
		{"header-pointer", func(b []byte) []byte { b[12] = 0xc0; b[13] = 0; return b }, false},
		{"trailing-bytes", func(b []byte) []byte { return append(b, 0) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := append([]byte(nil), query...)
			response[2] |= 0x80
			if err := ValidateDNSProbeResponse(query, tc.change(response)); (err == nil) != tc.valid {
				t.Fatalf("valid=%t want=%t err=%v", err == nil, tc.valid, err)
			}
		})
	}
}

func FuzzDNSProbeResponse(f *testing.F) {
	query := probeQueryFixture()
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	f.Add(query, response)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, query, response []byte) { _ = ValidateDNSProbeResponse(query, response) })
}
