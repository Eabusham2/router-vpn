package common

import (
	"encoding/binary"
	"testing"
)

func TestUnsignedDSDependencyWire(t *testing.T) {
	for _, scenario := range []string{"empty", "nxdomain", "soa", "opt", "positive", "signed", "alias", "dname", "referral", "malformed-soa", "multiple-soa", "foreign-class", "servfail", "truncated", "wrong-id", "edns-error", "edns-option", "oversize", "query-trailing", "query-answer", "query-option"} {
		t.Run(scenario, func(t *testing.T) {
			q := []byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 1, 'y', 1, 'z', 0, 0, 43, 0, 1}
			r := append([]byte(nil), q...)
			r[2] = 0x81
			r[3] = 0x80
			if scenario == "nxdomain" {
				r[3] |= 3
			}
			switch scenario {
			case "soa", "malformed-soa", "multiple-soa", "signed", "alias", "dname", "referral":
				kind := uint16(6)
				data := append([]byte{0, 0}, make([]byte, 20)...)
				if scenario == "malformed-soa" {
					data = data[:len(data)-1]
				}
				if scenario == "signed" {
					kind = 46
				}
				if scenario == "alias" {
					kind = 5
				}
				if scenario == "dname" {
					kind = 39
				}
				if scenario == "referral" {
					kind = 2
				}
				record := []byte{0xc0, 12, 0, byte(kind), 0, 1, 0, 0, 0, 1, 0, byte(len(data))}
				record = append(record, data...)
				r[9] = 1
				r = append(r, record...)
				if scenario == "multiple-soa" {
					r[9] = 2
					r = append(r, record...)
				}
			case "opt", "edns-error", "edns-option":
				r[11] = 1
				opt := []byte{0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0}
				if scenario == "edns-error" {
					opt[5] = 1
				}
				if scenario == "edns-option" {
					opt[10] = 4
					opt = append(opt, 0, 1, 0, 0)
				}
				r = append(r, opt...)
			case "positive":
				r[7] = 1
				r = append(r, 0xc0, 12, 0, 43, 0, 1, 0, 0, 0, 1, 0, 0)
			case "foreign-class":
				q[len(q)-1] = 3
				r[len(r)-1] = 3
			case "servfail":
				r[3] = 0x82
			case "truncated":
				r[2] |= 2
			case "wrong-id":
				r[0] ^= 1
			case "query-trailing":
				q = append(q, 0)
			case "query-answer":
				q[7] = 1
				q = append(q, 0xc0, 12, 0, 43, 0, 1, 0, 0, 0, 1, 0, 0)
			case "query-option":
				q[11] = 1
				q = append(q, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 4, 0, 1, 0, 0)
			case "oversize":
				r = append(r, make([]byte, 4096)...)
			}
			err := ValidateUnsignedDSNegativeResponse(q, r)
			want := scenario == "empty" || scenario == "nxdomain" || scenario == "soa" || scenario == "opt"
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
			if want {
				copy := append([]byte(nil), q...)
				binary.BigEndian.PutUint16(copy[len(copy)-4:], 1)
				if ValidateUnsignedDSNegativeResponse(copy, r) == nil {
					t.Fatal("address query borrowed DS purpose")
				}
			}
		})
	}
}
