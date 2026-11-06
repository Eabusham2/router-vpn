//go:build linux

package systembootstrap

import (
	"bytes"
	"testing"
)

func TestResolvedPrivateTLDNegativeCandidate(t *testing.T) {
	for _, scenario := range []string{"nxdomain-a", "nxdomain-aaaa", "nodata-a", "nodata-aaaa", "positive", "negative-with-answer", "signed", "alias", "dname", "deep", "foreign-class", "servfail", "truncated", "foreign-question", "trailing"} {
		t.Run(scenario, func(t *testing.T) {
			name := "host.private"
			if scenario == "deep" {
				name = "deep.host.private"
			}
			kind := uint16(1)
			if scenario == "nxdomain-aaaa" || scenario == "nodata-aaaa" {
				kind = 28
			}
			q, err := queryFor(name, kind, false, false)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "foreign-class" {
				q[len(q)-1] = 3
			}
			r := aliasTestResponse(t, q)
			r[3] |= 0x20 // AD is never adopted from this untrusted candidate.
			if scenario != "nodata-a" && scenario != "nodata-aaaa" {
				r[3] |= 3
			}
			switch scenario {
			case "positive", "negative-with-answer":
				r = aliasTestResponse(t, q, aliasTestRR(name, kind, []byte{192, 0, 2, 9}))
				if scenario == "negative-with-answer" {
					r[3] |= 3
				}
			case "signed", "alias", "dname":
				typ := uint16(46)
				if scenario == "alias" {
					typ = 5
				}
				if scenario == "dname" {
					typ = 39
				}
				r = aliasTestResponse(t, q, aliasTestRR(name, typ, aliasTestName("other.example")))
				r[6], r[7] = 0, 0
				r[8], r[9] = 0, 1 // forbid even authority-section aliases/signatures
			case "servfail":
				r[3] = (r[3] & 0xf0) | 2
			case "truncated":
				r[2] |= 2
			case "foreign-question":
				r[13] ^= 1
			case "trailing":
				r = append(r, 0)
			}
			original := bytes.Clone(r)
			c, err := NewResolvedPrivateTLDNegativeCandidate(q, r)
			want := scenario == "nxdomain-a" || scenario == "nxdomain-aaaa" || scenario == "nodata-a" || scenario == "nodata-aaaa"
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
			if !want {
				return
			}
			expected := bytes.Clone(original)
			expected[3] &^= 0x20
			if !bytes.Equal(c.UnsignedAnswer(), expected) || !bytes.Equal(r, original) || c.Type() != kind || c.Name() != name {
				t.Fatal("original negative code/question/buffer changed")
			}
			r[3] ^= 3
			if !bytes.Equal(c.UnsignedAnswer(), expected) {
				t.Fatal("candidate retained mutable original")
			}
			if _, err = NewResolvedPrivateTLDCandidate(q, original); err == nil {
				t.Fatal("ordinary positive constructor admitted negative")
			}
		})
	}
}
