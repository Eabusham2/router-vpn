//go:build linux

package systembootstrap

import (
	"bytes"
	"testing"
)

func TestResolvedPrivateTLDCandidate(t *testing.T) {
	for _, scenario := range []string{"address", "ipv6", "signed", "alias", "dname", "foreign", "negative", "empty", "deep", "bad-size", "truncated", "foreign-class"} {
		t.Run(scenario, func(t *testing.T) {
			name := "host.private"
			if scenario == "deep" {
				name = "a.host.private"
			}
			kind := uint16(1)
			data := []byte{192, 0, 2, 9}
			if scenario == "ipv6" {
				kind = 28
				data = make([]byte, 16)
				data[0] = 0x20
				data[1] = 1
				data[15] = 9
			}
			q, err := queryFor(name, kind, false, false)
			if err != nil {
				t.Fatal(err)
			}
			records := [][]byte{aliasTestRR(name, kind, data)}
			switch scenario {
			case "signed":
				records = append(records, aliasTestRR(name, 46, []byte{1}))
			case "alias":
				records = append(records, aliasTestRR(name, 5, aliasTestName("other.example")))
			case "dname":
				records = append(records, aliasTestRR("private", 39, aliasTestName("example")))
			case "foreign":
				records[0] = aliasTestRR("other.private", kind, data)
			case "empty":
				records = nil
			case "bad-size":
				records[0] = aliasTestRR(name, kind, []byte{1})
			}
			if scenario == "foreign-class" {
				q[len(q)-1] = 3
			}
			r := aliasTestResponse(t, q, records...)
			if scenario == "negative" {
				r[3] |= 3
			}
			if scenario == "truncated" {
				r[2] |= 2
			}
			before := bytes.Clone(r)
			c, err := NewResolvedPrivateTLDCandidate(q, r)
			want := scenario == "address" || scenario == "ipv6"
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
			if !want {
				return
			}
			if c.Name() != name || c.Type() != kind || len(c.SHA256()) != 64 || c.UnsignedAnswer()[3]&0x20 != 0 || !bytes.Equal(before, r) {
				t.Fatal("candidate authority/AD copy changed")
			}
			r[0] ^= 1
			if c.UnsignedAnswer()[0] != before[0] {
				t.Fatal("candidate retained caller buffer")
			}
		})
	}
}
