//go:build linux

package systembootstrap

import "testing"

func TestResolvedPrivateDeepCandidate(t *testing.T) {
	for _, scenario := range []string{"address", "ipv6", "nxdomain", "nodata", "two-label", "four-label", "signed", "alias", "foreign-class"} {
		t.Run(scenario, func(t *testing.T) {
			name := "host.vpn.example"
			if scenario == "two-label" {
				name = "vpn.example"
			}
			if scenario == "four-label" {
				name = "four.host.vpn.example"
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
			if scenario == "foreign-class" {
				q[len(q)-1] = 3
			}
			records := [][]byte{aliasTestRR(name, kind, data)}
			if scenario == "nxdomain" || scenario == "nodata" {
				records = nil
			}
			if scenario == "signed" {
				records = append(records, aliasTestRR(name, 46, []byte{1}))
			}
			if scenario == "alias" {
				records = append(records, aliasTestRR(name, 5, aliasTestName("other.example")))
			}
			r := aliasTestResponse(t, q, records...)
			if scenario == "nxdomain" {
				r[3] |= 3
			}
			c, err := NewResolvedPrivateDeepCandidate(q, r)
			want := scenario == "address" || scenario == "ipv6" || scenario == "nxdomain" || scenario == "nodata"
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
			if !want {
				return
			}
			if c.Name() != name || c.Type() != kind {
				t.Fatal("deep original source changed")
			}
			if _, err = NewResolvedPrivateTLDCandidate(q, r); err == nil {
				t.Fatal("deep candidate entered old positive API")
			}
			if _, err = NewResolvedPrivateTLDNegativeCandidate(q, r); err == nil {
				t.Fatal("deep candidate entered old negative API")
			}
		})
	}
}
