//go:build linux

package systembootstrap

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func aliasTestName(name string) []byte {
	var wire []byte
	for _, label := range strings.Split(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, []byte(label)...)
	}
	return append(wire, 0)
}
func aliasTestRR(name string, kind uint16, data []byte) []byte {
	wire := aliasTestName(name)
	wire = append(wire, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 30, byte(len(data)>>8), byte(len(data)))
	return append(wire, data...)
}
func aliasTestResponse(t *testing.T, q []byte, records ...[]byte) []byte {
	t.Helper()
	_, end, err := dnsName(q, 12)
	if err != nil {
		t.Fatal(err)
	}
	r := append([]byte(nil), q[:end+4]...)
	r[2], r[3] = 0x81, 0xa0
	r[10], r[11] = 0, 0
	binary.BigEndian.PutUint16(r[6:], uint16(len(records)))
	for _, rr := range records {
		r = append(r, rr...)
	}
	return r
}
func TestResolvedAliasFirstStep(t *testing.T) {
	for _, scenario := range []string{"cname", "dname", "dname-only", "closest-dname", "unrelated", "label-boundary", "self", "conflict", "dname-conflict", "synthesis-conflict", "address-and-alias", "bad-compression", "embedded-label-dot", "truncated", "overlong-substitution"} {
		t.Run(scenario, func(t *testing.T) {
			q, err := queryFor("host.branch.example", 1, false, false)
			if err != nil {
				t.Fatal(err)
			}
			c := aliasTestRR("host.branch.example", 5, aliasTestName("host.target.example"))
			d := aliasTestRR("branch.example", 39, aliasTestName("target.example"))
			records := [][]byte{c}
			switch scenario {
			case "dname":
				records = [][]byte{d, c}
			case "dname-only":
				records = [][]byte{d}
			case "closest-dname":
				records = [][]byte{aliasTestRR("example", 39, aliasTestName("unused.example")), d, c}
			case "unrelated":
				records = [][]byte{aliasTestRR("other.example", 5, aliasTestName("host.target.example"))}
			case "label-boundary":
				records = [][]byte{aliasTestRR("ranch.example", 39, aliasTestName("target.example"))}
			case "self":
				records = [][]byte{aliasTestRR("host.branch.example", 5, aliasTestName("host.branch.example"))}
			case "conflict":
				records = append(records, aliasTestRR("host.branch.example", 5, aliasTestName("foreign.example")))
			case "dname-conflict":
				records = [][]byte{d, aliasTestRR("branch.example", 39, aliasTestName("foreign.example"))}
			case "synthesis-conflict":
				records = [][]byte{d, aliasTestRR("host.branch.example", 5, aliasTestName("foreign.example"))}
			case "address-and-alias":
				records = append(records, aliasTestRR("host.branch.example", 1, []byte{192, 0, 2, 7}))
			case "bad-compression":
				records = [][]byte{aliasTestRR("host.branch.example", 5, []byte{0xc0, 0xff})}
			case "embedded-label-dot":
				records = [][]byte{aliasTestRR("host.branch.example", 5, []byte{3, 'a', '.', 'b', 0})}
			case "overlong-substitution":
				records = [][]byte{aliasTestRR("branch.example", 39, aliasTestName(strings.Repeat("a", 63)+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 63)+"."+strings.Repeat("d", 58)))}
			}
			r := aliasTestResponse(t, q, records...)
			if scenario == "truncated" {
				r[2] |= 2
			}
			step, err := ResolvedAliasStep(q, r)
			switch scenario {
			case "cname", "dname", "dname-only", "closest-dname":
				if err != nil || step == nil || step.Name != "host.branch.example" || step.Target != "host.target.example" || step.DNAME != (scenario != "cname") || step.TTL != 30 {
					t.Fatal("lost exact alias", step, err)
				}
			case "unrelated", "label-boundary":
				if err != nil || step != nil {
					t.Fatal("unrelated alias affected original question", step, err)
				}
			default:
				if err == nil {
					t.Fatal("malformed alias became a usable step", step)
				}
			}
		})
	}
}

func TestResolvedAliasComposition(t *testing.T) {
	for _, scenario := range []string{"ipv4", "ipv6", "insecure", "nxdomain", "nodata", "dname", "foreign-final", "wrong-family", "unresolved-final", "cycle", "changed-owner", "changed-substitution"} {
		t.Run(scenario, func(t *testing.T) {
			kind := uint16(1)
			data := []byte{192, 0, 2, 9}
			if scenario == "ipv6" {
				kind = 28
				data = netip.MustParseAddr("2001:db8::9").AsSlice()
			}
			q, _ := queryFor("host.entry.example", kind, true, true)
			final, _ := ResolvedAliasQuery(q, "host.exit.example", kind)
			steps := []ResolvedAlias{{Name: "host.entry.example", Target: "host.exit.example", Owner: "host.entry.example", TTL: 30}}
			if scenario == "dname" || scenario == "changed-substitution" {
				steps[0].DNAME = true
				steps[0].Owner = "entry.example"
				steps[0].DomainTarget = "exit.example"
			}
			switch scenario {
			case "foreign-final":
				final, _ = ResolvedAliasQuery(q, "foreign.example", kind)
			case "wrong-family":
				final, _ = ResolvedAliasQuery(q, "host.exit.example", 28)
			case "cycle":
				steps = append(steps, ResolvedAlias{Name: "host.exit.example", Target: "host.entry.example", Owner: "host.exit.example", TTL: 30})
			case "changed-owner":
				steps[0].Owner = "foreign.example"
			case "changed-substitution":
				steps[0].DomainTarget = "foreign.example"
			}
			response := aliasTestResponse(t, final, aliasTestRR("host.exit.example", kind, data))
			if scenario == "nxdomain" || scenario == "nodata" {
				response = aliasTestResponse(t, final)
				if scenario == "nxdomain" {
					response[3] |= 3
				}
			}
			if scenario == "unresolved-final" {
				response = aliasTestResponse(t, final, aliasTestRR("host.exit.example", 5, aliasTestName("third.example")))
			}
			answer, err := ResolvedAliasAnswer(q, steps, final, response, scenario != "insecure")
			switch scenario {
			case "ipv4", "ipv6", "insecure", "nxdomain", "nodata", "dname":
				if err != nil {
					t.Fatal(err)
				}
				ips, err := addressesFor(q, answer)
				want := 1
				if scenario == "nxdomain" || scenario == "nodata" {
					want = 0
				}
				if err != nil || len(ips) != want || (answer[3]&0x20 != 0) != (scenario != "insecure") || answer[3]&15 != response[3]&15 {
					t.Fatal("alias result lost original family, denial or authentication", ips, err)
				}
			default:
				if err == nil || answer != nil {
					t.Fatal("unproved alias chain was composed")
				}
			}
		})
	}
}

func TestResolvedAliasQueryPurpose(t *testing.T) {
	original, _ := queryFor("original.example", 1, true, true)
	for _, kind := range []uint16{1, 28, 5} {
		q, err := ResolvedAliasQuery(original, "target.example", kind)
		if err != nil {
			t.Fatal(err)
		}
		_, end, err := dnsName(q, 12)
		if err != nil || binary.BigEndian.Uint16(q[end:]) != kind || q[3] != original[3] || q[11] != original[11] || QuestionMatchesName(q, "target.example") != (kind != 5) {
			t.Fatal("alias query changed original options or ordinary admission")
		}
	}
	if _, err := ResolvedAliasQuery(original, "target.example", 39); err == nil {
		t.Fatal("arbitrary DNAME owner query admitted")
	}
	bad := append([]byte(nil), original...)
	bad[2] |= 0x80
	if _, err := ResolvedAliasQuery(bad, "target.example", 5); err == nil {
		t.Fatal("response substituted for original question")
	}
}
