package standardengine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func privateDSWire(name string, kind uint16) []byte {
	q := []byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label != "" {
			q = append(q, byte(len(label)))
			q = append(q, label...)
		}
	}
	return append(q, 0, byte(kind>>8), byte(kind), 0, 1)
}
func privateDSEmpty(q []byte, rcode byte) []byte {
	r := bytes.Clone(q)
	r[2] = 0x81
	r[3] = 0x80 | rcode
	return r
}
func TestResolvedPrivateDSDependencies(t *testing.T) {
	for _, scenario := range []string{"complete", "negative-dependencies", "old-api", "two-label", "four-label", "foreign-policy", "foreign-candidate", "missing", "foreign-reply-authority", "reordered", "positive", "signed", "alias", "foreign-name", "foreign-class", "servfail", "root-bogus", "root-insecure", "root-nodata", "root-alias", "changed-plan"} {
		t.Run(scenario, func(t *testing.T) {
			p, plan := privateTLDPlan(t, "deep")
			digest := strings.Repeat("a", 64)
			if scenario == "two-label" {
				p, plan = privateTLDPlan(t, "root-ds")
			}
			if scenario == "four-label" {
				plan.name = "four.host.vpn.example"
			}
			if scenario == "foreign-policy" {
				p.Manager.DNSOverTLS = "yes"
			}
			if scenario == "old-api" {
				if _, err := NewResolvedPrivateTLDProof(p, plan, 1, digest); err == nil {
					t.Fatal("old two-label constructor changed")
				}
				return
			}
			cap, err := NewResolvedPrivateDSDependencies(p, plan, 1, digest)
			if scenario == "two-label" || scenario == "four-label" || scenario == "foreign-policy" {
				if err == nil {
					t.Fatal("foreign authority admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !cap.Matches(p, plan, 1, digest) || cap.TLD() != "example." || cap.Name() != "host.vpn.example" || len(cap.Questions()) != 2 {
				t.Fatal("original capability changed")
			}
			if scenario == "foreign-candidate" {
				if cap.Matches(p, plan, 1, strings.Repeat("b", 64)) {
					t.Fatal("candidate rebound")
				}
				return
			}
			replies := []ResolvedPrivateDSReply{}
			for _, q := range cap.Questions() {
				wire := privateDSWire(q.Name, q.Type)
				replies = append(replies, ResolvedPrivateDSReply{SHA256(cap.Canonical()), wire, privateDSEmpty(wire, 0)})
			}
			rootQ := privateDSWire(cap.TLD(), 1)
			v := DNSSECVerdict{State: 1, RCode: 3, NXDomain: 1, Packet: privateDSEmpty(rootQ, 3)}
			switch scenario {
			case "negative-dependencies":
				for i := range replies {
					replies[i].Response[3] |= 3
				}
			case "foreign-reply-authority":
				replies[0].AuthoritySHA256 = strings.Repeat("b", 64)
			case "missing":
				replies = replies[:1]
			case "reordered":
				replies[0], replies[1] = replies[1], replies[0]
			case "positive", "signed", "alias":
				typ := uint16(43)
				if scenario == "signed" {
					typ = 46
				}
				if scenario == "alias" {
					typ = 5
				}
				r := replies[0].Response
				binary.BigEndian.PutUint16(r[6:], 1)
				r = append(r, 0xc0, 12, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 1, 0, 0)
				replies[0].Response = r
			case "foreign-name":
				replies[0].Question = privateDSWire("foreign.vpn.example", 43)
				replies[0].Response = privateDSEmpty(replies[0].Question, 0)
			case "foreign-class":
				replies[0].Question[len(replies[0].Question)-1] = 3
				replies[0].Response = privateDSEmpty(replies[0].Question, 0)
			case "servfail":
				replies[0].Response[3] = 0x82
			case "root-bogus":
				v.State = 3
			case "root-insecure":
				v.State = 2
			case "root-nodata":
				v.RCode = 0
				v.NXDomain = 0
				v.Packet = privateDSEmpty(rootQ, 0)
			case "root-alias":
				binary.BigEndian.PutUint16(v.Packet[6:], 1)
				v.Packet = append(v.Packet, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 2, 0xc0, 12)
			}
			proof, err := cap.Complete(replies, rootQ, v)
			want := scenario == "complete" || scenario == "negative-dependencies" || scenario == "changed-plan"
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
			if !want {
				return
			}
			if !proof.Matches(p, plan, 1, digest) {
				t.Fatal("completed authority lost")
			}
			saved := proof.Canonical()
			replies[0].Response[3] ^= 3
			v.Packet[0] ^= 1
			if !bytes.Equal(saved, proof.Canonical()) {
				t.Fatal("completed proof retained mutable packets")
			}
			if scenario == "changed-plan" {
				p.Manager.CurrentDNS.Address = "192.0.2.99"
				if proof.Matches(p, plan, 1, digest) {
					t.Fatal("current server change admitted")
				}
			}
		})
	}
}

func TestResolvedPrivateDSOriginalAuthority(t *testing.T) {
	for _, scenario := range []string{"original", "unrelated-nta", "strict", "tld-nta", "parent-nta", "original-nta", "parent-ds", "original-key", "shadowed-island", "empty-root", "changed-server", "wrong-type"} {
		t.Run(scenario, func(t *testing.T) {
			p, root := resolvedRootDSFixture()
			name := "host.vpn.example"
			root.Name = name
			present := map[ResolvedDNSSECQuestion]bool{{".", 43}: true}
			switch scenario {
			case "unrelated-nta":
				p.Manager.NegativeTrustAnchors = []string{"unrelated"}
			case "strict":
				p.Manager.DNSSEC = "yes"
				root.DNSSEC = "yes"
			case "tld-nta":
				p.Manager.NegativeTrustAnchors = []string{"example"}
			case "parent-nta":
				p.Manager.NegativeTrustAnchors = []string{"vpn.example"}
			case "original-nta":
				p.Manager.NegativeTrustAnchors = []string{name}
			case "parent-ds", "shadowed-island":
				present[ResolvedDNSSECQuestion{"vpn.example", 43}] = true
			case "original-key":
				present[ResolvedDNSSECQuestion{name, 48}] = true
			case "empty-root":
				delete(present, ResolvedDNSSECQuestion{".", 43})
			}
			if scenario == "shadowed-island" {
				p.Manager.NegativeTrustAnchors = []string{"vpn.example"}
			}
			raw, _ := p.Canonical()
			root.PolicySHA256 = ResolvedPolicySHA256(raw)
			rows := resolvedDNSSECObservations(t, p, name, 0, present)
			var other []ResolvedAnchorResult
			for _, r := range rows {
				if r.Name == "." && r.Type == 43 {
					if r.Present {
						root.Outcome = "positive"
						copy := r
						root.Root = &copy
					}
				} else {
					other = append(other, r)
				}
			}
			plan, err := BuildResolvedDNSSECPlanWithRootDS(p, name, 0, root, other)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "changed-server" {
				p.Manager.CurrentDNS.Address = "192.0.2.99"
			}
			kind := uint16(1)
			if scenario == "wrong-type" {
				kind = 5
			}
			cap, err := NewResolvedPrivateDSDependencies(p, plan, kind, strings.Repeat("a", 64))
			want := scenario == "original" || scenario == "unrelated-nta"
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
			if want && !cap.MatchesPolicy(p) {
				t.Fatal("original policy absent")
			}
		})
	}
}

func TestResolvedPrivateDSQuestionPurpose(t *testing.T) {
	p, plan := privateTLDPlan(t, "deep")
	cap, err := NewResolvedPrivateDSDependencies(p, plan, 1, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name string
		kind uint16
		want bool
	}{{"host.vpn.example.", 43, true}, {"vpn.example.", 43, true}, {"example.", 43, false}, {".", 43, false}, {"host.vpn.example.", 48, false}, {"host.vpn.example.", 1, false}, {"other.vpn.example.", 43, false}, {"vpn.example.", 5, false}} {
		t.Run(row.name+"-"+fmt.Sprint(row.kind), func(t *testing.T) {
			q := privateDSWire(row.name, row.kind)
			_, err := cap.Question(q)
			if (err == nil) != row.want {
				t.Fatal(err)
			}
		})
	}
	var zero ResolvedPrivateDSDependencies
	if _, err = zero.Question(privateDSWire("host.vpn.example.", 43)); err == nil {
		t.Fatal("zero capability admitted dependency")
	}
}
