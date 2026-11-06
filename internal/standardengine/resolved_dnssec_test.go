package standardengine

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func resolvedDNSSECPolicyFixture() ResolvedPolicy {
	p := resolvedPolicyFixture()
	p.Links = nil
	p.Manager.DNS = p.Manager.DNS[:2]
	p.Manager.Domains = nil
	p.Manager.NegativeTrustAnchors = nil
	p.Manager.DNSSEC = "yes"
	p.Manager.CurrentDNS = &p.Manager.DNS[0]
	return p
}
func resolvedDNSSECObservations(t *testing.T, p ResolvedPolicy, name string, index int32, present map[ResolvedDNSSECQuestion]bool) []ResolvedAnchorResult {
	t.Helper()
	questions, err := ResolvedDNSSECQuestions(p, name, index)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := p.Canonical()
	hash := ResolvedPolicySHA256(raw)
	var out []ResolvedAnchorResult
	for _, q := range questions {
		row := ResolvedAnchorResult{PolicySHA256: hash, Index: index, Name: q.Name, Type: q.Type}
		if present[q] {
			row = resolvedAnchorFixture(q.Type)
			row.PolicySHA256 = hash
			row.Index = index
			row.Name = q.Name
			var prefix []byte
			if q.Name != "." {
				for _, label := range strings.Split(q.Name, ".") {
					prefix = append(prefix, byte(len(label)))
					prefix = append(prefix, label...)
				}
			}
			prefix = append(prefix, 0)
			row.Records[0] = append(prefix, row.Records[0][1:]...)
		}
		out = append(out, row)
	}
	return out
}
func TestResolvedDNSSECOriginalNTASelection(t *testing.T) {
	for _, name := range []string{"global-descendant-ds", "global-descendant-dnskey", "global-exact-negative", "link-negative-overrides-ds", "strict", "allow-downgrade"} {
		t.Run(name, func(t *testing.T) {
			p := resolvedDNSSECPolicyFixture()
			index := int32(0)
			kind := uint16(43)
			want := 1
			if name != "strict" && name != "allow-downgrade" {
				p.Manager.NegativeTrustAnchors = []string{"example"}
			}
			if name == "global-descendant-dnskey" {
				kind = 48
				want = 0
			}
			if name == "global-exact-negative" {
				p.Manager.NegativeTrustAnchors = []string{"private.example"}
				want = 0
			}
			if name == "link-negative-overrides-ds" {
				server := p.Manager.DNS[0]
				server.Index = 7
				p.Manager.DNS = append(p.Manager.DNS, server)
				p.Links = []ResolvedScope{{Index: 7, DNS: []ResolvedDNS{server}, CurrentDNS: &server, DefaultRoute: true, NegativeTrustAnchors: []string{"example"}}}
				index = 7
				want = 0
			}
			if name == "allow-downgrade" {
				p.Manager.DNSSEC = "allow-downgrade"
			}
			rows := resolvedDNSSECObservations(t, p, "vpn.private.example", index, map[ResolvedDNSSECQuestion]bool{{"private.example", kind}: true})
			plan, err := BuildResolvedDNSSECPlan(p, "vpn.private.example", index, rows)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Inputs().TrustAnchors) != want {
				t.Fatal("original NTA precedence changed", plan.Inputs())
			}
			if plan.Mode() != p.Manager.DNSSEC || plan.Index() != index || plan.Name() != "vpn.private.example" {
				t.Fatal("original validating mode/scope changed")
			}
			if err = plan.Recheck(rows); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestResolvedDNSSECWireTextAndImmutableInputs(t *testing.T) {
	p := resolvedDNSSECPolicyFixture()
	rows := resolvedDNSSECObservations(t, p, "vpn.example", 0, map[ResolvedDNSSECQuestion]bool{{".", 43}: true, {"example", 48}: true})
	plan, err := BuildResolvedDNSSECPlan(p, "vpn.example", 0, rows)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := plan.ValidatorInputs()
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs.TrustAnchors) != 2 || inputs.TrustAnchors[0] != "example. 0 IN DNSKEY 257 3 13 AQIDBA==" || inputs.TrustAnchors[1] != ". 0 IN DS 20326 8 2 "+strings.Repeat("00", 32) {
		t.Fatal(inputs)
	}
	canonical := plan.Canonical()
	inputs.TrustAnchors[0] = "foreign"
	copy := plan.Canonical()
	copy[0] ^= 1
	rows[0].Name = "foreign.example"
	if !bytes.Equal(canonical, plan.Canonical()) || plan.Inputs().TrustAnchors[0] == "foreign" {
		t.Fatal("caller mutated immutable original plan")
	}
}
func TestResolvedDNSSECRechecksPresenceAndAbsence(t *testing.T) {
	for _, name := range []string{"absent-became-present", "present-disappeared", "record-changed", "missing", "reordered", "foreign-policy"} {
		t.Run(name, func(t *testing.T) {
			p := resolvedDNSSECPolicyFixture()
			rows := resolvedDNSSECObservations(t, p, "vpn.example", 0, map[ResolvedDNSSECQuestion]bool{{".", 43}: true})
			plan, err := BuildResolvedDNSSECPlan(p, "vpn.example", 0, rows)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "absent-became-present":
				rows = resolvedDNSSECObservations(t, p, "vpn.example", 0, map[ResolvedDNSSECQuestion]bool{{".", 43}: true, {"example", 43}: true})
			case "present-disappeared":
				rows = resolvedDNSSECObservations(t, p, "vpn.example", 0, nil)
			case "record-changed":
				rows[len(rows)-2].Records[0][len(rows[len(rows)-2].Records[0])-1] ^= 1
			case "missing":
				rows = rows[:len(rows)-1]
			case "reordered":
				rows[0], rows[1] = rows[1], rows[0]
			case "foreign-policy":
				rows[0].PolicySHA256 = strings.Repeat("c", 64)
			}
			if plan.Recheck(rows) == nil {
				t.Fatal("changed original loaded trust store accepted")
			}
		})
	}
}
func TestResolvedDNSSECAbsenceAndCapacityRemainExplicit(t *testing.T) {
	p := resolvedDNSSECPolicyFixture()
	rows := resolvedDNSSECObservations(t, p, "vpn.example", 0, nil)
	plan, err := BuildResolvedDNSSECPlan(p, "vpn.example", 0, rows)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = plan.ValidatorInputs(); err == nil {
		t.Fatal("missing anchors became implicit insecure root")
	}
	for i := 0; i < 33; i++ {
		p.Manager.NegativeTrustAnchors = append(p.Manager.NegativeTrustAnchors, fmt.Sprintf("n%d.example", i))
	}
	rows = resolvedDNSSECObservations(t, p, "vpn.example", 0, map[ResolvedDNSSECQuestion]bool{{".", 43}: true})
	plan, err = BuildResolvedDNSSECPlan(p, "vpn.example", 0, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Inputs().InsecureDomains) != 33 {
		t.Fatal("complete original policy was truncated")
	}
	if _, err = plan.ValidatorInputs(); err == nil {
		t.Fatal("current native capacity was ignored")
	}
}
