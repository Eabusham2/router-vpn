package standardengine

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func privateTLDPlan(t *testing.T, scenario string) (ResolvedPolicy, *ResolvedDNSSECPlan) {
	t.Helper()
	p, root := resolvedRootDSFixture()
	name := "vpn.example"
	present := map[ResolvedDNSSECQuestion]bool{{".", 43}: true}
	switch scenario {
	case "strict":
		p.Manager.DNSSEC = "yes"
		root.DNSSEC = "yes"
	case "deep":
		name = "host.vpn.example"
	case "single":
		name = "example"
	case "empty":
		delete(present, ResolvedDNSSECQuestion{".", 43})
	case "island-ds", "shadowed":
		present[ResolvedDNSSECQuestion{"example", 43}] = true
	case "island-key":
		present[ResolvedDNSSECQuestion{"example", 48}] = true
	case "root-key":
		delete(present, ResolvedDNSSECQuestion{".", 43})
		present[ResolvedDNSSECQuestion{".", 48}] = true
	}
	if scenario == "unrelated-nta" {
		p.Manager.NegativeTrustAnchors = []string{"unrelated"}
	}
	if scenario == "root-nta" {
		p.Manager.NegativeTrustAnchors = []string{"."}
	}
	if scenario == "tld-nta" {
		p.Manager.NegativeTrustAnchors = []string{"example"}
	}
	if scenario == "name-nta" {
		p.Manager.NegativeTrustAnchors = []string{"vpn.example"}
	}
	if scenario == "shadowed" {
		p.Manager.NegativeTrustAnchors = []string{"example"}
	}
	raw, _ := p.Canonical()
	root.PolicySHA256 = ResolvedPolicySHA256(raw)
	root.Name = name
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
	return p, plan
}
func TestResolvedPrivateTLDRootAuthority(t *testing.T) {
	for _, scenario := range []string{"root-ds", "root-key", "unrelated-nta", "root-nta", "tld-nta", "name-nta", "strict", "deep", "empty", "island-ds", "island-key", "shadowed", "alias-type", "bad-digest", "foreign-policy"} {
		t.Run(scenario, func(t *testing.T) {
			if scenario == "root-nta" {
				p, _ := resolvedRootDSFixture()
				p.Manager.NegativeTrustAnchors = []string{"."}
				if _, err := p.Canonical(); err == nil {
					t.Fatal("root NTA escaped current policy boundary")
				}
				return
			}
			p, plan := privateTLDPlan(t, scenario)
			kind := uint16(1)
			digest := strings.Repeat("a", 64)
			if scenario == "alias-type" {
				kind = 5
			}
			if scenario == "bad-digest" {
				digest = "a"
			}
			if scenario == "foreign-policy" {
				p.Manager.DNSOverTLS = "yes"
			}
			proof, err := NewResolvedPrivateTLDProof(p, plan, kind, digest)
			want := scenario == "root-ds" || scenario == "root-key" || scenario == "unrelated-nta"
			if (err == nil) != want {
				t.Fatalf("admission %s: %v", scenario, err)
			}
			if !want {
				return
			}
			if proof.TLD() != "example." || proof.Name() != "vpn.example" || proof.Index() != 0 || !proof.Matches(p, plan, kind, digest) {
				t.Fatal("original association lost")
			}
			if proof.Matches(p, plan, 28, digest) || proof.Matches(p, plan, kind, strings.Repeat("b", 64)) {
				t.Fatal("candidate/type rebound")
			}
			raw := proof.Canonical()
			saved := bytes.Clone(raw)
			raw[0] ^= 1
			if !bytes.Equal(proof.Canonical(), saved) {
				t.Fatal("canonical ownership lost")
			}
			input := proof.Inputs()
			input.TrustAnchors[0] = "changed"
			if proof.Inputs().TrustAnchors[0] == "changed" {
				t.Fatal("anchor ownership lost")
			}
		})
	}
}
func TestResolvedPrivateTLDQueryPurpose(t *testing.T) {
	p, plan := privateTLDPlan(t, "root-ds")
	proof, err := NewResolvedPrivateTLDProof(p, plan, 28, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		name string
		kind uint16
		want bool
	}{{"example.", 1, true}, {"example.", 43, true}, {"example.", 48, true}, {".", 43, true}, {".", 48, true}, {"example.", 28, false}, {"example.", 5, false}, {"vpn.example.", 1, false}, {"vpn.example.", 43, false}, {"other.", 1, false}, {".", 1, false}} {
		t.Run(fmt.Sprintf("%s-%d", x.name, x.kind), func(t *testing.T) {
			_, err := proof.Question(resolvedDNSSECWire(x.name, x.kind, true))
			if (err == nil) != x.want {
				t.Fatal(x, err)
			}
		})
	}
}

func TestResolvedPrivateTLDVerdict(t *testing.T) {
	for _, fault := range []string{"secure", "bogus", "insecure", "nodata", "wrong-name", "address-data", "foreign-id", "truncated", "alias-answer"} {
		t.Run(fault, func(t *testing.T) {
			p, plan := privateTLDPlan(t, "root-ds")
			proof, err := NewResolvedPrivateTLDProof(p, plan, 1, strings.Repeat("a", 64))
			if err != nil {
				t.Fatal(err)
			}
			q := resolvedDNSSECWire("example.", 1, false)
			r := bytes.Clone(q)
			r[2] = 0x81
			r[3] = 0x83
			v := DNSSECVerdict{State: 1, RCode: 3, NXDomain: 1, Packet: r}
			switch fault {
			case "bogus":
				v.State = 3
			case "insecure":
				v.State = 2
			case "nodata":
				v.RCode = 0
				v.NXDomain = 0
				r[3] &^= 15
			case "wrong-name":
				q = resolvedDNSSECWire("other.", 1, false)
			case "address-data":
				v.HaveData = 1
			case "foreign-id":
				r[0] ^= 1
			case "truncated":
				r[2] |= 2
			case "alias-answer":
				r[7] = 1
				r = append(r, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 7, 5, 'o', 't', 'h', 'e', 'r', 0)
				v.Packet = r
			}
			if err := proof.CheckVerdict(q, v); (err == nil) != (fault == "secure") {
				t.Fatal(fault, err)
			}
		})
	}
}
