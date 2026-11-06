//go:build linux

package mobiletor

import (
	"net/netip"
	"router-vpn/internal/standardengine"
	"strings"
	"testing"
)

func bootstrapPrivateTLDFixture(t *testing.T, transport string) (standardengine.ResolvedPolicy, *standardengine.ResolvedDNSSECPlan, *standardengine.ResolvedPrivateTLDProof) {
	t.Helper()
	p := bootstrapOpportunisticPolicy("192.0.2.53", 2053, "original.example")
	p.Manager.DNSSEC = "allow-downgrade"
	p.Manager.DNSOverTLS = transport
	raw, _ := p.Canonical()
	sha := standardengine.ResolvedPolicySHA256(raw)
	qs, err := standardengine.ResolvedDNSSECQuestions(p, "node.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	var rows []standardengine.ResolvedAnchorResult
	for _, q := range qs {
		r := standardengine.ResolvedAnchorResult{PolicySHA256: sha, Name: q.Name, Type: q.Type}
		if q.Name == "." && q.Type == 43 {
			r.Present = true
			r.Flags = standardengine.ResolvedAnchorFlags
			r.Records = [][]byte{{0, 0, 43, 0, 1, 0, 0, 0, 60, 0, 5, 1, 2, 13, 2, 1}}
		}
		rows = append(rows, r)
	}
	plan, err := standardengine.BuildResolvedDNSSECPlan(p, "node.example", 0, rows)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := standardengine.NewResolvedPrivateTLDProof(p, plan, 1, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	return p, plan, proof
}
func TestLinuxStandardBootstrapPrivateTLDPurpose(t *testing.T) {
	for _, transport := range []string{"no", "yes", "opportunistic"} {
		t.Run(transport, func(t *testing.T) {
			p, plan, proof := bootstrapPrivateTLDFixture(t, transport)
			b, err := desktopLinuxBindPrivateTLD(p, []*standardengine.ResolvedPrivateTLDProof{proof})
			if err != nil {
				t.Fatal(err)
			}
			g := &DesktopLinuxBootstrapDNSGroup{dnssec: b}
			ordinary, err := desktopLinuxBindDNSSEC(p, []*standardengine.ResolvedDNSSECPlan{plan}, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"example", "."} {
				kind := uint16(1)
				if name == "." {
					kind = 48
				}
				wire := bootstrapDNSSECWire(name, kind)
				q, err := NewDesktopLinuxBootstrapPrivateTLDQuestion(p, proof, wire)
				if err != nil {
					t.Fatal(err)
				}
				u, err := q.upstream("udp", transport != "no")
				if err != nil || q.matches(g, u, wire) != nil {
					t.Fatal("original proof rejected", err)
				}
				if u.Endpoint.Port() != 2053 || u.Endpoint.Addr().String() != "192.0.2.53" {
					t.Fatal("original resolver lost")
				}
				if transport != "no" && u.TLSServerName != "original.example" {
					t.Fatal("SNI lost")
				}
				if q.matches(&DesktopLinuxBootstrapDNSGroup{dnssec: ordinary}, u, wire) == nil {
					t.Fatal("ordinary group accepted private proof")
				}
				u.Endpoint = netip.AddrPortFrom(u.Endpoint.Addr().Next(), u.Endpoint.Port())
				if q.matches(g, u, wire) == nil {
					t.Fatal("foreign endpoint accepted")
				}
			}
			if _, err = NewDesktopLinuxBootstrapPrivateTLDQuestion(p, proof, bootstrapDNSSECWire("node.example", 1)); err == nil {
				t.Fatal("original address inherited proof authority")
			}
			if _, err = desktopLinuxBindPrivateTLD(p, []*standardengine.ResolvedPrivateTLDProof{proof, proof}); err == nil {
				t.Fatal("duplicated scope accepted")
			}
		})
	}
}
