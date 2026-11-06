package standardengine

import (
	"strings"
	"testing"
)

func resolvedPolicyFixture() ResolvedPolicy {
	scope := ResolvedScope{DNS: []ResolvedDNS{{0, "192.0.2.53", 5353, "dns.example"}, {0, "2001:db8::53", 853, "tls.example"}}, Domains: []ResolvedDomain{{0, "internal.example", false}, {0, ".", true}}, DefaultRoute: true, LLMNR: "resolve", MulticastDNS: "no", DNSOverTLS: "opportunistic", DNSSEC: "allow-downgrade", NegativeTrustAnchors: []string{"private.example"}}
	link := scope
	link.Index = 7
	link.DNS = append([]ResolvedDNS(nil), scope.DNS...)
	for i := range link.DNS {
		link.DNS[i].Index = 7
	}
	link.Domains = append([]ResolvedDomain(nil), scope.Domains...)
	for i := range link.Domains {
		link.Domains[i].Index = 7
	}
	scope.DNS = append(scope.DNS, link.DNS...)
	scope.Domains = append(scope.Domains, link.Domains...)
	selected := link.DNS[1]
	scope.CurrentDNS = &selected
	link.CurrentDNS = &selected
	return ResolvedPolicy{Schema: 1, Authority: ResolvedAuthority{strings.Repeat("a", 32), ":1.42", 42, 4, 9, strings.Repeat("b", 64)}, LLMNRHostname: "original-daemon", Manager: scope, FallbackDNS: []ResolvedDNS{{0, "198.51.100.53", 0, ""}}, Links: []ResolvedScope{link}}
}

func TestResolvedPolicyRetainsOrderedOriginalScope(t *testing.T) {
	p := resolvedPolicyFixture()
	raw, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResolvedPolicy(raw, SHA256(raw))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Manager.DNS[0].Port != 5353 || decoded.Manager.DNS[1].ServerName != "tls.example" || decoded.Links[0].Index != 7 || decoded.FallbackDNS[0].Port != 0 {
		t.Fatal("endpoint scope, port, SNI or default port lost")
	}
	for _, mutate := range []func(*ResolvedPolicy){
		func(p *ResolvedPolicy) { p.Manager.DNS[0], p.Manager.DNS[1] = p.Manager.DNS[1], p.Manager.DNS[0] },
		func(p *ResolvedPolicy) {
			p.Manager.Domains[0], p.Manager.Domains[1] = p.Manager.Domains[1], p.Manager.Domains[0]
		},
		func(p *ResolvedPolicy) { p.Links[0].DefaultRoute = false },
		func(p *ResolvedPolicy) { p.Links[0].DNSSEC = "yes" },
		func(p *ResolvedPolicy) { p.Authority.NamespaceInode++ },
		func(p *ResolvedPolicy) { p.Authority.UniqueOwner = ":1.43" },
		func(p *ResolvedPolicy) { p.LLMNRHostname = "replacement" },
		func(p *ResolvedPolicy) { selected := p.Links[0].DNS[0]; p.Manager.CurrentDNS = &selected },
	} {
		changed, err := DecodeResolvedPolicy(raw, SHA256(raw))
		if err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		other, err := changed.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if SHA256(other) == SHA256(raw) {
			t.Fatal("original policy mutation retained identity")
		}
		if _, err = DecodeResolvedPolicy(other, SHA256(raw)); err == nil {
			t.Fatal("accepted successor as original")
		}
	}
	decoded.Manager.DNS[0].Address = "203.0.113.9"
	if p.Manager.DNS[0].Address != "192.0.2.53" {
		t.Fatal("decoded observation aliases caller")
	}
}

func TestResolvedPolicyRejectsIncompleteScopes(t *testing.T) {
	for name, mutate := range map[string]func(*ResolvedPolicy){
		"schema":                    func(p *ResolvedPolicy) { p.Schema = 2 },
		"bus":                       func(p *ResolvedPolicy) { p.Authority.BusID = "" },
		"owner":                     func(p *ResolvedPolicy) { p.Authority.UniqueOwner = "org.freedesktop.resolve1" },
		"owner-delimiter":           func(p *ResolvedPolicy) { p.Authority.UniqueOwner = ":1.42,invalid" },
		"pid":                       func(p *ResolvedPolicy) { p.Authority.PID = 0 },
		"namespace":                 func(p *ResolvedPolicy) { p.Authority.NamespaceInode = 0 },
		"observer":                  func(p *ResolvedPolicy) { p.Authority.PhysicalSHA256 = "" },
		"repeated-link":             func(p *ResolvedPolicy) { p.Links = append(p.Links, p.Links[0]) },
		"global-link":               func(p *ResolvedPolicy) { p.Links[0].Index = 0 },
		"unbounded-links":           func(p *ResolvedPolicy) { p.Links = make([]ResolvedScope, 257) },
		"manager-link-disagreement": func(p *ResolvedPolicy) { p.Manager.DNS[2].Port++ },
		"manager-row-ifindex":       func(p *ResolvedPolicy) { p.Manager.DNS[0].Index = 99 },
		"link-row-ifindex":          func(p *ResolvedPolicy) { p.Links[0].DNS[0].Index = 8 },
		"current-ifindex":           func(p *ResolvedPolicy) { p.Manager.CurrentDNS.Index = 99 },
		"missing-hostname":          func(p *ResolvedPolicy) { p.LLMNRHostname = "" },
		"security":                  func(p *ResolvedPolicy) { p.Manager.DNSSEC = "ignore" },
		"bad-sni":                   func(p *ResolvedPolicy) { p.Manager.DNS[0].ServerName = "injected\nname" },
		"embedded-zone":             func(p *ResolvedPolicy) { p.Manager.DNS[0].Address = "fe80::1%7" },
		"multicast":                 func(p *ResolvedPolicy) { p.Manager.DNS[0].Address = "224.0.0.251" },
		"root-search":               func(p *ResolvedPolicy) { p.Manager.Domains = []ResolvedDomain{{0, ".", false}} },
	} {
		t.Run(name, func(t *testing.T) {
			p := resolvedPolicyFixture()
			mutate(&p)
			if _, err := p.Canonical(); err == nil {
				t.Fatal("incomplete authority admitted")
			}
		})
	}
}
