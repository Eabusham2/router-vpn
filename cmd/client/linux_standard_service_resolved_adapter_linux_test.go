//go:build linux

package main

import (
	"router-vpn/internal/standardengine"
	"strings"
	"testing"
)

func resolvedAdapterPolicy() standardengine.ResolvedPolicy {
	server := standardengine.ResolvedDNS{Address: "192.0.2.53", Port: 5353, ServerName: "original.example"}
	return standardengine.ResolvedPolicy{Schema: 1, Authority: standardengine.ResolvedAuthority{BusID: strings.Repeat("a", 32), UniqueOwner: ":1.42", PID: 42, NamespaceInode: 9, PhysicalSHA256: strings.Repeat("b", 64)}, LLMNRHostname: "original-host", Manager: standardengine.ResolvedScope{CurrentDNS: &server, DNS: []standardengine.ResolvedDNS{server}, DNSOverTLS: "no", DNSSEC: "no"}}
}
func TestResolvedAdapterSelectedUpstream(t *testing.T) {
	for _, row := range []struct {
		name, mode, network string
		port, want          uint16
	}{
		{"udp-explicit", "no", "udp", 5353, 5353}, {"tcp-explicit", "no", "tcp", 3053, 3053}, {"udp-default", "no", "udp", 0, 53}, {"tls-explicit", "yes", "udp", 8853, 8853}, {"tls-default", "yes", "tcp", 0, 853},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := resolvedAdapterPolicy()
			p.Manager.DNSOverTLS = row.mode
			p.Manager.DNS[0].Port = row.port
			p.Manager.CurrentDNS = &p.Manager.DNS[0]
			got, err := resolvedSelectedUpstream(p, "vpn.example", row.network)
			if err != nil || got.Endpoint.Port() != row.want || got.Endpoint.Addr().String() != "192.0.2.53" || got.InterfaceIndex != 0 {
				t.Fatalf("captured tuple lost: %+v %v", got, err)
			}
			if row.mode == "yes" {
				if got.Network != "tls" || got.TLSServerName != "original.example" {
					t.Fatal("strict TLS identity lost", got)
				}
			} else if got.Network != row.network || got.TLSServerName != "" {
				t.Fatal("plaintext gained TLS policy", got)
			}
		})
	}
	t.Run("selected-link", func(t *testing.T) {
		p := resolvedAdapterPolicy()
		s := p.Manager.DNS[0]
		s.Index = 7
		link := standardengine.ResolvedScope{Index: 7, CurrentDNS: &s, DNS: []standardengine.ResolvedDNS{s}, Domains: []standardengine.ResolvedDomain{{Index: 7, Name: "example", RoutingOnly: true}}}
		p.Manager.DNS = link.DNS
		p.Manager.Domains = link.Domains
		p.Manager.CurrentDNS = &s
		p.Links = []standardengine.ResolvedScope{link}
		got, err := resolvedSelectedUpstream(p, "vpn.example", "udp")
		if err != nil || got.InterfaceIndex != 7 {
			t.Fatalf("lost original selected link: %+v %v", got, err)
		}
	})
	for name, mutate := range map[string]func(*standardengine.ResolvedPolicy){
		"dnssec-required":   func(p *standardengine.ResolvedPolicy) { p.Manager.DNSSEC = "yes" },
		"dnssec-downgrade":  func(p *standardengine.ResolvedPolicy) { p.Manager.DNSSEC = "allow-downgrade" },
		"unknown-dnssec":    func(p *standardengine.ResolvedPolicy) { p.Manager.DNSSEC = "" },
		"opportunistic-tls": func(p *standardengine.ResolvedPolicy) { p.Manager.DNSOverTLS = "opportunistic" },
		"unknown-tls":       func(p *standardengine.ResolvedPolicy) { p.Manager.DNSOverTLS = "" },
		"missing-selection": func(p *standardengine.ResolvedPolicy) { p.Manager.CurrentDNS = nil },
		"parallel-scopes": func(p *standardengine.ResolvedPolicy) {
			s := p.Manager.DNS[0]
			s.Index = 7
			p.Manager.DNS = append(p.Manager.DNS, s)
			p.Links = []standardengine.ResolvedScope{{Index: 7, DNS: []standardengine.ResolvedDNS{s}, CurrentDNS: &s, DefaultRoute: true}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := resolvedAdapterPolicy()
			mutate(&p)
			if _, err := resolvedSelectedUpstream(p, "vpn.example", "udp"); err == nil {
				t.Fatal("unsupported original policy silently downgraded")
			}
		})
	}
}
