package main

import (
	"testing"

	"router-vpn/internal/common"
)

func dnsTestProfile() common.RouterProfile {
	return common.RouterProfile{
		ID: "home", Name: "Home Router", NodeKind: "router-vpn",
		AdGuardIPv4: "10.77.0.1", AdGuardIPv6: "fd77:77::1",
		DNSMode: "home", DNSProtocol: "udp", DNSHost: "10.77.0.1", DNSPort: 53,
		FastestDNSHost: "9.9.9.9", FastestDNSName: "Quad9 IPv4", FastestDNSLatencyMs: 7.5,
	}
}

func TestApplyDNSPolicyHomeAndFastest(t *testing.T) {
	p := dnsTestProfile()
	home, err := applyDNSPolicyToProfile(p, dnsPolicyRequest{Mode: "home"})
	if err != nil { t.Fatal(err) }
	if home.DNSHost != "10.77.0.1" || home.DNSProtocol != "udp" || home.DNSPort != 53 { t.Fatalf("unexpected home policy: %+v", home) }
	fastest, err := applyDNSPolicyToProfile(p, dnsPolicyRequest{Mode: "fastest"})
	if err != nil { t.Fatal(err) }
	if fastest.DNSHost != "9.9.9.9" || fastest.DNSMode != "fastest" || fastest.DNSPort != 53 { t.Fatalf("unexpected fastest policy: %+v", fastest) }
}

func TestApplyDNSPolicyEncryptedInference(t *testing.T) {
	p := dnsTestProfile()
	doh, err := applyDNSPolicyToProfile(p, dnsPolicyRequest{Mode: "doh", Host: "1.1.1.1"})
	if err != nil { t.Fatal(err) }
	if doh.DNSProtocol != "https" || doh.DNSPort != 443 || doh.DNSServerName != "cloudflare-dns.com" || doh.DNSPath != "/dns-query" { t.Fatalf("unexpected DoH policy: %+v", doh) }
	dot, err := applyDNSPolicyToProfile(p, dnsPolicyRequest{Mode: "dot", Host: "dns.google"})
	if err != nil { t.Fatal(err) }
	if dot.DNSProtocol != "tls" || dot.DNSPort != 853 || dot.DNSServerName != "dns.google" { t.Fatalf("unexpected DoT policy: %+v", dot) }
}

func TestApplyDNSPolicyRejectsUnsafeOrUnsupported(t *testing.T) {
	p := dnsTestProfile()
	for _, request := range []dnsPolicyRequest{
		{Mode: "custom", Protocol: "https", Host: "1.1.1.1"},
		{Mode: "doh", Host: "203.0.113.1"},
		{Mode: "custom", Protocol: "udp", Host: "bad host"},
		{Mode: "doh", Host: "1.1.1.1", Path: "dns-query"},
		{Mode: "bogus", Host: "1.1.1.1"},
	} {
		if _, err := applyDNSPolicyToProfile(p, request); err == nil { t.Fatalf("expected rejection for %+v", request) }
	}
}

func TestDNSPolicyOnlyMutatesDNSFields(t *testing.T) {
	p := dnsTestProfile()
	p.Endpoint = "vpn.example.test"
	p.APIToken = "private-token"
	p.NodeProofID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	p.HomeLANAccess = true
	p.KillSwitch = true
	p.ManualMTU = 1337
	updated, err := applyDNSPolicyToProfile(p, dnsPolicyRequest{Mode: "custom", Protocol: "tcp", Host: "8.8.8.8", Port: 53})
	if err != nil { t.Fatal(err) }
	if updated.Endpoint != p.Endpoint || updated.APIToken != p.APIToken || updated.NodeProofID != p.NodeProofID || updated.HomeLANAccess != p.HomeLANAccess || updated.KillSwitch != p.KillSwitch || updated.ManualMTU != p.ManualMTU {
		t.Fatalf("non-DNS profile fields changed: before=%+v after=%+v", p, updated)
	}
	if updated.DNSMode != "custom" || updated.DNSProtocol != "tcp" || updated.DNSHost != "8.8.8.8" { t.Fatalf("DNS fields were not updated: %+v", updated) }
}
