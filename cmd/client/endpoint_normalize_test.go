package main

import "testing"

func TestNormalizeEndpointAcceptsDirectIPv4WithoutDDNS(t *testing.T) {
	got, err := normalizeEndpoint("203.0.113.9")
	if err != nil {
		t.Fatalf("direct IPv4 endpoint unexpectedly requires hostname/DDNS: %v", err)
	}
	if got != "203.0.113.9" {
		t.Fatalf("direct IPv4 endpoint changed: %q", got)
	}
}

func TestNormalizeEndpointAcceptsDirectIPv6WithoutDDNS(t *testing.T) {
	got, err := normalizeEndpoint("[2001:db8::9]")
	if err != nil {
		t.Fatalf("direct IPv6 endpoint unexpectedly requires hostname/DDNS: %v", err)
	}
	if got != "2001:db8::9" {
		t.Fatalf("direct IPv6 endpoint changed: %q", got)
	}
}

func TestNormalizeEndpointStillAcceptsHostnameWhenChosen(t *testing.T) {
	got, err := normalizeEndpoint("Vpn.Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if got != "vpn.example.com" {
		t.Fatalf("hostname normalization changed: %q", got)
	}
}
