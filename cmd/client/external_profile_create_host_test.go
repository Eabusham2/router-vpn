package main

import (
	"strings"
	"testing"
)

func TestTypedExternalProfileBuilderRejectsUnsafeServerTextBeforePersistence(t *testing.T) {
	protocols := []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"}
	badServers := []string{
		"https://proxy.example.com",
		"proxy.example.com/path",
		"proxy.example.com?query=1",
		"user@proxy.example.com",
		"proxy example.com",
		"proxy.example.com\nother.example.com",
	}
	for _, protocol := range protocols {
		for _, server := range badServers {
			q := createRequestFor(protocol)
			q.Server = server
			if _, err := externalProfileFromCreateRequest(q); err == nil || !strings.Contains(err.Error(), "node server") {
				t.Fatalf("%s persisted unsafe server %q instead of rejecting it early: %v", protocol, server, err)
			}
		}
	}
}

func TestTypedExternalProfileBuilderNormalizesHostnameBeforePersistence(t *testing.T) {
	for _, protocol := range []string{"socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		q := createRequestFor(protocol)
		q.Server = "Vpn.Example.COM"
		p, err := externalProfileFromCreateRequest(q)
		if err != nil {
			t.Fatalf("%s hostname rejected: %v", protocol, err)
		}
		if p.Endpoint != "vpn.example.com" {
			t.Fatalf("%s persisted non-normalized endpoint %q", protocol, p.Endpoint)
		}
	}
}
