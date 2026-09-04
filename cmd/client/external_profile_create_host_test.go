package main

import (
	"strings"
	"testing"
)

func TestTypedExternalProfileBuilderRejectsUnsafeServerTextBeforePersistence(t *testing.T) {
	protocols := []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"}
	badServers := []string{
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
		for _, server := range []string{"Vpn.Example.COM", "https://Vpn.Example.COM/supplied/path?ignored=1"} {
			q := createRequestFor(protocol)
			q.Server = server
			p, err := externalProfileFromCreateRequest(q)
			if err != nil {
				t.Fatalf("%s hostname %q rejected: %v", protocol, server, err)
			}
			if p.Endpoint != "vpn.example.com" {
				t.Fatalf("%s persisted non-normalized endpoint %q from %q", protocol, p.Endpoint, server)
			}
		}
	}
}
