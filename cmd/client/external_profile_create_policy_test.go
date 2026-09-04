package main

import "testing"

func TestTypedExternalBuilderAdoptsRuntimeDNSPolicyBeforePersistence(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			p, err := externalProfileFromCreateRequest(createRequestFor(protocol))
			if err != nil {
				t.Fatal(err)
			}
			if p.DNSMode != "rescue" || p.DNSProtocol != "https" || p.DNSHost != "1.1.1.1" || p.DNSPort != 443 || p.DNSServerName != "cloudflare-dns.com" || p.DNSPath != "/dns-query" {
				t.Fatalf("typed %s node did not persist its real external runtime DNS policy: %+v", protocol, p)
			}
			if p.RouterAPI != "" || p.AdGuardIPv4 != "" || p.AdGuardIPv6 != "" || p.SocksHost != "" || p.SocksUsername != "" || p.SocksPassword != "" {
				t.Fatalf("typed %s node inherited Router VPN home-only state: %+v", protocol, p)
			}
		})
	}
}
