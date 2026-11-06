package mobilemultihop

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func importedCONNECTEncryptedDNSFixture(t *testing.T, entry, carrier, protocol, address string) []string {
	t.Helper()
	var source []string
	if carrier == "plain" {
		source = importedCONNECTFixture(t, entry, NativeStartLayerMethod, "custom")
	} else {
		source = importedCONNECTServiceFixture(t, entry, carrier, "custom", protocol)
	}
	profile := externalTestRead(t, source[4])
	profile["dns_mode"], profile["dns_protocol"] = "custom", protocol
	profile["dns_host"], profile["dns_port"] = "203.0.113.53", float64(8853)
	profile["dns_server_name"], profile["dns_path"] = "resolver.example.net", "/owned-dns-query"
	if address == "hostname" {
		profile["dns_host"] = "resolver.example.net"
		profile["dns_mode"] = map[string]string{"tls": "dot", "https": "doh", "h3": "doh3"}[protocol]
		bootstrapProtocol := "udp"
		if carrier == "plain" {
			bootstrapProtocol = "tcp"
		}
		source[6] = externalTestJSON(t, map[string]any{"server": map[string]any{"type": bootstrapProtocol, "tag": "external-dns-bootstrap", "server": "203.0.113.54", "server_port": float64(5354), "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "timeout": "3s", "disable_cache": true, "disable_optimistic_cache": true, "rewrite_ttl": float64(42), "client_subnet": "192.0.2.0/24"}})
	}
	source[4] = externalTestJSON(t, profile)
	return source
}

func TestImportedEntryCONNECTSelectedEncryptedDNS(t *testing.T) {
	for _, entry := range []string{"http-connect", "https-connect"} {
		for _, carrier := range []string{"plain", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, protocol := range []string{"tls", "https", "h3"} {
				for _, address := range []string{"literal", "hostname"} {
					if carrier == "plain" && protocol == "h3" {
						continue
					}
					t.Run(entry+"/"+carrier+"/"+protocol+"/"+address, func(t *testing.T) {
						source := importedCONNECTEncryptedDNSFixture(t, entry, carrier, protocol, address)
						original := append([]string(nil), source...)
						selected, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
						if err != nil {
							t.Fatal(err)
						}
						c := importedPacketCompile(t, source)
						graph := externalTestRead(t, c.Config())
						if !reflect.DeepEqual(graph["dns"], externalTestRead(t, selected.Config())["dns"]) {
							t.Fatal("CONNECT changed selected DNS or its original bootstrap")
						}
						if !reflect.DeepEqual(source, original) {
							t.Fatal("CONNECT rewrote captured source")
						}
						capability := "uot-v2"
						if carrier == "plain" {
							capability = "tcp-only"
						}
						if c.meta.TransportCapability != capability {
							t.Fatal("DNS changed transport authority")
						}
						udpRejected := false
						for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
							rule := raw.(map[string]any)
							if rule["network"] == "udp" && rule["action"] == "reject" {
								udpRejected = true
							}
						}
						if udpRejected != (carrier == "plain") {
							t.Fatal("DNS changed non-DNS UDP admission")
						}
						if directory := os.Getenv("ROUTERVPN_CONNECT_DNS_FIXTURES"); directory != "" {
							capture := append(append([]string(nil), source...), c.SourceSHA256(), c.Config())
							name := entry + "--" + carrier + "--" + protocol + "--" + address + ".json"
							if err := os.WriteFile(filepath.Join(directory, name), []byte(externalTestJSON(t, capture)), 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
}

func TestImportedEntryCONNECTSelectedDNSRefusals(t *testing.T) {
	for _, fault := range []string{"plain-h3", "plain-udp-bootstrap", "missing-bootstrap", "foreign-bootstrap-route", "foreign-query", "hostname-bootstrap", "unused-bootstrap", "insecure-tls", "changed-home", "unknown-protocol"} {
		t.Run(fault, func(t *testing.T) {
			source := importedCONNECTEncryptedDNSFixture(t, "https-connect", "plain", "https", "hostname")
			p := externalTestRead(t, source[4])
			b := externalTestRead(t, source[6])
			server := b["server"].(map[string]any)
			switch fault {
			case "plain-h3":
				p["dns_mode"], p["dns_protocol"] = "custom", "h3"
			case "plain-udp-bootstrap":
				server["type"] = "udp"
			case "missing-bootstrap":
				source[6] = ""
			case "foreign-bootstrap-route":
				server["detour"] = "direct"
			case "foreign-query":
				b["query"].(map[string]any)["server"] = "foreign"
			case "hostname-bootstrap":
				server["server"] = "bootstrap.example.net"
			case "unused-bootstrap":
				p["dns_host"] = "203.0.113.53"
			case "insecure-tls":
				p["dns_server_name"] = ""
			case "changed-home":
				p["dns_mode"], p["dns_host"] = "home", "10.99.0.1"
			case "unknown-protocol":
				p["dns_mode"], p["dns_protocol"] = "custom", "quic"
			}
			if fault != "missing-bootstrap" {
				source[6] = externalTestJSON(t, b)
			}
			source[4] = externalTestJSON(t, p)
			if _, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil {
				t.Fatal("invalid captured DNS admitted")
			}
		})
	}
}

func TestImportedEntryCONNECTSelectedDNSProviders(t *testing.T) {
	for _, row := range []struct{ name, carrier, mode, protocol string }{
		{"plain-home-tls", "plain", "home", "tls"}, {"plain-home-https", "plain", "home", "https"}, {"plain-rescue", "plain", "rescue", "https"},
		{"uot-home-tls", "off", "home", "tls"}, {"uot-home-https", "off", "home", "https"}, {"uot-home-h3", "off", "home", "h3"}, {"uot-rescue", "off", "rescue", "https"}, {"uot-fastest", "off", "fastest", "udp"},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := importedCONNECTEncryptedDNSFixture(t, "https-connect", row.carrier, "https", "literal")
			p := externalTestRead(t, s[4])
			p["dns_mode"], p["dns_protocol"] = row.mode, row.protocol
			host, port := p["adguard_ipv4"], float64(8853)
			switch row.mode {
			case "home":
				p["dns_host"] = host
			case "rescue":
				host, port = "1.1.1.1", 443
			case "fastest":
				host, port = "203.0.113.55", 53
				p["fastest_dns_host"], p["fastest_dns_latency_ms"] = host, float64(4)
			}
			s[4] = externalTestJSON(t, p)
			c := importedPacketCompile(t, s)
			dns := externalTestRead(t, c.Config())["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if dns["server"] != host || dns["server_port"] != port || dns["type"] != row.protocol || dns["detour"] != "proxy" {
				t.Fatal("selected provider changed", dns)
			}
			if row.mode == "rescue" {
				if dns["tls"].(map[string]any)["server_name"] != "cloudflare-dns.com" || dns["path"] != "/dns-query" {
					t.Fatal("explicit Rescue preset changed")
				}
			}
			if row.mode == "fastest" {
				delete(p, "fastest_dns_latency_ms")
				s[4] = externalTestJSON(t, p)
				if _, err := NewImportedEntry(s[0], s[1], s[2], s[3], s[4], s[5], s[6]); err == nil {
					t.Fatal("uncaptured Fastest winner admitted")
				}
			}
		})
	}
}
