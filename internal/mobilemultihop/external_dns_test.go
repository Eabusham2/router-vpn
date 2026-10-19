package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func externalTestDNS(t *testing.T, graph, capture map[string]any) (map[string]any, map[string]any, *ExternalPolicy) {
	t.Helper()
	before, selected := externalTestJSON(t, graph), externalTestJSON(t, capture)
	plan, err := NewExternalPolicy(before, selected)
	if err != nil {
		t.Fatal(err)
	}
	if before != externalTestJSON(t, graph) || selected != externalTestJSON(t, capture) {
		t.Fatal("DNS compilation rewrote the immutable transport or saved policy")
	}
	return externalTestRead(t, plan.Config())["dns"].(map[string]any), externalTestRead(t, plan.Metadata()), plan
}

func TestExternalDNSPreservesEverySelectedTransportAndIdentity(t *testing.T) {
	tests := []struct {
		name, mode, protocol, host, serverName, path string
		port                                         int
		wantProtocol, wantHost, wantName, wantPath   string
		wantPort                                     int
	}{
		{"rescue ignores old custom fields", "rescue", "udp", "9.9.9.9", "old.example.com", "/old", 5353, "https", "1.1.1.1", "cloudflare-dns.com", "/dns-query", 443},
		{"custom UDP", "custom", "udp", "9.9.9.9", "", "", 5353, "udp", "9.9.9.9", "", "", 5353},
		{"custom TCP", "custom", "tcp", "149.112.112.112", "", "", 5354, "tcp", "149.112.112.112", "", "", 5354},
		{"DoT mode owns transport", "dot", "udp", "9.9.9.9", "dns.quad9.net", "/stale", 8853, "tls", "9.9.9.9", "dns.quad9.net", "", 8853},
		{"DoH mode owns transport", "doh", "tcp", "1.0.0.1", "cloudflare-dns.com", "/custom/dns", 8443, "https", "1.0.0.1", "cloudflare-dns.com", "/custom/dns", 8443},
		{"DoH3 mode owns transport", "doh3", "tcp", "9.9.9.9", "dns.quad9.net", "/custom/quic", 9443, "h3", "9.9.9.9", "dns.quad9.net", "/custom/quic", 9443},
		{"custom DoT alias", "custom", "dot", "9.9.9.9", "dns.quad9.net", "", 0, "tls", "9.9.9.9", "dns.quad9.net", "", 853},
		{"custom DoH alias", "custom", "doh", "1.1.1.1", "cloudflare-dns.com", "", 0, "https", "1.1.1.1", "cloudflare-dns.com", "/dns-query", 443},
		{"custom DoH3 alias", "custom", "doh3", "1.1.1.1", "cloudflare-dns.com", "", 0, "h3", "1.1.1.1", "cloudflare-dns.com", "/dns-query", 443},
		{"literal IPv6 DNS", "custom", "tcp", "2620:fe::fe", "", "", 0, "tcp", "2620:fe::fe", "", "", 53},
		{"explicit private custom DNS", "custom", "tcp", "10.31.0.53", "", "", 5353, "tcp", "10.31.0.53", "", "", 5353},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "shadowsocks", "socks5")
			p := capture["profile"].(map[string]any)
			p["dns_mode"], p["dns_protocol"], p["dns_host"] = test.mode, test.protocol, test.host
			p["dns_port"], p["dns_server_name"], p["dns_path"] = test.port, test.serverName, test.path
			dns, meta, _ := externalTestDNS(t, graph, capture)
			server := dns["servers"].([]any)[0].(map[string]any)
			if len(dns["servers"].([]any)) != 1 || dns["final"] != ExternalDNSTag || server["tag"] != ExternalDNSTag || server["detour"] != ExternalFinalTag ||
				server["type"] != test.wantProtocol || server["server"] != test.wantHost || server["server_port"] != float64(test.wantPort) {
				t.Fatal("selected transport, address, port or final path changed", server)
			}
			if meta["dns_protocol"] != test.wantProtocol || meta["dns_server"] != test.wantHost || meta["dns_port"] != float64(test.wantPort) || meta["dns_detour"] != ExternalFinalTag || meta["dns_proof"] != "required" {
				t.Fatal("metadata is not the exact configured DNS path", meta)
			}
			if test.wantName != "" {
				tls := server["tls"].(map[string]any)
				if len(tls) != 2 || tls["enabled"] != true || tls["server_name"] != test.wantName {
					t.Fatal("encrypted DNS certificate identity changed", tls)
				}
			} else if _, exists := server["tls"]; exists {
				t.Fatal("unselected TLS added")
			}
			if test.wantPath == "" {
				if _, exists := server["path"]; exists {
					t.Fatal("unselected HTTP path retained")
				}
			} else if server["path"] != test.wantPath {
				t.Fatal("selected HTTP path changed")
			}
		})
	}
}

func TestExternalDNSDefaultsFastestAndHomeOwnerAreExplicit(t *testing.T) {
	graph, capture := externalTestFixture(t, "http-connect", "")
	p := capture["profile"].(map[string]any)
	delete(p, "dns_mode")
	_, meta, _ := externalTestDNS(t, graph, capture)
	if meta["dns_mode"] != "rescue" || meta["dns_default_migrated"] != true {
		t.Fatal("absent external DNS did not use the explicit Rescue migration")
	}
	p["dns_mode"], p["fastest_dns_host"] = "fastest", "9.9.9.9"
	if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
		t.Fatal("Fastest UDP silently changed to TCP for an HTTP-only exit")
	}
	graph, capture = externalTestFixture(t, "socks5", "")
	p = capture["profile"].(map[string]any)
	p["dns_mode"], p["fastest_dns_host"], p["dns_host"] = "fastest", "149.112.112.112", "1.1.1.1"
	p["fastest_dns_latency_ms"] = 4.5
	_, meta, _ = externalTestDNS(t, graph, capture)
	if meta["dns_server"] != "149.112.112.112" || meta["dns_protocol"] != "udp" || meta["dns_port"] != float64(53) {
		t.Fatal("Fastest lost its captured winner")
	}
	delete(p, "fastest_dns_latency_ms")
	if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
		t.Fatal("unmeasured Fastest hostname became a successful captured selection")
	}
	p["dns_results"] = []any{map[string]any{"address": "149.112.112.112", "working": true, "latency_ms": 4.5}}
	externalTestDNS(t, graph, capture)
	for _, bad := range []map[string]any{
		{"address": "9.9.9.9", "working": true, "latency_ms": 4.5},
		{"address": "149.112.112.112", "working": false, "latency_ms": 4.5},
		{"address": "149.112.112.112", "working": true, "latency_ms": 0},
		{"address": "149.112.112.112", "working": true, "latency_ms": "4.5"},
	} {
		p["dns_results"] = []any{bad}
		if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
			t.Fatal("failed, different or unmeasured Fastest sample accepted")
		}
	}
	delete(p, "fastest_dns_host")
	if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
		t.Fatal("Fastest invented a public fallback without a captured selection")
	}

	// A TCP-only final exit may still use UDP Home DNS through the independent,
	// captured Router VPN entry. LAN-Off grants no ordinary private TUN bypass.
	graph, capture = externalTestFixture(t, "https-connect", "router-wg")
	p = capture["profile"].(map[string]any)
	p["dns_mode"], p["home_lan_access"], p["ipv6_mode"] = "home", false, "off"
	dns, meta, plan := externalTestDNS(t, graph, capture)
	server := dns["servers"].([]any)[0].(map[string]any)
	if server["server"] != "10.77.0.1" || server["detour"] != "entry-wg" || server["type"] != "udp" || meta["entry_proof"] != "required" || meta["entry_node_id"] != strings.Repeat("c", 64) || meta["entry_id"] != "saved-entry" {
		t.Fatal("Home DNS borrowed an unproved or different management owner")
	}
	for _, raw := range externalTestRead(t, plan.Config())["route"].(map[string]any)["rules"].([]any) {
		if raw.(map[string]any)["action"] == "route" {
			t.Fatal("Home DNS opened a general Router API/LAN bypass")
		}
	}
	p["dns_host"], p["dns_protocol"], p["dns_port"] = "fd77:77::1", "tcp", 5353
	_, meta, _ = externalTestDNS(t, graph, capture)
	if meta["dns_server"] != "fd77:77::1" || meta["dns_protocol"] != "tcp" || meta["dns_port"] != float64(5353) {
		t.Fatal("explicit Home resolver transport or IPv6 identity changed")
	}
}

func externalTestBootstrap() map[string]any {
	return map[string]any{
		"server": map[string]any{"type": "tcp", "tag": "external-dns-bootstrap", "server": "9.9.9.9", "server_port": 5353, "detour": ExternalFinalTag},
		"query":  map[string]any{"server": "external-dns-bootstrap", "strategy": "prefer_ipv4", "timeout": "2300ms", "disable_cache": true, "disable_optimistic_cache": true, "rewrite_ttl": 7, "client_subnet": "192.0.2.0/24"},
	}
}

func TestExternalDNSHostnameRetainsExactBootstrapQueryAndCertificate(t *testing.T) {
	graph, capture := externalTestFixture(t, "socks5", "https-connect")
	p := capture["profile"].(map[string]any)
	p["dns_mode"], p["dns_protocol"], p["dns_host"] = "custom", "https", "dns.service.example"
	p["dns_server_name"], p["dns_path"], p["dns_port"] = "certificate.service.example", "/owned/dns", 8443
	capture["dns_bootstrap"] = externalTestBootstrap()
	dns, meta, _ := externalTestDNS(t, graph, capture)
	servers := dns["servers"].([]any)
	bootstrap := externalTestRead(t, externalTestJSON(t, capture["dns_bootstrap"]))
	selected := servers[0].(map[string]any)
	if len(servers) != 2 || !reflect.DeepEqual(servers[1], bootstrap["server"]) || !reflect.DeepEqual(selected["domain_resolver"], bootstrap["query"]) ||
		selected["server"] != "dns.service.example" || selected["tls"].(map[string]any)["server_name"] != "certificate.service.example" || meta["dns_bootstrap_sha256"] != externalDigest([]byte(externalTestJSON(t, bootstrap))) {
		t.Fatal("captured bootstrap query, TLS identity or route changed")
	}
}

func TestExternalDNSRejectsAmbiguousPolicyBootstrapAndHomeIdentity(t *testing.T) {
	mutations := map[string]func(map[string]any, map[string]any){
		"unknown mode":                 func(p, b map[string]any) { p["dns_mode"] = "system" },
		"custom no protocol":           func(p, b map[string]any) { delete(p, "dns_protocol") },
		"unknown transport":            func(p, b map[string]any) { p["dns_protocol"] = "local" },
		"wrong port type":              func(p, b map[string]any) { p["dns_port"] = "443" },
		"fractional port":              func(p, b map[string]any) { p["dns_port"] = 443.5 },
		"oversize port":                func(p, b map[string]any) { p["dns_port"] = 65536 },
		"negative port":                func(p, b map[string]any) { p["dns_port"] = -1 },
		"missing TLS identity":         func(p, b map[string]any) { delete(p, "dns_server_name") },
		"TLS URL identity":             func(p, b map[string]any) { p["dns_server_name"] = "https://dns.example.com" },
		"TLS localhost":                func(p, b map[string]any) { p["dns_server_name"] = "localhost" },
		"wrong host type":              func(p, b map[string]any) { p["dns_host"] = true },
		"hostname whitespace":          func(p, b map[string]any) { p["dns_host"] = " dns.example.com" },
		"hostname single label":        func(p, b map[string]any) { p["dns_host"] = "resolver" },
		"hostname scheme":              func(p, b map[string]any) { p["dns_host"] = "https://dns.example.com" },
		"unowned loopback":             func(p, b map[string]any) { p["dns_host"] = "127.0.0.1" },
		"unspecified":                  func(p, b map[string]any) { p["dns_host"] = "0.0.0.0" },
		"link local":                   func(p, b map[string]any) { p["dns_host"] = "169.254.1.1" },
		"scoped IPv6":                  func(p, b map[string]any) { p["dns_host"] = "fe80::1%eth0" },
		"mapped IPv6":                  func(p, b map[string]any) { p["dns_host"] = "::ffff:9.9.9.9" },
		"HTTP absolute path":           func(p, b map[string]any) { p["dns_path"] = "https://foreign.example/dns" },
		"HTTP authority path":          func(p, b map[string]any) { p["dns_path"] = "//foreign.example/dns" },
		"HTTP path query":              func(p, b map[string]any) { p["dns_path"] = "/dns?target=foreign" },
		"HTTP path newline":            func(p, b map[string]any) { p["dns_path"] = "/dns\n" },
		"missing query owner":          func(p, b map[string]any) { delete(b, "query") },
		"wrong query owner":            func(p, b map[string]any) { b["query"].(map[string]any)["server"] = "local" },
		"unknown query option":         func(p, b map[string]any) { b["query"].(map[string]any)["fallback"] = "local" },
		"wrong cache type":             func(p, b map[string]any) { b["query"].(map[string]any)["disable_cache"] = "true" },
		"bad query strategy":           func(p, b map[string]any) { b["query"].(map[string]any)["strategy"] = "system" },
		"unbounded query timeout":      func(p, b map[string]any) { b["query"].(map[string]any)["timeout"] = "1h" },
		"fractional TTL":               func(p, b map[string]any) { b["query"].(map[string]any)["rewrite_ttl"] = 1.5 },
		"oversize TTL":                 func(p, b map[string]any) { b["query"].(map[string]any)["rewrite_ttl"] = 4294967296.0 },
		"uncanonical client subnet":    func(p, b map[string]any) { b["query"].(map[string]any)["client_subnet"] = "192.0.2.1/24" },
		"wrong bootstrap route":        func(p, b map[string]any) { b["server"].(map[string]any)["detour"] = "external-entry" },
		"wrong bootstrap tag":          func(p, b map[string]any) { b["server"].(map[string]any)["tag"] = "local" },
		"bootstrap hostname recursion": func(p, b map[string]any) { b["server"].(map[string]any)["server"] = "bootstrap.example.com" },
		"bootstrap resolver recursion": func(p, b map[string]any) { b["server"].(map[string]any)["domain_resolver"] = ExternalDNSTag },
		"UDP bootstrap on TCP path":    func(p, b map[string]any) { b["server"].(map[string]any)["type"] = "udp" },
		"unknown bootstrap field":      func(p, b map[string]any) { b["foreign"] = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "http-connect", "")
			p := capture["profile"].(map[string]any)
			p["dns_mode"], p["dns_protocol"], p["dns_host"], p["dns_server_name"], p["dns_path"] = "custom", "https", "dns.example.com", "dns.example.com", "/dns-query"
			bootstrap := externalTestBootstrap()
			capture["dns_bootstrap"] = bootstrap
			mutate(p, bootstrap)
			before, selected := externalTestJSON(t, graph), externalTestJSON(t, capture)
			if plan, err := NewExternalPolicy(before, selected); err == nil || plan != nil {
				t.Fatal("ambiguous DNS became a runnable config")
			}
			if before != externalTestJSON(t, graph) || selected != externalTestJSON(t, capture) {
				t.Fatal("failed validation changed captured source")
			}
		})
	}
	for _, entry := range []string{"", "socks5", "wireguard"} {
		graph, capture := externalTestFixture(t, "socks5", entry)
		capture["profile"].(map[string]any)["dns_mode"] = "home"
		if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
			t.Fatal("Home DNS borrowed an absent or external node owner", entry)
		}
	}
	for _, field := range []string{"node_proof_id", "router_api", "api_token", "adguard_ipv4", "adguard_ipv6", "foreign host", "public AdGuard", "wrong family"} {
		t.Run("Home "+field, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "socks5", "router-wg")
			p, entry := capture["profile"].(map[string]any), capture["entry"].(map[string]any)
			p["dns_mode"], p["dns_host"] = "home", "10.77.0.1"
			switch field {
			case "foreign host":
				p["dns_host"] = "10.78.0.1"
			case "public AdGuard":
				entry["adguard_ipv4"] = "1.1.1.1"
			case "wrong family":
				entry["adguard_ipv4"] = "fd77:77::1"
			case "adguard_ipv4", "adguard_ipv6":
				delete(entry, "adguard_ipv4")
				delete(entry, "adguard_ipv6")
			default:
				delete(entry, field)
			}
			if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
				t.Fatal("Home DNS compiled without the selected private proof owner")
			}
		})
	}
	graph, capture := externalTestFixture(t, "socks5", "")
	p := capture["profile"].(map[string]any)
	p["dns_mode"], p["dns_protocol"], p["dns_host"], p["dns_server_name"] = "custom", "https", "dns.example.com", "dns.example.com"
	if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
		t.Fatal("DNS hostname fell through to a system/default resolver")
	}
	p["dns_host"] = "1.1.1.1"
	capture["dns_bootstrap"] = externalTestBootstrap()
	if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
		t.Fatal("unused DNS bootstrap owner adopted")
	}
}

func TestExternalPolicyEnvelopeBindsExactStringsAndNeverClaimsProof(t *testing.T) {
	graph, capture := externalTestFixture(t, "socks5", "")
	source, selected := externalTestJSON(t, graph), externalTestJSON(t, capture)
	first, err := CompileExternalPolicy(source, selected)
	if err != nil {
		t.Fatal(err)
	}
	again, err := CompileExternalPolicy(source, selected)
	if err != nil || again != first {
		t.Fatal("pure compiler is not deterministic")
	}
	envelope := externalTestRead(t, first)
	if envelope["schema"] != float64(1) || len(envelope) != 4 {
		t.Fatal("unexpected host envelope")
	}
	config, meta := envelope["config_json"].(string), externalTestRead(t, envelope["metadata_json"].(string))
	if meta["source_sha256"] != envelope["source_sha256"] || meta["config_sha256"] != externalDigest([]byte(config)) {
		t.Fatal("host envelope lost exact source/config hashes")
	}
	for _, pair := range [][2]string{{source + "\n", selected}, {source, selected + "\n"}} {
		next, err := CompileExternalPolicy(pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		changed := externalTestRead(t, next)
		if changed["source_sha256"] == envelope["source_sha256"] || changed["config_json"] != config {
			t.Fatal("source digest did not bind exact captured bytes independently of canonical graph")
		}
	}
	if meta["dns_proof"] != "required" || meta["public_exit_proof"] != "required" || meta["auto_mtu"] != "unmeasured" {
		t.Fatal("pure config compiler claimed a live measurement")
	}
}
