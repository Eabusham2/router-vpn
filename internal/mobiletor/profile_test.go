package mobiletor

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func torHostProfile() map[string]any {
	return map[string]any{"id": "saved-tor", "node_kind": "external", "external": map[string]any{"protocol": "tor-bridge", "expected_public_ip": "", "tor_bridge": map[string]any{"transport": "obfs4", "bridges": []any{obfs4Bridge}}}, "dns_mode": "custom", "dns_protocol": "tcp", "dns_host": "9.9.9.9", "dns_port": 5353, "home_lan_access": true}
}

func torHostEncode(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func torHostCompile(t *testing.T, profile map[string]any, base string) map[string]any {
	t.Helper()
	source := torHostEncode(t, profile)
	compiled, err := CompileProfile(source, "frozen-session-1", base)
	if err != nil {
		t.Fatal(err)
	}
	if source != torHostEncode(t, profile) {
		t.Fatal("compiler mutated frozen profile")
	}
	root, err := profileObject(compiled, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func torHostTagged(t *testing.T, rows any, tag string) map[string]any {
	t.Helper()
	for _, raw := range rows.([]any) {
		value := raw.(map[string]any)
		if value["tag"] == tag {
			return value
		}
	}
	t.Fatal("missing runtime tag", tag)
	return nil
}

func TestTorProfilePreservesSavedResolverAndDynamicSession(t *testing.T) {
	for _, protocol := range []string{"tcp", "dot", "doh"} {
		for _, bridge := range []bool{false, true} {
			profile := torHostProfile()
			profile["dns_protocol"] = protocol
			profile["dns_server_name"] = "resolver.example"
			profile["dns_path"] = "/private-dns?network=chosen"
			if !bridge {
				profile["external"] = map[string]any{"protocol": "tor", "expected_public_ip": ""}
			}
			root := torHostCompile(t, profile, "")
			out := torHostTagged(t, root["outbounds"], ProfileOutboundTag)
			if out["type"] != "routervpn-tor" || out["session_id"] != "frozen-session-1" || out["detour"] != nil {
				t.Fatal("Tor captured ownership changed", out)
			}
			lines := out["bridges"].([]any)
			if bridge && (len(lines) != 1 || lines[0] != obfs4Bridge) || !bridge && len(lines) != 0 {
				t.Fatal("Tor bridge selection changed")
			}
			dns := root["dns"].(map[string]any)
			selected := torHostTagged(t, dns["servers"], profileDNS)
			bootstrap := torHostTagged(t, dns["servers"], bootstrapDNS)
			if selected["server"] != "9.9.9.9" || selected["server_port"] != json.Number("5353") || selected["detour"] != ProfileOutboundTag || bootstrap["detour"] != nil {
				t.Fatal("DNS endpoint, port or path ownership was replaced")
			}
			if selected["server"] != bootstrap["server"] || selected["type"] != bootstrap["type"] {
				t.Fatal("bootstrap silently chose another resolver")
			}
			if protocol != "tcp" && selected["tls"].(map[string]any)["server_name"] != "resolver.example" {
				t.Fatal("TLS certificate identity lost")
			}
			if protocol == "doh" && selected["path"] != "/private-dns?network=chosen" {
				t.Fatal("DoH path lost")
			}
			if dns["final"] != profileDNS || root["route"].(map[string]any)["final"] != ProfileOutboundTag {
				t.Fatal("Tor lost final DNS/traffic routing")
			}
		}
	}
}

func torHostBase(t *testing.T) string {
	return torHostEncode(t, map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "owned-tun", "address": []any{"172.29.10.1/30", "fd29:10::1/126"}, "mtu": 1392, "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "198.51.100.22", "server_port": 443, "method": "aes-256-gcm", "password": "preserve-exact-entry-secret"}},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "https", "tag": "entry-underlay-dns", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": map[string]any{"enabled": true, "server_name": "cloudflare-dns.com"}}}, "final": "entry-underlay-dns"},
		"route":     map[string]any{"final": "proxy", "auto_detect_interface": true, "default_domain_resolver": map[string]any{"server": "entry-underlay-dns"}, "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"ip_version": 6, "action": "reject"}, map[string]any{"network": "tcp", "action": "route", "outbound": "proxy"}}},
	})
}

func TestTorLastHopKeepsCompletePredecessorAndSeparateBootstrap(t *testing.T) {
	base := torHostBase(t)
	root := torHostCompile(t, torHostProfile(), base)
	original, _ := profileObject(base, 4*1024*1024)
	entry := torHostTagged(t, root["outbounds"], "proxy")
	if !reflect.DeepEqual(entry, torHostTagged(t, original["outbounds"], "proxy")) {
		t.Fatal("Tor replaced predecessor credentials or engine")
	}
	if !reflect.DeepEqual(root["inbounds"], original["inbounds"]) {
		t.Fatal("Tor created or replaced the predecessor TUN")
	}
	out := torHostTagged(t, root["outbounds"], ProfileOutboundTag)
	if out["detour"] != "proxy" || out["domain_resolver"].(map[string]any)["server"] != bootstrapDNS {
		t.Fatal("Tor underlay or bootstrap owner is not frozen")
	}
	bootstrap := torHostTagged(t, root["dns"].(map[string]any)["servers"], bootstrapDNS)
	if bootstrap["detour"] != "proxy" {
		t.Fatal("Tor bootstrap escaped the captured predecessor")
	}
	route := root["route"].(map[string]any)
	if !reflect.DeepEqual(route["default_domain_resolver"], original["route"].(map[string]any)["default_domain_resolver"]) {
		t.Fatal("Tor bootstrap replaced entry hostname bootstrap")
	}
	for _, raw := range route["rules"].([]any) {
		if raw.(map[string]any)["outbound"] == "proxy" {
			t.Fatal("ordinary application rule bypasses Tor")
		}
	}
}

func torHostNaiveBase(t *testing.T, layer string, quic bool) map[string]any {
	t.Helper()
	base, _ := profileObject(torHostBase(t), 4*1024*1024)
	naive := map[string]any{"type": "naive", "tag": "proxy", "server": "198.51.100.22", "server_port": json.Number("13443"),
		"username": "captured-private-user", "password": "captured-private-password", "quic": quic,
		"tls":          map[string]any{"enabled": true, "server_name": "entry.example.test", "certificate": []any{"exact captured trust"}},
		"udp_over_tcp": map[string]any{"enabled": true, "version": json.Number("2")}}
	base["outbounds"] = []any{naive}
	if layer != "off" {
		kind := "shadowsocks"
		if layer == "aes-xor" {
			kind = "routervpn-aes-xor"
		}
		base["outbounds"] = append(base["outbounds"].([]any), map[string]any{"type": kind, "tag": "captured-start-layer",
			"server": "198.51.100.22", "server_port": json.Number("8388"), "method": "2022-blake3-aes-256-gcm",
			"password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))})
		naive["detour"], naive["server"] = "captured-start-layer", "127.0.0.1"
	}
	dns := base["dns"].(map[string]any)
	dns["strategy"] = "prefer_ipv6"
	selected := dns["servers"].([]any)[0].(map[string]any)
	selected["detour"], selected["server_port"], selected["path"] = "proxy", json.Number("8443"), "/captured-entry-dns?policy=one"
	delete(base["route"].(map[string]any), "default_domain_resolver")
	return base
}

func TestTorNaiveBootstrapCapturesEntryDNSBeforeAddingTor(t *testing.T) {
	for _, layer := range []string{"off", "aes", "aes-xor"} {
		for _, quic := range []bool{false, true} {
			for _, protocol := range []string{"tcp", "dot", "doh"} {
				base := torHostNaiveBase(t, layer, quic)
				source := torHostEncode(t, base)
				profile := torHostProfile()
				profile["dns_protocol"], profile["dns_server_name"], profile["dns_path"], profile["ipv6_mode"] = protocol, "tor-dns.example", "/tor-query", "off"
				root := torHostCompile(t, profile, source)
				if source != torHostEncode(t, base) {
					t.Fatal("captured predecessor mutated")
				}
				naive := torHostTagged(t, root["outbounds"], "proxy")
				selection := naive["domain_resolver"].(map[string]any)
				if selection["strategy"] != "prefer_ipv6" {
					t.Fatal("Tor exit IPv6 policy changed the entry resolver strategy")
				}
				dns := root["dns"].(map[string]any)
				bootstrap := torHostTagged(t, dns["servers"], profileString(selection, "server"))
				original := base["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				wanted := map[string]any{}
				for key, value := range original {
					wanted[key] = value
				}
				wanted["tag"] = selection["server"]
				delete(wanted, "detour")
				if layer != "off" {
					wanted["detour"] = "captured-start-layer"
				}
				if !reflect.DeepEqual(wanted, bootstrap) {
					t.Fatal("Naive bootstrap changed the captured resolver address, port, TLS, path or lower owner")
				}
				if !reflect.DeepEqual(original, torHostTagged(t, dns["servers"], "entry-underlay-dns")) {
					t.Fatal("entry application resolver was rewritten")
				}
				delete(naive, "domain_resolver")
				if !reflect.DeepEqual(naive, base["outbounds"].([]any)[0]) {
					t.Fatal("Naive endpoint, credentials, SNI, trust, HTTP or UDP settings changed")
				}
				if root["route"].(map[string]any)["default_domain_resolver"] != nil || dns["final"] != profileDNS {
					t.Fatal("bootstrap became a new default or displaced Tor application DNS")
				}
			}
		}
	}
}

func TestTorNaiveBootstrapPreservesExplicitResolverOptions(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		base := torHostNaiveBase(t, "aes-xor", true)
		naive := base["outbounds"].([]any)[0].(map[string]any)
		resolver := base["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
		resolver["detour"] = "captured-start-layer"
		options := map[string]any{"server": "entry-underlay-dns", "strategy": "ipv4_only", "timeout": "9s",
			"disable_cache": true, "disable_optimistic_cache": true, "rewrite_ttl": json.Number("42"), "client_subnet": "192.0.2.0/24"}
		if inherited {
			base["route"].(map[string]any)["default_domain_resolver"] = options
		} else {
			naive["domain_resolver"] = options
		}
		root := torHostCompile(t, torHostProfile(), torHostEncode(t, base))
		if !reflect.DeepEqual(torHostTagged(t, root["outbounds"], "proxy")["domain_resolver"], options) {
			t.Fatal("explicit entry DNS query options changed")
		}
		if len(root["dns"].(map[string]any)["servers"].([]any)) != 3 {
			t.Fatal("explicit resolver unnecessarily replaced")
		}
		if !reflect.DeepEqual(root["route"].(map[string]any)["default_domain_resolver"], base["route"].(map[string]any)["default_domain_resolver"]) {
			t.Fatal("another native owner's default resolver changed")
		}
	}
}

func TestTorNaiveBootstrapRejectsAmbiguityAndRecursiveOwners(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"missing-dns":      func(root map[string]any) { delete(root, "dns") },
		"missing-selected": func(root map[string]any) { root["dns"].(map[string]any)["final"] = "unowned" },
		"ambient-local": func(root map[string]any) {
			root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["type"] = "local"
		},
		"uncaptured-hostname": func(root map[string]any) {
			root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["server"] = "system-bootstrap.example"
		},
		"ambiguous": func(root map[string]any) {
			dns := root["dns"].(map[string]any)
			delete(dns, "final")
			dns["servers"] = append(dns["servers"].([]any), map[string]any{"tag": "another", "type": "tcp", "server": "9.9.9.9"})
		},
		"reserved-tag": func(root map[string]any) {
			dns := root["dns"].(map[string]any)
			dns["servers"] = append(dns["servers"].([]any), map[string]any{"tag": "routervpn-tor-naive-bootstrap-0", "type": "tcp", "server": "9.9.9.9"})
		},
		"explicit-self-resolver": func(root map[string]any) {
			root["outbounds"].([]any)[0].(map[string]any)["domain_resolver"] = "entry-underlay-dns"
		},
		"inherited-self-resolver": func(root map[string]any) {
			root["route"].(map[string]any)["default_domain_resolver"] = "entry-underlay-dns"
		},
		"unresolved-explicit": func(root map[string]any) {
			root["outbounds"].([]any)[0].(map[string]any)["domain_resolver"] = "unowned"
		},
		"bootstrap-dns-cycle": func(root map[string]any) {
			root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["domain_resolver"] = "entry-underlay-dns"
		},
		"self-underlay": func(root map[string]any) {
			root["outbounds"].([]any)[0].(map[string]any)["detour"] = "proxy"
		},
		"missing-underlay": func(root map[string]any) {
			root["outbounds"].([]any)[0].(map[string]any)["detour"] = "unowned"
		},
		"indirect-self": func(root map[string]any) {
			root["outbounds"].([]any)[1].(map[string]any)["detour"] = "proxy"
		},
		"lower-domain-without-captured-dns": func(root map[string]any) {
			root["outbounds"].([]any)[1].(map[string]any)["server"] = "uncaptured.example"
		},
		"dynamic-lower": func(root map[string]any) {
			root["outbounds"].([]any)[1].(map[string]any)["type"] = "selector"
		},
	} {
		t.Run(name, func(t *testing.T) {
			base := torHostNaiveBase(t, "aes-xor", false)
			change(base)
			value, err := CompileProfile(torHostEncode(t, torHostProfile()), "captured-session", torHostEncode(t, base))
			if err == nil || value != "" {
				t.Fatal("uncaptured or recursive Naive bootstrap was compiled")
			}
			if strings.Contains(err.Error(), "captured-private") {
				t.Fatal("bootstrap failure exposed entry credentials")
			}
		})
	}
}

func TestTorPredecessorKeepsRegisteredWGAndPQOwners(t *testing.T) {
	for _, kind := range []string{"wireguard", "routervpn-amneziawg", "routervpn-pq"} {
		base, _ := profileObject(torHostBase(t), 4*1024*1024)
		entry := base["outbounds"].([]any)[0].(map[string]any)
		entry["type"] = kind
		base["outbounds"], base["endpoints"] = []any{}, []any{entry}
		root := torHostCompile(t, torHostProfile(), torHostEncode(t, base))
		if !reflect.DeepEqual(root["endpoints"], base["endpoints"]) {
			t.Fatal("registered native endpoint owner changed", kind)
		}
	}
}

func TestTorPredecessorPreservesAuthenticatedAESWhitening(t *testing.T) {
	base, _ := profileObject(torHostBase(t), 4*1024*1024)
	entry := base["outbounds"].([]any)[0].(map[string]any)
	entry["type"], entry["method"] = "routervpn-aes-xor", "2022-blake3-aes-256-gcm"
	entry["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	entry["server_port"] = json.Number("8389")
	source := torHostEncode(t, base)
	compiled := torHostCompile(t, torHostProfile(), source)
	if !reflect.DeepEqual(torHostTagged(t, compiled["outbounds"], "proxy"), entry) {
		t.Fatal("Tor replaced its authenticated AES+XOR method, key or peer")
	}
	if torHostTagged(t, compiled["outbounds"], ProfileOutboundTag)["detour"] != "proxy" {
		t.Fatal("Tor bypassed the captured AES+XOR entry")
	}
	for name, mutate := range map[string]func(map[string]any){
		"plaintext": func(out map[string]any) { out["method"] = "none" },
		"xor-only":  func(out map[string]any) { out["method"] = "xor" },
		"wrong-key": func(out map[string]any) { out["password"] = "not-a-complete-native-key" },
		"short-key": func(out map[string]any) {
			out["password"] = base64.StdEncoding.EncodeToString([]byte("sixteen-byte-key"))
		},
		"hidden-key":     func(out map[string]any) { out["password"] = out["password"].(string) + "\n" },
		"socket-option":  func(out map[string]any) { out["bind_interface"] = "en0" },
		"missing-server": func(out map[string]any) { delete(out, "server") },
		"local-server":   func(out map[string]any) { out["server"] = "127.0.0.1" },
		"invalid-port":   func(out map[string]any) { out["server_port"] = json.Number("65536") },
		"self-detour":    func(out map[string]any) { out["detour"] = "proxy" },
	} {
		t.Run(name, func(t *testing.T) {
			changed, _ := profileObject(source, 4*1024*1024)
			mutate(changed["outbounds"].([]any)[0].(map[string]any))
			if _, err := CompileProfile(torHostEncode(t, torHostProfile()), "owned-session", torHostEncode(t, changed)); err == nil {
				t.Fatal("Tor accepted an unowned or unauthenticated whitening entry")
			}
		})
	}
}

func TestTorDevicePolicyCapturesLANIPv6AndCurrentInterfaceMTU(t *testing.T) {
	profile := torHostProfile()
	profile["home_lan_access"], profile["ipv6_mode"] = false, "off"
	profile["home_lan_cidrs"] = []any{"192.168.50.0/24", "fd12:3456::/48"}
	profile["mtu_policy"], profile["manual_mtu"] = "manual", 1452
	root := torHostCompile(t, profile, "")
	tun := root["inbounds"].([]any)[0].(map[string]any)
	if tun["mtu"] != json.Number("1452") || tun["strict_route"] != true {
		t.Fatal("fixed MTU/strict TUN lost")
	}
	captures := torHostEncode(t, tun["route_address"])
	for _, value := range []string{"0.0.0.0/0", "::/0", "192.168.50.0/24", "fd12:3456::/48"} {
		if !strings.Contains(captures, value) {
			t.Fatal("LAN-Off missed capture", value)
		}
	}
	rules := root["route"].(map[string]any)["rules"].([]any)
	if rules[0].(map[string]any)["ip_version"] != json.Number("6") || rules[0].(map[string]any)["action"] != "reject" {
		t.Fatal("IPv6-Off is not enforced before DNS")
	}
	if root["dns"].(map[string]any)["strategy"] != "ipv4_only" {
		t.Fatal("IPv6-Off DNS policy lost")
	}
	profile["mtu_policy"], profile["effective_mtu"] = "auto", 9000
	root = torHostCompile(t, profile, "")
	if root["inbounds"].([]any)[0].(map[string]any)["mtu"] != json.Number("1280") {
		t.Fatal("saved MTU history became current-path measurement")
	}
}

func TestTorProfileRejectsUnownedOrMalformedSelections(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wrong-node-kind":       func(p map[string]any) { p["node_kind"] = "router-vpn" },
		"fixed-exit-proof":      func(p map[string]any) { p["external"].(map[string]any)["expected_public_ip"] = "203.0.113.4" },
		"second-protocol":       func(p map[string]any) { p["external"].(map[string]any)["socks5"] = map[string]any{"host": "127.0.0.1"} },
		"wrong-dns-type":        func(p map[string]any) { p["dns_mode"] = false },
		"home-adguard":          func(p map[string]any) { p["dns_mode"], p["adguard_ipv4"] = "home", "192.168.50.133" },
		"udp":                   func(p map[string]any) { p["dns_protocol"] = "udp" },
		"quic":                  func(p map[string]any) { p["dns_mode"] = "doh3" },
		"system-dns":            func(p map[string]any) { p["dns_host"] = "localhost" },
		"private-dns":           func(p map[string]any) { p["dns_host"] = "192.168.50.133" },
		"invalid-port":          func(p map[string]any) { p["dns_port"] = 65536 },
		"string-port":           func(p map[string]any) { p["dns_port"] = "53" },
		"fractional-port":       func(p map[string]any) { p["dns_port"] = 53.5 },
		"wrong-lan-type":        func(p map[string]any) { p["home_lan_access"] = "false" },
		"public-lan":            func(p map[string]any) { p["home_lan_access"], p["home_lan_cidrs"] = false, []any{"128.0.0.0/1"} },
		"broad-private-start":   func(p map[string]any) { p["home_lan_access"], p["home_lan_cidrs"] = false, []any{"192.168.0.0/12"} },
		"invalid-mtu":           func(p map[string]any) { p["mtu_policy"], p["manual_mtu"] = "manual", 9001 },
		"router-credentials":    func(p map[string]any) { p["api_token"] = "secret" },
		"discarded-start-layer": func(p map[string]any) { p["start_layer"] = "aes" },
		"plain-with-bridge":     func(p map[string]any) { p["external"].(map[string]any)["protocol"] = "tor" },
		"listener-injection": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"].(map[string]any)["socks_port"] = 9999
		},
		"bridge-injection": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"].(map[string]any)["bridges"] = []any{obfs4Bridge + "\nSocksPort 0.0.0.0:9050"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile := torHostProfile()
			mutate(profile)
			if value, err := CompileProfile(torHostEncode(t, profile), "session-1", ""); err == nil || value != "" {
				t.Fatal("invalid selection compiled", value)
			}
		})
	}
	valid := torHostEncode(t, torHostProfile())
	for _, source := range []string{valid + "{}", strings.Replace(valid, `"dns_port":5353`, `"dns_port":5353,"dns_port":53`, 1), strings.Repeat(" ", 256*1024) + valid} {
		if value, err := CompileProfile(source, "session-1", ""); err == nil || value != "" {
			t.Fatal("ambiguous or oversized JSON compiled")
		}
	}
	for _, session := range []string{"", "session\nother", "../escape", strings.Repeat("s", 129)} {
		if _, err := CompileProfile(valid, session, ""); err == nil {
			t.Fatal("invalid session compiled")
		}
	}
}

func TestTorPredecessorRejectsDirectFallbackAndSecondVPN(t *testing.T) {
	cases := map[string]func(map[string]any){
		"direct":           func(p map[string]any) { p["outbounds"].([]any)[0].(map[string]any)["type"] = "direct" },
		"dynamic-selector": func(p map[string]any) { p["outbounds"].([]any)[0].(map[string]any)["type"] = "selector" },
		"two-tuns":         func(p map[string]any) { p["inbounds"] = append(p["inbounds"].([]any), p["inbounds"].([]any)[0]) },
		"unowned-proxy": func(p map[string]any) {
			p["inbounds"] = append(p["inbounds"].([]any), map[string]any{"type": "mixed", "listen": "0.0.0.0", "listen_port": 9050})
		},
		"duplicate-tag": func(p map[string]any) { p["outbounds"] = append(p["outbounds"].([]any), p["outbounds"].([]any)[0]) },
		"another-tor":   func(p map[string]any) { p["outbounds"].([]any)[0].(map[string]any)["type"] = "routervpn-tor" },
		"bypass-route": func(p map[string]any) {
			p["route"].(map[string]any)["rules"] = []any{map[string]any{"outbound": "direct"}}
		},
		"route-exclusion": func(p map[string]any) {
			p["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"] = []any{"192.168.50.0/24"}
		},
		"stolen-dns-tag": func(p map[string]any) {
			p["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["tag"] = bootstrapDNS
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			base, _ := profileObject(torHostBase(t), 4*1024*1024)
			mutate(base)
			if value, err := CompileProfile(torHostEncode(t, torHostProfile()), "session-1", torHostEncode(t, base)); err == nil || value != "" {
				t.Fatal("unsafe Tor predecessor compiled")
			}
		})
	}
}
