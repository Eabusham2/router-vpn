package mobilemultihop

import "testing"

func externalDraftDNSFixture(t *testing.T, protocol string) (map[string]any, map[string]any) {
	t.Helper()
	base := protocol
	if base == "amneziawg" || base == "openvpn" {
		base = "wireguard"
	}
	graph, capture := externalTestFixture(t, base, "")
	if protocol == "amneziawg" {
		externalAmneziaReplace(t, graph, capture, false, "strong")
	}
	if protocol == "openvpn" {
		externalOpenVPNReplace(t, graph, capture, false, "tcp")
	}
	return graph, capture
}

func TestExternalDNSHomeDraftNeverInventsRunnablePolicy(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		for _, mode := range []string{"missing", "", "home"} {
			for _, transport := range []string{"", "udp", "tcp", "dot", "doh", "doh3"} {
				t.Run(protocol+"/"+mode+"/"+transport, func(t *testing.T) {
					graph, capture := externalDraftDNSFixture(t, protocol)
					profile := capture["profile"].(map[string]any)
					if mode == "missing" {
						delete(profile, "dns_mode")
					} else {
						profile["dns_mode"] = mode
					}
					profile["dns_protocol"], profile["dns_port"] = transport, 5453
					profile["dns_server_name"], profile["dns_path"] = "adguard.home.example", "/selected-query"
					for _, host := range []string{"", "10.77.0.53", "fd77::53"} {
						profile["dns_host"] = host
						frozen := externalTestJSON(t, profile)
						if err := ValidateExternalDNS(frozen, ""); err != nil {
							t.Fatal("valid Home draft rejected", err)
						}
						if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
							t.Fatal("Home draft without an entry became a runnable native connection")
						}
						if frozen != externalTestJSON(t, profile) {
							t.Fatal("idle validation rewrote the saved DNS selection")
						}
					}
				})
			}
		}
	}
}

func TestExternalDNSDraftUsesSameExplicitResolverParserAsRuntime(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		for _, mode := range []string{"rescue", "custom", "dot", "doh", "doh3"} {
			for _, transport := range []string{"udp", "tcp", "tls", "https", "h3"} {
				t.Run(protocol+"/"+mode+"/"+transport, func(t *testing.T) {
					graph, capture := externalTestFixture(t, protocol, "")
					profile := capture["profile"].(map[string]any)
					profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = mode, transport, "9.9.9.9"
					profile["dns_port"], profile["dns_server_name"], profile["dns_path"] = 5453, "dns.quad9.net", "/selected-query"
					frozen := externalTestJSON(t, profile)
					idleErr := ValidateExternalDNS(frozen, "")
					_, runtimeErr := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
					if (idleErr == nil) != (runtimeErr == nil) {
						t.Fatal("explicit DNS idle/runtime decision diverged", idleErr, runtimeErr)
					}
					if frozen != externalTestJSON(t, profile) {
						t.Fatal("explicit saved Rescue/custom was rewritten")
					}
				})
			}
		}
	}
}

func TestExternalDNSDraftRejectsMalformedAndUnownedSettings(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"public-home":     func(p map[string]any) { p["dns_host"] = "1.1.1.1" },
		"hostname-home":   func(p map[string]any) { p["dns_host"] = "adguard.home.example" },
		"mapped-home":     func(p map[string]any) { p["dns_host"] = "::ffff:10.77.0.53" },
		"system":          func(p map[string]any) { p["dns_protocol"] = "system" },
		"untyped-mode":    func(p map[string]any) { p["dns_mode"] = true },
		"untyped-port":    func(p map[string]any) { p["dns_port"] = "53" },
		"large-port":      func(p map[string]any) { p["dns_port"] = 65536 },
		"fractional-port": func(p map[string]any) { p["dns_port"] = 53.5 },
		"missing-tls":     func(p map[string]any) { p["dns_protocol"] = "dot" },
		"invalid-tls":     func(p map[string]any) { p["dns_protocol"], p["dns_server_name"] = "dot", "localhost" },
		"invalid-http": func(p map[string]any) {
			p["dns_protocol"], p["dns_server_name"], p["dns_path"] = "doh", "adguard.home.example", "https://another.example/query"
		},
		"unused-bootstrap": func(p map[string]any) {
			p["dns_bootstrap"] = map[string]any{"server": map[string]any{}, "query": map[string]any{}}
		},
		"null-bootstrap": func(p map[string]any) { p["dns_bootstrap"] = nil },
		"untyped-device": func(p map[string]any) { p["home_lan_access"] = "false" },
		"wrong-node":     func(p map[string]any) { p["node_kind"] = "router-vpn" },
	} {
		t.Run(name, func(t *testing.T) {
			_, capture := externalTestFixture(t, "shadowsocks", "")
			profile := capture["profile"].(map[string]any)
			profile["dns_mode"] = "home"
			mutate(profile)
			if err := ValidateExternalDNS(externalTestJSON(t, profile), ""); err == nil {
				t.Fatal("malformed DNS draft saved")
			}
		})
	}
}

func TestExternalDNSDraftProvidedHomeEntryMustBeExact(t *testing.T) {
	for _, fault := range []string{"none", "id", "missing-token", "public-api", "no-adguard", "wrong-address", "disabled", "wrong-exit", "missing-mode", "external-entry"} {
		t.Run(fault, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "http-connect", "router-wg")
			profile, entry := capture["profile"].(map[string]any), capture["entry"].(map[string]any)
			profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "home", "doh3", entry["adguard_ipv6"]
			profile["dns_port"], profile["dns_server_name"], profile["dns_path"] = 5453, "adguard.home.example", "/selected-query"
			profile["multihop_enabled"], profile["multihop_entry_id"], profile["multihop_entry_mode"] = true, entry["id"], "wg"
			profile["multihop_exit_id"], profile["multihop_exit_mode"] = profile["id"], "http-connect"
			switch fault {
			case "id":
				entry["id"] = "replacement"
			case "missing-token":
				delete(entry, "api_token")
			case "public-api":
				entry["router_api"] = "http://1.1.1.1:8787"
			case "no-adguard":
				delete(entry, "adguard_ipv4")
				delete(entry, "adguard_ipv6")
			case "wrong-address":
				profile["dns_host"] = "10.77.0.55"
			case "disabled":
				profile["multihop_enabled"] = false
			case "wrong-exit":
				profile["multihop_exit_id"] = "replacement"
			case "missing-mode":
				delete(profile, "multihop_entry_mode")
			case "external-entry":
				entry["node_kind"] = "external"
			}
			err := ValidateExternalDNS(externalTestJSON(t, profile), externalTestJSON(t, entry))
			if (err == nil) != (fault == "none") {
				t.Fatal("captured Home ownership decision was incorrect", err)
			}
			if fault == "none" {
				if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err != nil {
					t.Fatal("valid exact Home choice no longer compiles", err)
				}
			}
		})
	}
}
