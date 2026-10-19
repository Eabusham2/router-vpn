package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var externalTestProtocols = []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"}

func externalTestJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func externalTestRead(t *testing.T, text string) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func externalTestTransport(protocol, tag, detour string, entry bool) (map[string]any, map[string]any) {
	host, port, mtu := "203.0.113.20", 443, 1380
	seed := "e"
	if entry {
		host, port, mtu, seed = "198.51.100.20", 8443, 1420, "i"
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(seed, 32)))
	out := map[string]any{"tag": tag, "server": host, "server_port": port}
	if detour != "" {
		out["detour"] = detour
	}
	ext := map[string]any{"protocol": protocol, "expected_public_ip": "203.0.113.88"}
	switch protocol {
	case "wireguard":
		delete(out, "server")
		delete(out, "server_port")
		out["type"], out["private_key"], out["mtu"] = "wireguard", key, mtu
		out["address"] = []string{"10.93.0.2/32", "fd93::2/128"}
		peer := map[string]any{"address": host, "port": port, "public_key": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))), "pre_shared_key": key, "allowed_ips": []string{"0.0.0.0/0", "::/0"}}
		out["peers"] = []any{peer}
		ext["wireguard"] = map[string]any{"private_key": key, "addresses": out["address"], "peer_public_key": peer["public_key"], "preshared_key": key, "endpoint": fmt.Sprintf("%s:%d", host, port), "allowed_ips": peer["allowed_ips"], "mtu": mtu}
	case "socks5":
		out["type"], out["version"], out["username"], out["password"] = "socks", "5", "selected-user-"+seed, "selected-password-"+seed
		ext["socks5"] = map[string]any{"host": host, "port": port, "username": out["username"], "password": out["password"]}
	case "http-connect", "https-connect":
		out["type"], out["username"], out["password"] = "http", "selected-user-"+seed, "selected-password-"+seed
		source := map[string]any{"host": host, "port": port, "username": out["username"], "password": out["password"]}
		if protocol == "https-connect" {
			out["tls"] = map[string]any{"enabled": true, "server_name": "proxy.example.com"}
			source["tls_server_name"] = "proxy.example.com"
		}
		ext[strings.ReplaceAll(protocol, "-", "_")] = source
	case "shadowsocks":
		out["type"], out["method"], out["password"] = "shadowsocks", "2022-blake3-aes-256-gcm", key
		ext["shadowsocks"] = map[string]any{"server": host, "port": port, "method": out["method"], "password": key}
	case "hysteria2":
		out["type"], out["password"], out["tls"] = "hysteria2", "selected-secret-"+seed, map[string]any{"enabled": true, "server_name": "hy2.example.com"}
		ext["hysteria2"] = map[string]any{"server": host, "port": port, "password": out["password"], "tls_server_name": "hy2.example.com"}
	}
	return out, ext
}

func externalTestFixture(t *testing.T, protocol, entryProtocol string) (map[string]any, map[string]any) {
	t.Helper()
	entryTag := ""
	if entryProtocol != "" {
		entryTag = "external-entry"
	}
	if entryProtocol == "router-wg" {
		entryTag = "entry-wg"
	}
	out, ext := externalTestTransport(protocol, ExternalFinalTag, entryTag, false)
	profile := map[string]any{"id": "saved-exit", "node_kind": "external", "external": ext,
		"dns_mode": "rescue", "home_lan_access": true, "ipv6_mode": "on", "mtu_policy": "auto", "effective_mtu": 8800}
	capture := map[string]any{"schema": 1, "exit_id": "saved-exit", "protocol": protocol, "expected_public_ip": "203.0.113.88", "profile": profile}
	endpoints, outbounds := []any{}, []any{}
	if protocol == "wireguard" {
		endpoints = append(endpoints, out)
	} else {
		outbounds = append(outbounds, out)
	}
	if entryProtocol != "" {
		kind := "external"
		if entryProtocol == "router-wg" {
			entryProtocol, kind = "wireguard", "router-vpn"
		}
		entry, entryExt := externalTestTransport(entryProtocol, entryTag, "", true)
		if kind == "router-vpn" {
			entry["system"], entry["listen_port"] = false, 51888
			entry["peers"].([]any)[0].(map[string]any)["persistent_keepalive_interval"] = 25
		}
		if entryProtocol == "wireguard" {
			endpoints = append([]any{entry}, endpoints...)
		} else {
			outbounds = append([]any{entry}, outbounds...)
		}
		entryProfile := map[string]any{"id": "saved-entry", "node_kind": kind, "home_lan_access": true, "ipv6_mode": "on", "mtu_policy": "auto"}
		if kind == "external" {
			entryProfile["external"] = entryExt
		} else {
			entryProfile["node_proof_id"], entryProfile["router_api"], entryProfile["api_token"] = strings.Repeat("c", 64), "http://10.77.0.1:8787", "captured-entry-token"
			entryProfile["adguard_ipv4"], entryProfile["adguard_ipv6"] = "10.77.0.1", "fd77:77::1"
		}
		capture["entry"], capture["entry_tag"] = entryProfile, entryTag
	}
	graph := map[string]any{"log": map[string]any{"level": "warn"}, "endpoints": endpoints, "outbounds": outbounds,
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "interface_name": "router-vpn", "address": []string{"172.29.91.1/30", "fd29:91::1/126"}, "mtu": 1280, "auto_route": true, "strict_route": true, "stack": "system"},
			map[string]any{"type": "mixed", "tag": "standard-exit-proof", "listen": "127.0.0.1", "listen_port": 1099}},
		"route": map[string]any{"rules": []any{}, "final": ExternalFinalTag, "auto_detect_interface": true}}
	// Decode once so mutation fixtures exercise actual JSON types exactly like
	// the string-only shipping bridge (including nested arrays and numbers).
	return externalTestRead(t, externalTestJSON(t, graph)), externalTestRead(t, externalTestJSON(t, capture))
}

func externalTestFind(t *testing.T, graph map[string]any, tag string) map[string]any {
	t.Helper()
	for _, family := range []string{"endpoints", "outbounds"} {
		for _, raw := range graph[family].([]any) {
			value := raw.(map[string]any)
			if value["tag"] == tag {
				return value
			}
		}
	}
	t.Fatal("missing fixture transport", tag)
	return nil
}

func TestExternalPolicyMatrixPreservesSelectedOwnersAndDevices(t *testing.T) {
	entries := append([]string{"", "router-wg"}, externalTestProtocols...)
	compiled, rejected := 0, 0
	for _, protocol := range externalTestProtocols {
		for _, entry := range entries {
			for _, dns := range []string{"rescue", "tcp", "udp"} {
				for _, device := range []string{"on", "off", "fixed"} {
					name := strings.Join([]string{protocol, entry, dns, device}, "-")
					t.Run(name, func(t *testing.T) {
						graph, capture := externalTestFixture(t, protocol, entry)
						profile := capture["profile"].(map[string]any)
						if dns != "rescue" {
							profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", dns, "9.9.9.9", 5353
						}
						if device == "off" {
							profile["ipv6_mode"], profile["home_lan_access"] = "off", false
						}
						if device == "fixed" {
							profile["mtu_policy"], profile["manual_mtu"] = "manual", 1360
						}
						source, selected := externalTestJSON(t, graph), externalTestJSON(t, capture)
						plan, err := NewExternalPolicy(source, selected)
						tcpEntry := entry == "http-connect" || entry == "https-connect"
						tcpExit := protocol == "http-connect" || protocol == "https-connect"
						impossible := tcpEntry && (protocol == "wireguard" || protocol == "hysteria2") || dns == "udp" && (tcpEntry || tcpExit)
						if impossible {
							if err == nil || plan != nil {
								t.Fatal("impossible UDP carrier became a runnable policy")
							}
							rejected++
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						compiled++
						got, meta := externalTestRead(t, plan.Config()), externalTestRead(t, plan.Metadata())
						if source != externalTestJSON(t, graph) || selected != externalTestJSON(t, capture) {
							t.Fatal("compiler mutated captured source")
						}
						if meta["source_sha256"] != plan.SourceSHA256() || meta["config_sha256"] != externalDigest([]byte(plan.Config())) || meta["exit_id"] != "saved-exit" || meta["policy_id"] != "saved-exit" || meta["expected_public_ip"] != "203.0.113.88" {
							t.Fatal("source or proof identity lost")
						}
						if meta["dns_proof"] != "required" || meta["public_exit_proof"] != "required" {
							t.Fatal("configuration was relabeled as a successful live proof")
						}
						route := got["route"].(map[string]any)
						if route["final"] != ExternalFinalTag {
							t.Fatal("final changed")
						}
						wantDNS := "https"
						if dns != "rescue" {
							wantDNS = dns
						}
						server := got["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
						if server["detour"] != ExternalFinalTag || server["type"] != wantDNS {
							t.Fatal("DNS changed transport or final exit")
						}
						tun := got["inbounds"].([]any)[0].(map[string]any)
						if tun["auto_route"] != true || tun["strict_route"] != true || len(tun["address"].([]any)) != 2 {
							t.Fatal("one strict dual-stack TUN was lost")
						}
						captures := tun["route_address"].([]any)
						if captures[0] != "0.0.0.0/0" || captures[1] != "::/0" {
							t.Fatal("IPv6-Off lost capture and could leak")
						}
						if device == "off" {
							rules := route["rules"].([]any)
							if first := rules[0].(map[string]any); first["ip_version"] != float64(6) || first["action"] != "reject" || !reflect.DeepEqual(first["inbound"], []any{"tun-in"}) {
								t.Fatal("IPv6 reject no longer precedes DNS/LAN rules")
							}
							if got["dns"].(map[string]any)["strategy"] != "ipv4_only" || len(captures) != 6 || meta["home_lan_access"] != false {
								t.Fatal("LAN/IPv6 restrictions lost")
							}
							for _, raw := range rules {
								rule := raw.(map[string]any)
								if rule["action"] == "route" {
									t.Fatal("unrelated Router API bypass invented")
								}
							}
						}
						if device == "fixed" {
							if tun["mtu"] != float64(1360) || meta["auto_mtu"] != "not-requested" {
								t.Fatal("fixed MTU changed or launched Auto")
							}
						} else if tun["mtu"] != float64(1280) || meta["auto_mtu"] != "unmeasured" || meta["auto_mtu_reason"] == "" {
							t.Fatal("saved effective MTU was used as current-path proof")
						}
						entryTag, _ := capture["entry_tag"].(string)
						for _, tag := range []string{ExternalFinalTag, entryTag} {
							if tag == "" {
								continue
							}
							original, actual := externalTestFind(t, graph, tag), externalTestFind(t, got, tag)
							delete(original, "mtu")
							delete(actual, "mtu")
							if !reflect.DeepEqual(original, actual) {
								t.Fatal("captured transport, credential, TLS name or detour changed", tag)
							}
						}
						if directory := os.Getenv("ROUTERVPN_EXTERNAL_POLICY_GRAPHS"); directory != "" {
							path := filepath.Join(directory, name+".json")
							if err := os.WriteFile(path, []byte(plan.Config()), 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
	if compiled != 336 || rejected != 96 {
		t.Fatalf("external coverage changed: compiled=%d rejected=%d", compiled, rejected)
	}
}

func TestExternalPolicyRejectsSourceIdentityAndGraphMutations(t *testing.T) {
	mutations := map[string]func(map[string]any, map[string]any){
		"wrong final":              func(g, _ map[string]any) { g["route"].(map[string]any)["final"] = "external-entry" },
		"wrong exit id":            func(_, c map[string]any) { c["exit_id"] = "another-exit" },
		"wrong exit proof":         func(_, c map[string]any) { c["expected_public_ip"] = "203.0.113.89" },
		"nonpublic proof":          func(_, c map[string]any) { c["expected_public_ip"] = "10.0.0.1" },
		"unknown capture field":    func(_, c map[string]any) { c["fallback"] = "direct" },
		"missing entry capture":    func(_, c map[string]any) { delete(c, "entry") },
		"wrong entry tag":          func(_, c map[string]any) { c["entry_tag"] = "another-entry" },
		"same entry exit":          func(_, c map[string]any) { c["entry"].(map[string]any)["id"] = "saved-exit" },
		"wrong secret":             func(g, _ map[string]any) { externalTestFind(t, g, ExternalFinalTag)["password"] = "another-key" },
		"wrong predecessor secret": func(g, _ map[string]any) { externalTestFind(t, g, "external-entry")["password"] = "another-key" },
		"wrong port":               func(g, _ map[string]any) { externalTestFind(t, g, ExternalFinalTag)["server_port"] = 1443 },
		"missing detour":           func(g, _ map[string]any) { delete(externalTestFind(t, g, ExternalFinalTag), "detour") },
		"exit cycle":               func(g, _ map[string]any) { externalTestFind(t, g, ExternalFinalTag)["detour"] = ExternalFinalTag },
		"entry cycle":              func(g, _ map[string]any) { externalTestFind(t, g, "external-entry")["detour"] = ExternalFinalTag },
		"extra direct": func(g, _ map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": "fallback"})
		},
		"duplicate owner": func(g, _ map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), externalTestFind(t, g, ExternalFinalTag))
		},
		"ambient hostname": func(g, _ map[string]any) { externalTestFind(t, g, ExternalFinalTag)["server"] = "proxy.example.com" },
		"second TUN":       func(g, _ map[string]any) { g["inbounds"] = append(g["inbounds"].([]any), g["inbounds"].([]any)[0]) },
		"non-strict TUN":   func(g, _ map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["strict_route"] = false },
		"IPv6 omitted": func(g, _ map[string]any) {
			g["inbounds"].([]any)[0].(map[string]any)["address"] = []string{"172.29.91.1/30"}
		},
		"app bypass": func(g, _ map[string]any) {
			g["inbounds"].([]any)[0].(map[string]any)["exclude_uid_range"] = []string{"1:9999"}
		},
		"split route": func(g, _ map[string]any) {
			g["inbounds"].([]any)[0].(map[string]any)["route_address"] = []string{"203.0.113.0/24"}
		},
		"proof exposed": func(g, _ map[string]any) { g["inbounds"].([]any)[1].(map[string]any)["listen"] = "0.0.0.0" },
		"custom bypass": func(g, _ map[string]any) {
			g["route"].(map[string]any)["rules"] = []any{map[string]any{"ip_cidr": []string{"10.0.0.0/8"}, "outbound": "external-entry"}}
		},
		"implicit domain resolver": func(g, _ map[string]any) { g["route"].(map[string]any)["default_domain_resolver"] = "local" },
		"foreign service":          func(g, _ map[string]any) { g["services"] = []any{map[string]any{"type": "resolved"}} },
		"invalid IPv6 type":        func(_, c map[string]any) { c["profile"].(map[string]any)["ipv6_mode"] = true },
		"invalid IPv6 value":       func(_, c map[string]any) { c["profile"].(map[string]any)["ipv6_mode"] = "prefer-off" },
		"invalid LAN type":         func(_, c map[string]any) { c["entry"].(map[string]any)["home_lan_access"] = "false" },
		"LAN public range": func(_, c map[string]any) {
			c["profile"].(map[string]any)["home_lan_cidrs"] = []string{"203.0.113.0/24"}
		},
		"LAN noncanonical": func(_, c map[string]any) { c["profile"].(map[string]any)["home_lan_cidrs"] = []string{"10.1.2.3/24"} },
		"LAN link-local": func(_, c map[string]any) {
			c["profile"].(map[string]any)["home_lan_cidrs"] = []string{"169.254.0.0/16"}
		},
		"LAN mapped IPv6": func(_, c map[string]any) {
			c["profile"].(map[string]any)["home_lan_cidrs"] = []string{"::ffff:10.0.0.0/104"}
		},
		"MTU wrong type":   func(_, c map[string]any) { c["profile"].(map[string]any)["mtu_policy"] = false },
		"MTU unknown mode": func(_, c map[string]any) { c["profile"].(map[string]any)["mtu_policy"] = "jumbo-auto" },
		"MTU too small": func(_, c map[string]any) {
			c["profile"].(map[string]any)["mtu_policy"], c["profile"].(map[string]any)["manual_mtu"] = "manual", 1279
		},
		"MTU conflicting one TUN": func(_, c map[string]any) {
			c["profile"].(map[string]any)["mtu_policy"], c["profile"].(map[string]any)["manual_mtu"] = "fixed", 1380
			c["entry"].(map[string]any)["mtu_policy"], c["entry"].(map[string]any)["manual_mtu"] = "fixed", 1360
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "shadowsocks", "socks5")
			mutate(graph, capture)
			before, selected := externalTestJSON(t, graph), externalTestJSON(t, capture)
			if plan, err := NewExternalPolicy(before, selected); err == nil || plan != nil {
				t.Fatal("mutated graph or policy accepted")
			}
			if before != externalTestJSON(t, graph) || selected != externalTestJSON(t, capture) {
				t.Fatal("rejection modified saved source")
			}
		})
	}
	graph, capture := externalTestFixture(t, "socks5", "")
	raw, policy := externalTestJSON(t, graph), externalTestJSON(t, capture)
	for _, bad := range []string{`{"schema":1,"schema":1}`,
		strings.Replace(policy, `"dns_mode":"rescue"`, `"dns_mode":"rescue","dns_mode":"home"`, 1), policy + " null", string([]byte{0xff}), strings.Repeat(" ", 513<<10)} {
		if _, err := NewExternalPolicy(raw, bad); err == nil {
			t.Fatal("ambiguous or oversized JSON accepted")
		}
	}
}

func TestExternalPolicyIntersectsBothNodesAndKeepsFixedMTUOwnership(t *testing.T) {
	graph, capture := externalTestFixture(t, "wireguard", "router-wg")
	profile, entry := capture["profile"].(map[string]any), capture["entry"].(map[string]any)
	profile["home_lan_access"], profile["home_lan_cidrs"] = false, []string{"192.168.20.0/24"}
	entry["home_lan_access"], entry["home_lan_cidrs"], entry["ipv6_mode"] = false, []string{"10.20.0.0/16"}, "off"
	entry["mtu_policy"], entry["manual_mtu"] = "manual", 1440
	profile["mtu_policy"], profile["manual_mtu"] = "manual", 1360
	plan, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	got, meta := externalTestRead(t, plan.Config()), externalTestRead(t, plan.Metadata())
	if !reflect.DeepEqual(meta["blocked_lan_cidrs"], []any{"10.20.0.0/16", "192.168.20.0/24"}) || meta["ipv6_mode"] != "off" {
		t.Fatal("both-node restrictions were not intersected")
	}
	if externalTestFind(t, got, "entry-wg")["mtu"] != float64(1440) || externalTestFind(t, got, ExternalFinalTag)["mtu"] != float64(1360) || got["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1360) {
		t.Fatal("entry, exit and TUN lost separate fixed MTU ownership")
	}
	profile["manual_mtu"] = 1400
	if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
		t.Fatal("fixed nested WireGuard MTU silently clamped")
	}
	graph, capture = externalTestFixture(t, "socks5", "shadowsocks")
	entry = capture["entry"].(map[string]any)
	entry["mtu_policy"], entry["manual_mtu"] = "fixed", 1380
	plan, err = NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	meta = externalTestRead(t, plan.Metadata())
	if meta["configured_mtu"] != float64(1380) || meta["auto_mtu"] != "not-requested" {
		t.Fatal("proxy entry fixed policy was overridden by exit Auto")
	}
}

func TestExternalPolicyKeepsRouterWGListenerButRejectsSystemOrForeignOwners(t *testing.T) {
	for _, bad := range []any{-1, 65536, 1.5, "51888", true} {
		graph, capture := externalTestFixture(t, "socks5", "router-wg")
		externalTestFind(t, graph, "entry-wg")["listen_port"] = bad
		if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
			t.Fatal("invalid native entry listener accepted", bad)
		}
	}
	graph, capture := externalTestFixture(t, "socks5", "router-wg")
	externalTestFind(t, graph, "entry-wg")["system"] = true
	if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
		t.Fatal("second OS WireGuard interface accepted")
	}
	for _, entry := range []string{"", "wireguard"} {
		graph, capture = externalTestFixture(t, "wireguard", entry)
		tag := ExternalFinalTag
		if entry != "" {
			tag = "external-entry"
		}
		externalTestFind(t, graph, tag)["listen_port"] = 51888
		if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
			t.Fatal("external saved protocol adopted an uncaptured native listener")
		}
	}
}
