package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func nodeProfileFixture(t *testing.T, mode, layer string) (string, map[string]any, string) {
	t.Helper()
	raw, node := wireGuardFixture()
	files := ""
	endpoint := "192.0.2.44"
	switch {
	case MAXMode(mode):
		assets, meta := maxFixture(t, mode)
		node = startObject(t, meta)["node_id"].(string)
		files = pqEncoded(assets)
	case IsPQMode(mode):
		assets, id := pqFixture(mode)
		node, files, endpoint = id, pqEncoded(assets), "192.0.2.1"
	case CompositeMode(mode):
		files = pqEncoded(compositeHopAssets(t, mode))
	case XrayEntryMode(mode):
		files, _ = xrayEntryFixture(t, mode)
	case mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong":
		asset := "wg.conf"
		if mode != "wg" {
			raw, node = amneziaFixture()
			asset = "awg.conf"
		}
		files, endpoint = pqEncoded(map[string]string{asset: base64.StdEncoding.EncodeToString([]byte(raw))}), "192.0.2.1"
	default:
		graph := proxyEntryGraph(mode)
		cert := ""
		if mode == "hysteria2" {
			cert = entryCertificate(t)
		}
		if mode == "shadowsocks" {
			out := graph["outbounds"].([]any)[0].(map[string]any)
			out["method"], out["password"] = NativeStartLayerMethod, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
		}
		files = proxyEntryProfile(t, graph, cert)
	}
	profile := map[string]any{"id": "captured-router", "node_kind": "router-vpn", "node_proof_id": node, "router_api": "http://10.77.0.1:8787", "api_token": "captured-secret-token", "endpoint": endpoint, "start_layer": layer, "dns_mode": "home", "adguard_ipv4": "192.168.50.133", "mtu_policy": "auto", "effective_mtu": float64(9000), "ipv6_mode": "on", "home_lan_access": true}
	start := ""
	if layer != "" && !MAXMode(mode) && mode != "shadowsocks" {
		graph := proxyEntryGraph("shadowsocks")
		outer := graph["outbounds"].([]any)[0].(map[string]any)
		outer["method"], outer["password"] = NativeStartLayerMethod, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
		start = proxyEntryProfile(t, graph, "")
	}
	return files, profile, start
}

func TestNodeProfileEveryRawFamilyAndStartLayer(t *testing.T) {
	count := 0
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				files, profile, start := nodeProfileFixture(t, mode, layer)
				capture := startJSON(t, profile)
				compiled, err := NewNodeProfile(mode, files, capture, start, "")
				if err != nil {
					t.Fatal(err)
				}
				count++
				graph, meta := startObject(t, compiled.Config()), startObject(t, compiled.Metadata())
				tun := graph["inbounds"].([]any)[0].(map[string]any)
				if len(graph["inbounds"].([]any)) != 1 || tun["mtu"] != float64(1280) || graph["route"].(map[string]any)["final"] != "proxy" {
					t.Fatal("one TUN, conservative initial MTU or final owner changed")
				}
				dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["server"] != "192.168.50.133" || dns["type"] != "udp" || dns["detour"] != "proxy" {
					t.Fatal("captured Home AdGuard was replaced or bypassed")
				}
				if meta["node_id"] != profile["node_proof_id"] || meta["mode"] != mode || meta["measurement"] != "pending-live-proof" || meta["config_sha256"] != externalDigest([]byte(compiled.Config())) {
					t.Fatal("configuration mislabeled as a different node/mode or a live proof")
				}
				if capture != startJSON(t, profile) {
					t.Fatal("compiler changed caller preferences")
				}
				again, err := NewNodeProfile(mode, files, capture, start, "")
				if err != nil || again.Config() != compiled.Config() || again.SourceSHA256() != compiled.SourceSHA256() {
					t.Fatal("repeated captured source produced different graph")
				}
				if dir := os.Getenv("ROUTERVPN_NODE_PROFILE_GRAPHS"); dir != "" {
					if err := os.WriteFile(filepath.Join(dir, mode+"-"+layer+".json"), []byte(compiled.Config()), 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
	if count != 57 {
		t.Fatal("missing native modes", count)
	}
}

func TestNodeProfileDevicePoliciesKeepTransportOwners(t *testing.T) {
	for _, mode := range predecessorFamilies {
		t.Run(mode, func(t *testing.T) {
			files, profile, start := nodeProfileFixture(t, mode, "")
			initial, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
			if err != nil {
				t.Fatal(err)
			}
			profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1392)
			profile["ipv6_mode"], profile["home_lan_access"] = "off", false
			profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", "tcp", "9.9.9.9", float64(5353)
			changed, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
			if err != nil {
				t.Fatal(err)
			}
			g, before := startObject(t, changed.Config()), startObject(t, initial.Config())
			if g["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1392) {
				t.Fatal("fixed MTU was not applied")
			}
			for _, family := range []string{"outbounds", "endpoints"} {
				rows, _ := g[family].([]any)
				old, _ := before[family].([]any)
				if len(rows) != len(old) {
					t.Fatal("transport owner count changed")
				}
				for i, raw := range rows {
					next := predecessorCopy(raw.(map[string]any))
					prior := predecessorCopy(old[i].(map[string]any))
					delete(next, "mtu")
					delete(prior, "mtu")
					delete(next, "domain_resolver")
					delete(prior, "domain_resolver")
					if !reflect.DeepEqual(next, prior) {
						t.Fatal("device policy altered captured native transport", family)
					}
				}
			}
			dns := g["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if dns["type"] != "tcp" || dns["server_port"] != float64(5353) || dns["detour"] != "proxy" {
				t.Fatal("selected DNS transport or port changed")
			}
			rules := g["route"].(map[string]any)["rules"].([]any)
			if len(rules) != 4 || rules[0].(map[string]any)["ip_version"] != float64(6) || rules[3].(map[string]any)["action"] != "reject" {
				t.Fatal("LAN/IPv6 reject policy lost")
			}
		})
	}
}

func TestNodeProfileRejectsIncompleteOrMisownedSources(t *testing.T) {
	files, profile, start := nodeProfileFixture(t, "wg", "")
	for name, mutate := range map[string]func(map[string]any){
		"wrong node":          func(p map[string]any) { p["node_proof_id"] = strings.Repeat("f", 64) },
		"unknown start":       func(p map[string]any) { p["start_layer"] = "xor" },
		"missing AES":         func(p map[string]any) { p["start_layer"] = "aes-256-gcm" },
		"bad fixed":           func(p map[string]any) { p["mtu_policy"] = "fixed"; p["manual_mtu"] = 1279 },
		"missing DNS":         func(p map[string]any) { delete(p, "adguard_ipv4") },
		"unmeasured fastest":  func(p map[string]any) { p["dns_mode"] = "fastest"; p["fastest_dns_host"] = "1.1.1.1" },
		"foreign DNS":         func(p map[string]any) { p["dns_host"] = "8.8.8.8" },
		"bad IPv6":            func(p map[string]any) { p["ipv6_mode"] = false },
		"bad LAN":             func(p map[string]any) { p["home_lan_access"] = "false" },
		"public service":      func(p map[string]any) { p["router_api"] = "http://1.1.1.1:8787" },
		"missing proof token": func(p map[string]any) { delete(p, "api_token") },
		"Jumbo raw":           func(p map[string]any) { p["jumbo_tun"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			p := predecessorCopy(profile)
			mutate(p)
			if _, err := NewNodeProfile("wg", files, startJSON(t, p), start, ""); err == nil {
				t.Fatal("accepted incomplete captured source")
			}
		})
	}
	for _, mode := range []string{"all", "auto", "smart-auto", "custom", "unknown", "WG"} {
		if _, err := NewNodeProfile(mode, files, startJSON(t, profile), start, ""); err == nil {
			t.Fatal("orchestrator label became an unproved raw transport", mode)
		}
	}
	if _, err := NewNodeProfile("wg", files, startJSON(t, profile), files, ""); err == nil {
		t.Fatal("unused Start Layer accepted")
	}
	var extra map[string]string
	_ = json.Unmarshal([]byte(files), &extra)
	extra["helper.sh"] = base64.StdEncoding.EncodeToString([]byte("false"))
	if _, err := NewNodeProfile("wg", pqEncoded(extra), startJSON(t, profile), "", ""); err == nil {
		t.Fatal("extra private helper silently discarded")
	}
}

func TestNodeProfileLegacyXHTTPRetainsRealNativeProtocol(t *testing.T) {
	for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		files, profile, start := nodeProfileFixture(t, "reality-xhttp", layer)
		var assets map[string]string
		_ = json.Unmarshal([]byte(files), &assets)
		delete(assets, "sing-box.json")
		compiled, err := NewNodeProfile("reality-xhttp", pqEncoded(assets), startJSON(t, profile), start, "")
		if err != nil {
			t.Fatal(err)
		}
		g := startObject(t, compiled.Config())
		out := g["outbounds"].([]any)[0].(map[string]any)
		if out["type"] != "routervpn-xray" || out["mode"] != "reality-xhttp" || len(g["inbounds"].([]any)) != 1 {
			t.Fatal("legacy raw XHTTP was substituted or gained a helper listener")
		}
	}
}

func TestNodeProfileSelectedDNSBootstrapAndPerformance(t *testing.T) {
	for _, mode := range predecessorFamilies {
		files, profile, start := nodeProfileFixture(t, mode, "")
		profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_server_name"], profile["dns_path"] = "custom", "https", "resolver.example", "resolver.example", "/selected-dns"
		profile["dns_port"] = float64(4443)
		profile["daita_enabled"], profile["daita_rate_kbps"], profile["daita_host"] = true, float64(64), "10.77.0.1"
		bootstrap := map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "9.9.9.9", "server_port": 53, "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only"}}
		compiled, err := NewNodeProfile(mode, files, startJSON(t, profile), start, startJSON(t, bootstrap))
		if err != nil {
			t.Fatal(mode, err)
		}
		g := startObject(t, compiled.Config())
		dns := g["dns"].(map[string]any)["servers"].([]any)
		selected := dns[0].(map[string]any)
		if selected["server"] != "resolver.example" || selected["server_port"] != float64(4443) || selected["path"] != "/selected-dns" || selected["detour"] != "proxy" || dns[1].(map[string]any)["detour"] != "proxy" {
			t.Fatal("selected DoH/bootstrap escaped or changed")
		}
		services := g["services"].([]any)
		if len(services) != 1 || services[0].(map[string]any)["node_id"] != profile["node_proof_id"] || services[0].(map[string]any)["rate_kbps"] != float64(64) {
			t.Fatal("bounded padding owner lost")
		}
		if _, err := NewNodeProfile(mode, files, startJSON(t, profile), start, ""); err == nil {
			t.Fatal("hostname used implicit bootstrap", mode)
		}
		bootstrap["server"].(map[string]any)["detour"] = "direct"
		if _, err := NewNodeProfile(mode, files, startJSON(t, profile), start, startJSON(t, bootstrap)); err == nil {
			t.Fatal("plaintext bootstrap bypass accepted", mode)
		}
	}
	files, profile, start := nodeProfileFixture(t, "hysteria2", "")
	profile["jumbo_tun"] = true
	compiled, err := NewNodeProfile("hysteria2", files, startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal(err)
	}
	if startObject(t, compiled.Config())["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(9000) {
		t.Fatal("compatible proxy Jumbo was discarded")
	}
}
