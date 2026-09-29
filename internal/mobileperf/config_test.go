package mobileperf

import (
	"encoding/json"
	"strings"
	"testing"
)

func perfFixture() map[string]any {
	return map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "mtu": 1380, "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.1", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": "preserve-secret"}},
		"route":     map[string]any{"final": "proxy", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}},
		"dns":       map[string]any{"final": "selected", "servers": []any{map[string]any{"type": "tls", "tag": "selected", "server": "192.0.2.53", "detour": "proxy"}}},
	}
}
func node() map[string]any {
	return map[string]any{"id": "exit", "node_kind": "router-vpn", "node_proof_id": strings.Repeat("a", 64), "router_api": "http://10.77.0.1:8787", "socks_host": "10.77.0.1", "daita_host": "10.77.0.1", "daita_port": 45999, "daita_rate_kbps": 192}
}
func jsonText(v any) string { b, _ := json.Marshal(v); return string(b) }
func compilePerf(root map[string]any, entry, exit map[string]any) (map[string]any, error) {
	s, err := Apply(jsonText(root), jsonText(map[string]any{"entry": entry, "exit": exit}))
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = json.Unmarshal([]byte(s), &result)
	return result, err
}
func TestDisabledPerformanceIsByteIdentical(t *testing.T) {
	raw := jsonText(perfFixture())
	out, err := Apply(raw, jsonText(map[string]any{"entry": node(), "exit": node()}))
	if err != nil || out != raw {
		t.Fatal("disabled changes source", err)
	}
}
func TestCoverAndJumboRetainActualDataplane(t *testing.T) {
	original := perfFixture()
	profile := node()
	profile["daita_enabled"] = true
	profile["jumbo_tun"] = true
	out, err := compilePerf(original, profile, profile)
	if err != nil {
		t.Fatal(err)
	}
	if out["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(9000) {
		t.Fatal("Jumbo not applied")
	}
	for _, key := range []string{"route", "dns", "outbounds"} {
		if jsonText(out[key]) != jsonText(original[key]) {
			t.Fatal("performance replaced", key)
		}
	}
	services := out["services"].([]any)
	if len(services) != 1 {
		t.Fatal("multiple cover workers")
	}
	service := services[0].(map[string]any)
	if service["type"] != CoverType || service["packet_tag"] != "proxy" || service["proof_tag"] != "proxy" || service["sink"] != "10.77.0.1" {
		t.Fatal("unowned padding path")
	}
	again, err := compilePerf(out, profile, profile)
	if err != nil || jsonText(out) != jsonText(again) {
		t.Fatal("performance not idempotent", err)
	}
}
func TestCoverPerHopAndSplitTransportOwnership(t *testing.T) {
	root := perfFixture()
	root["endpoints"] = []any{map[string]any{"type": "routervpn-amneziawg", "tag": "entry-wg"}}
	root["outbounds"].([]any)[0].(map[string]any)["detour"] = "entry-wg"
	entry, exit := node(), node()
	entry["id"] = "entry"
	entry["node_proof_id"] = strings.Repeat("b", 64)
	entry["daita_enabled"] = true
	exit["daita_enabled"] = true
	out, err := compilePerf(root, entry, exit)
	if err != nil {
		t.Fatal(err)
	}
	services := out["services"].([]any)
	if len(services) != 2 || services[1].(map[string]any)["packet_tag"] != "entry-wg" {
		t.Fatal("entry cover sent through wrong hop")
	}
	root = perfFixture()
	root["outbounds"] = []any{map[string]any{"type": "routervpn-xray", "tag": "tcp-stack"}, map[string]any{"type": "hysteria2", "tag": "udp-stack"}}
	root["route"] = map[string]any{"final": "tcp-stack", "rules": []any{map[string]any{"action": "route", "network": "udp", "outbound": "udp-stack"}}}
	out, err = compilePerf(root, exit, exit)
	if err != nil {
		t.Fatal(err)
	}
	service := out["services"].([]any)[0].(map[string]any)
	if service["proof_tag"] != "tcp-stack" || service["packet_tag"] != "udp-stack" {
		t.Fatal("split cover lost TCP/UDP ownership")
	}
}
func TestPerformanceCannotIgnorePolicyOrCreateRawJumbo(t *testing.T) {
	for _, name := range []string{"bad-bool", "public-sink", "high-rate", "wrong-port", "missing-proof", "external-node", "plaintext", "foreign-service", "fixed-conflict", "raw-jumbo", "entry-jumbo"} {
		t.Run(name, func(t *testing.T) {
			root := perfFixture()
			profile := node()
			profile["daita_enabled"] = true
			entry := profile
			switch name {
			case "bad-bool":
				profile["daita_enabled"] = "true"
			case "public-sink":
				profile["daita_host"] = "1.1.1.1"
			case "high-rate":
				profile["daita_rate_kbps"] = 10000
			case "wrong-port":
				profile["daita_port"] = 22
			case "missing-proof":
				delete(profile, "node_proof_id")
			case "external-node":
				profile["node_kind"] = "external"
			case "plaintext":
				root["outbounds"].([]any)[0].(map[string]any)["type"] = "direct"
			case "foreign-service":
				root["services"] = []any{map[string]any{"type": "unowned", "tag": "routervpn-cover-exit"}}
			case "fixed-conflict":
				profile["jumbo_tun"] = true
				profile["mtu_policy"] = "manual"
				profile["manual_mtu"] = 1400
			case "raw-jumbo":
				profile["jumbo_tun"] = true
				root["outbounds"] = []any{}
				root["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": "proxy"}}
			case "entry-jumbo":
				root["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": "entry-wg"}}
				entry = node()
				entry["jumbo_tun"] = true
			}
			if _, err := compilePerf(root, entry, profile); err == nil {
				t.Fatal("invalid performance configuration accepted")
			}
		})
	}
	if _, err := Apply(jsonText(perfFixture()), `{"entry":{},"entry":{},"exit":{}}`); err == nil {
		t.Fatal("duplicate profile accepted")
	}
}

func TestImportedPaddingCannotOverrideDisabledPreferences(t *testing.T) {
	profile := node()
	profile["daita_enabled"] = true
	compiled, err := compilePerf(perfFixture(), profile, profile)
	if err != nil {
		t.Fatal(err)
	}
	profile["daita_enabled"] = false
	if _, err = compilePerf(compiled, profile, profile); err == nil {
		t.Fatal("disabled preference activated an imported cover worker")
	}
	profile["jumbo_tun"] = true
	if _, err = compilePerf(compiled, profile, profile); err == nil {
		t.Fatal("Jumbo reactivated old cover settings")
	}
}
