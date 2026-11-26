package mobilemtu

import (
	"encoding/json"
	"strings"
	"testing"
)

func encoded(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestMTUPlanPreservesOriginalNestedRoute(t *testing.T) {
	graph := map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.29.94.1/30", "fd29:94::1/126"}, "auto_route": true, "strict_route": true, "mtu": 1380}},
		"outbounds": []any{},
		"endpoints": []any{
			map[string]any{"type": "wireguard", "tag": "proxy", "mtu": 1420, "detour": "entry-wg", "private_key": "captured-final-key", "peers": []any{map[string]any{"address": "192.0.2.2"}}},
			map[string]any{"type": "routervpn-amneziawg", "tag": "entry-wg", "mtu": 1500, "private_key": "captured-entry-key", "amnezia": map[string]any{"s4": "32"}},
		},
		"route": map[string]any{"final": "proxy", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}},
		"dns":   map[string]any{"final": "selected", "servers": []any{map[string]any{"type": "tls", "tag": "selected", "server": "192.0.2.53", "detour": "proxy"}}},
	}
	before := encoded(graph)
	plan, err := NewPlan(before, 1380)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Original != 1380 || plan.Ceiling != 1420 || plan.TunTag != "tun-in" {
		t.Fatal("lost original tunnel or nested packet ceiling", plan)
	}
	candidates := plan.Candidates(1500)
	if len(candidates) == 0 || len(candidates) > 5 {
		t.Fatal("unbounded or empty candidate plan")
	}
	changed := false
	for _, mtu := range candidates {
		changed = changed || mtu != plan.Original
		output, err := plan.Config(mtu)
		if err != nil || mtu > plan.Ceiling {
			t.Fatal("unsafe candidate", mtu, err)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(output), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(mtu) {
			t.Fatal("MTU was not applied to the owned TUN")
		}
		for _, key := range []string{"endpoints", "outbounds", "route", "dns"} {
			if encoded(parsed[key]) != encoded(graph[key]) {
				t.Fatal("MTU changed captured route or credentials", key)
			}
		}
	}
	if !changed {
		t.Fatal("no changed MTU candidate was exercised")
	}
	if restored, err := plan.Config(1380); err != nil || restored != before {
		t.Fatal("rollback did not retain exact original bytes")
	}
	if _, err := plan.Config(1421); err == nil {
		t.Fatal("candidate escaped captured packet ceiling")
	}
	profile, err := ReadProfile(encoded(map[string]any{
		"id": "home", "node_kind": "router-vpn", "node_proof_id": strings.Repeat("a", 64),
		"router_api": "http://10.77.0.1:8787", "api_token": "fixture-private-token",
		"daita_host": "10.77.0.1", "daita_port": 45999, "socks_host": "10.77.0.1", "mtu_policy": "auto",
	}))
	if err != nil {
		t.Fatal(err)
	}
	key := plan.PathKey(profile, "Wi-Fi A")
	if key == plan.PathKey(profile, "Wi-Fi B") || strings.Contains(key, profile.Token) {
		t.Fatal("cache identity lost the original path or exposed credentials")
	}
	graph["endpoints"].([]any)[1].(map[string]any)["mtu"] = 1280
	if _, err := NewPlan(encoded(graph), 1380); err == nil {
		t.Fatal("smaller predecessor ceiling was ignored")
	}
}
