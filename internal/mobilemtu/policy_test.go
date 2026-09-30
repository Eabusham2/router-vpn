package mobilemtu

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixtureProfile() map[string]any {
	return map[string]any{"id": "home", "node_kind": "router-vpn", "node_proof_id": strings.Repeat("a", 64), "router_api": "http://10.77.0.1:8787", "api_token": "private-fixture-token", "daita_host": "10.77.0.1", "daita_port": 45999, "socks_host": "10.77.0.1", "mtu_policy": "auto"}
}
func fixtureGraph() map[string]any {
	return map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.29.94.1/30", "fd29:94::1/126"}, "auto_route": true, "strict_route": true, "mtu": 1380}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.1", "server_port": 8388, "password": "fixture-preserved-private-key", "method": "2022-blake3-aes-256-gcm"}},
		"route":     map[string]any{"final": "proxy", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}},
		"dns":       map[string]any{"final": "selected", "servers": []any{map[string]any{"type": "tls", "tag": "selected", "server": "192.0.2.53", "detour": "proxy"}}},
	}
}
func encoded(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}
func TestMTUPlanChangesOnlyTheOwnedTUN(t *testing.T) {
	graph := fixtureGraph()
	before := encoded(graph)
	plan, err := NewPlan(before, 1380)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Original != 1380 || plan.Ceiling != 1500 || plan.TunTag != "tun-in" {
		t.Fatal(plan)
	}
	if got, err := plan.Config(1380); err != nil || got != before {
		t.Fatal("rollback does not retain exact original bytes")
	}
	for _, mtu := range plan.Candidates(1400) {
		output, err := plan.Config(mtu)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]any
		json.Unmarshal([]byte(output), &parsed)
		if parsed["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(mtu) {
			t.Fatal("MTU not applied")
		}
		for _, key := range []string{"outbounds", "route", "dns"} {
			if encoded(parsed[key]) != encoded(graph[key]) {
				t.Fatal("MTU rewrote", key)
			}
		}
	}
	if len(plan.Candidates(1400)) > 5 {
		t.Fatal("candidate budget exceeded")
	}
	for _, bad := range []int{0, 1279, 1501, 9000} {
		if _, err = plan.Config(bad); err == nil {
			t.Fatal("unsafe candidate", bad)
		}
	}
	profile, _ := ReadProfile(encoded(fixtureProfile()))
	key := plan.PathKey(profile, "Wi-Fi interface A")
	if key == plan.PathKey(profile, "Wi-Fi interface B") || strings.Contains(key, profile.Token) {
		t.Fatal("cache is not path-keyed/private")
	}
}
func TestMTUPacketEnvelopeAndNestedGraph(t *testing.T) {
	graph := fixtureGraph()
	graph["outbounds"] = []any{}
	graph["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": "proxy", "mtu": 1420, "private_key": "preserved", "peers": []any{map[string]any{"address": "192.0.2.2"}}}}
	plan, err := NewPlan(encoded(graph), 1380)
	if err != nil || plan.Ceiling != 1420 {
		t.Fatal(plan, err)
	}
	endpoints := graph["endpoints"].([]any)
	endpoints[0].(map[string]any)["detour"] = "entry-wg"
	endpoints = append(endpoints, map[string]any{"type": "routervpn-amneziawg", "tag": "entry-wg", "mtu": 1500, "amnezia": map[string]any{"s4": "32"}})
	graph["endpoints"] = endpoints
	plan, err = NewPlan(encoded(graph), 1380)
	if err != nil || plan.Ceiling != 1420 {
		t.Fatal(plan, err)
	}
	// An AWG exit adds its transport padding to the encapsulation budget.
	endpoints[0].(map[string]any)["type"] = "routervpn-amneziawg"
	endpoints[0].(map[string]any)["amnezia"] = map[string]any{"s4": "32"}
	plan, err = NewPlan(encoded(graph), 1380)
	if err != nil || plan.Ceiling != 1408 {
		t.Fatal(plan, err)
	}
	changed, _ := plan.Config(1280)
	var after map[string]any
	json.Unmarshal([]byte(changed), &after)
	if encoded(after["endpoints"]) != encoded(endpoints) {
		t.Fatal("TUN optimizer changed entry/exit key or MTU ownership")
	}
	endpoints[1].(map[string]any)["mtu"] = 1280
	if _, err = NewPlan(encoded(graph), 1380); err == nil {
		t.Fatal("nested packet ceiling silently ignored")
	}
}
func TestMTURejectsBadAuthoritiesAndGraphAmbiguity(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["node_kind"] = "external" }, func(p map[string]any) { p["node_proof_id"] = "" }, func(p map[string]any) { p["api_token"] = "x\ny" },
		func(p map[string]any) { p["router_api"] = "http://10.77.0.1:70000" }, func(p map[string]any) { p["router_api"] = "http://example.test:8787" }, func(p map[string]any) { p["router_api"] = "http://user:key@10.77.0.1:8787" },
		func(p map[string]any) { p["daita_host"] = "192.0.2.1" }, func(p map[string]any) { p["daita_host"] = "127.0.0.1" }, func(p map[string]any) { p["daita_host"] = "fe80::1" }, func(p map[string]any) { p["daita_host"] = "::ffff:10.77.0.1" },
		func(p map[string]any) { p["daita_port"] = 22 }, func(p map[string]any) { p["mtu_policy"] = true }, func(p map[string]any) { p["jumbo_tun"] = "false" },
	} {
		p := fixtureProfile()
		mutate(p)
		if _, err := ReadProfile(encoded(p)); err == nil {
			t.Fatal("invalid private authority accepted", p)
		}
	}
	for _, mutate := range []func(map[string]any){
		func(g map[string]any) { g["inbounds"] = []any{} }, func(g map[string]any) { g["inbounds"] = append(g["inbounds"].([]any), g["inbounds"].([]any)[0]) },
		func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["strict_route"] = false }, func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["mtu"] = true },
		func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1400 }, func(g map[string]any) { g["route"].(map[string]any)["final"] = "absent" },
		func(g map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["type"] = "direct" },
	} {
		g := fixtureGraph()
		mutate(g)
		if _, err := NewPlan(encoded(g), 1380); err == nil {
			t.Fatal("ambiguous native graph accepted")
		}
	}
	if _, err := NewPlan(`{"inbounds":[],"inbounds":[]}`, 1380); err == nil {
		t.Fatal("duplicate JSON accepted")
	}
}
func TestMTUCacheBoundAndCASRollback(t *testing.T) {
	store := &testPreferences{}
	cache := NewCache(store)
	key := strings.Repeat("a", 64)
	if _, ok := cache.Lookup(key); ok {
		t.Fatal("empty cache fabricated value")
	}
	if err := cache.Save(key, 1380, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if value, ok := cache.Lookup(key); !ok || value != 1380 {
		t.Fatal("fresh measured value lost")
	}
	before := store.data
	valid := true
	store.afterWrite = func() { valid = false }
	if err := cache.Save(key, 1400, func() bool { return valid }); err == nil {
		t.Fatal("stale result committed")
	}
	if store.data != before {
		t.Fatal("stale preference write not rolled back")
	}
	store.afterWrite = nil
	for i := 0; i < 80; i++ {
		k := fmt.Sprintf("%064x", i)
		if err := cache.Save(k, 1280, func() bool { return true }); err != nil {
			t.Fatal(err)
		}
	}
	var data cacheDocument
	json.Unmarshal([]byte(store.data), &data)
	if len(data.Entries) != 64 {
		t.Fatal("unbounded cache")
	}
	for k, v := range data.Entries {
		v.Tested = time.Now().Add(-25 * time.Hour).Unix()
		data.Entries[k] = v
	}
	store.data = encoded(data)
	if _, ok := cache.Lookup(key); ok {
		t.Fatal("expired cache reused")
	}

}
