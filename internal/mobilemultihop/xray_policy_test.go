package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"testing"
)

func xrayPolicyFixture(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	g := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []any{"172.19.0.1/30"}, "mtu": 1380, "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "routervpn-xray", "tag": "tcp-stack", "mode": "max", "config_json": "original-validated-Xray", "detour": "aes"}, map[string]any{"type": "hysteria2", "tag": "udp-stack", "server": "10.77.0.1", "password": "original-private-key"}, map[string]any{"type": "shadowsocks", "tag": "aes", "server": "192.0.2.1", "password": "original-aes"}}, "dns": map[string]any{"servers": []any{map[string]any{"type": "h3", "tag": "home", "server": "192.168.50.133", "server_port": 5353, "detour": "udp-stack"}}, "final": "home"}, "route": map[string]any{"final": "tcp-stack", "rules": []any{map[string]any{"network": "tcp", "action": "route", "outbound": "tcp-stack"}, map[string]any{"network": "udp", "action": "route", "outbound": "udp-stack"}}}}
	return g, map[string]any{"node_kind": "router-vpn", "home_lan_access": false, "ipv6_mode": "off", "router_api": "http://10.77.0.1:8787"}
}
func proxyPolicy(t *testing.T, g, p map[string]any) (map[string]any, error) {
	t.Helper()
	a, _ := json.Marshal(g)
	b, _ := json.Marshal(p)
	v, e := ApplyNativeXrayDevicePolicy(string(a), string(b))
	if e != nil {
		return nil, e
	}
	var out map[string]any
	e = json.Unmarshal([]byte(v), &out)
	return out, e
}
func TestNativeXrayDevicePolicyPreservesEncryptedLegsAndDNS(t *testing.T) {
	for _, lan := range []bool{true, false} {
		for _, ip := range []string{"on", "off"} {
			g, p := xrayPolicyFixture(t)
			p["home_lan_access"] = lan
			p["ipv6_mode"] = ip
			next, e := proxyPolicy(t, g, p)
			if e != nil {
				t.Fatal(e)
			}
			originalRaw, _ := json.Marshal(g)
			var original map[string]any
			json.Unmarshal(originalRaw, &original)
			if !reflect.DeepEqual(next["outbounds"], original["outbounds"]) {
				t.Fatal("changed encrypted transport or credentials")
			}
			if !reflect.DeepEqual(next["dns"].(map[string]any)["servers"], original["dns"].(map[string]any)["servers"]) {
				t.Fatal("DNS resolver policy changed")
			}
			route := next["route"].(map[string]any)
			if route["final"] != "tcp-stack" {
				t.Fatal("final route changed")
			}
			rules := route["rules"].([]any)
			oldRules := original["route"].(map[string]any)["rules"].([]any)
			if !reflect.DeepEqual(rules[len(rules)-2:], oldRules) {
				t.Fatal("dual transport rules changed")
			}
			tun := next["inbounds"].([]any)[0].(map[string]any)
			if ip == "off" {
				if rules[0].(map[string]any)["action"] != "reject" || rules[0].(map[string]any)["ip_version"] != float64(6) {
					t.Fatal("IPv6 escapes VPN")
				}
				if len(tun["address"].([]any)) != 2 {
					t.Fatal("IPv6 not captured")
				}
			}
			if !lan {
				offset := 0
				if ip == "off" {
					offset = 1
				}
				control := rules[offset+1].(map[string]any)
				if control["outbound"] != "tcp-stack" || control["port"] != float64(8787) || !reflect.DeepEqual(control["ip_cidr"], []any{"10.77.0.1/32"}) {
					t.Fatal("broad control bypass")
				}
				if rules[offset+2].(map[string]any)["action"] != "reject" {
					t.Fatal("LAN not blocked")
				}
			}
		}
	}
}
func TestNativeXrayDevicePolicyRejectsBypassAndAmbiguousOwnership(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(g map[string]any) { g["route"].(map[string]any)["final"] = "aes" }, func(g map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["type"] = "direct" }, func(g map[string]any) { g["outbounds"] = append(g["outbounds"].([]any), g["outbounds"].([]any)[0]) }, func(g map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["mode"] = "tor" }, func(g map[string]any) {
			g["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"] = []string{"::/0"}
		}, func(g map[string]any) { g["inbounds"] = append(g["inbounds"].([]any), g["inbounds"].([]any)[0]) }, func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["address"] = []string{"invalid"} },
	} {
		g, p := xrayPolicyFixture(t)
		mutate(g)
		if _, e := proxyPolicy(t, g, p); e == nil {
			t.Fatal("unowned policy accepted")
		}
	}
	for _, value := range []any{nil, 1, "false", []any{}} {
		g, p := xrayPolicyFixture(t)
		p["home_lan_access"] = value
		if _, e := proxyPolicy(t, g, p); e == nil {
			t.Fatal("malformed LAN flag accepted")
		}
	}
	for _, value := range []any{nil, true, "invented", 4} {
		g, p := xrayPolicyFixture(t)
		p["ipv6_mode"] = value
		if _, e := proxyPolicy(t, g, p); e == nil {
			t.Fatal("invalid IPv6 policy accepted")
		}
	}
}
