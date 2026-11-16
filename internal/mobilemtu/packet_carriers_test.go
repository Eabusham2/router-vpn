package mobilemtu

import (
	"encoding/base64"
	"strings"
	"testing"
)

func mtuPacketCarriersFixture() (map[string]any, map[string]any, map[string]any, map[string]any) {
	graph := fixtureGraph()
	graph["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1280
	packet := map[string]any{"type": "wireguard", "tag": "proxy", "mtu": 1824, "detour": "ss-inner", "peers": []any{map[string]any{"address": "192.0.2.9", "port": 51820}}}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	inner := map[string]any{"type": "shadowsocks", "tag": "ss-inner", "method": "2022-blake3-aes-256-gcm", "server": "192.0.2.8", "server_port": 8388, "password": key, "detour": "ss-outer"}
	outer := map[string]any{"type": "shadowsocks", "tag": "ss-outer", "method": "2022-blake3-aes-256-gcm", "server": "192.0.2.7", "server_port": 8388, "password": key, "detour": "entry"}
	graph["outbounds"] = []any{inner, outer}
	graph["endpoints"] = []any{packet, map[string]any{"tag": "entry", "type": "wireguard", "mtu": 2000}}
	return graph, packet, inner, outer
}

func TestMTUPacketCarriersValidateEveryCapturedEdge(t *testing.T) {
	graph, _, _, _ := mtuPacketCarriersFixture()
	before := encoded(graph)
	plan, err := NewPlan(before, 1280)
	if err != nil || plan.Ceiling != 1500 {
		t.Fatal("valid complete envelope refused", plan, err)
	}
	if after, err := plan.Config(1280); err != nil || after != before {
		t.Fatal("captured source changed", err)
	}
	for name, mutate := range map[string]func(map[string]any, map[string]any, map[string]any, map[string]any){
		"unprojected":      func(_ map[string]any, p, _, _ map[string]any) { p["mtu"] = 2000 },
		"one-wrapper-only": func(_ map[string]any, p, _, _ map[string]any) { p["mtu"] = 1872 },
		"new-identity-headers": func(_ map[string]any, _, i, _ map[string]any) {
			key := i["password"].(string)
			i["password"] = key + ":" + key + ":" + key
		},
		"changed-address-family": func(_ map[string]any, _, i, _ map[string]any) { i["server"] = "2001:db8::2" },
		"missing":                func(g map[string]any, _, i, _ map[string]any) { g["outbounds"] = []any{i} },
		"cycle":                  func(_ map[string]any, _, _, o map[string]any) { o["detour"] = "ss-inner" },
		"duplicate":              func(g map[string]any, _, i, _ map[string]any) { g["outbounds"] = append(g["outbounds"].([]any), i) },
		"under-minimum": func(g map[string]any, _, _, _ map[string]any) {
			g["endpoints"].([]any)[1].(map[string]any)["mtu"] = 1400
		},
		"control": func(_ map[string]any, p, _, _ map[string]any) {
			p["type"] = "routervpn-amneziawg"
			p["mtu"] = 1280
			p["amnezia"] = map[string]any{"jc": "3", "jmin": "40", "jmax": "900", "s1": "1280", "s2": "48", "s3": "24", "s4": "0", "h1": "10-19", "h2": "20-29", "h3": "30-39", "h4": "40-49"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			g, p, i, o := mtuPacketCarriersFixture()
			mutate(g, p, i, o)
			if name == "control" {
				g["endpoints"].([]any)[1].(map[string]any)["mtu"] = 1500
			}
			if _, err := NewPlan(encoded(g), 1280); err == nil {
				t.Fatal("unsafe original carrier graph admitted")
			}
		})
	}
}

func TestMTUPacketCarriersPreserveNativeDatagramOptionForms(t *testing.T) {
	for i, network := range []any{nil, []any{}, "udp", []any{"udp"}, []any{"tcp", "udp"}, []any{"udp", "tcp"}} {
		for j, uot := range []any{nil, false, map[string]any{}, map[string]any{"enabled": false}, map[string]any{"enabled": false, "version": 2}, map[string]any{"version": 255}, map[string]any{"enabled": nil, "version": nil}} {
			g, p, inner, _ := mtuPacketCarriersFixture()
			p["mtu"] = 1872
			inner["detour"] = "entry"
			g["outbounds"] = []any{inner}
			inner["network"], inner["udp_over_tcp"] = network, uot
			before := encoded(g)
			plan, err := NewPlan(before, 1280)
			if err != nil {
				t.Fatal("native-valid original single-layer datagrams refused", i, j, err)
			}
			if after, err := plan.Config(1280); err != nil || after != before {
				t.Fatal("original disabled option was rewritten", i, j, err)
			}
		}
	}
	for _, network := range []any{"", "tcp", []any{"tcp"}, "quic", []any{"udp", "quic"}, []any{true}, true} {
		g, _, inner, _ := mtuPacketCarriersFixture()
		inner["network"] = network
		if _, err := NewPlan(encoded(g), 1280); err == nil {
			t.Fatal("non-UDP or invalid native network form admitted", network)
		}
	}
	for _, uot := range []any{true, "false", map[string]any{"enabled": true}, map[string]any{"enabled": "false"}, map[string]any{"enabled": false, "foreign": true}, map[string]any{"version": 256}, map[string]any{"version": 1.5}, map[string]any{"enabled": 0}} {
		g, _, inner, _ := mtuPacketCarriersFixture()
		inner["udp_over_tcp"] = uot
		if _, err := NewPlan(encoded(g), 1280); err == nil {
			t.Fatal("enabled or malformed native UoT form admitted", uot)
		}
	}
}
