package mobilemtu

import "testing"

func TestExecutionPlansRetainActualGraphAndRejectMalformedAuthority(t *testing.T) {
	entry := "routervpn-chain-0-aaaaaaaaaaaa-node-bbbbbbbbbbbb"
	local := "routervpn-chain-1-cccccccccccc-node-dddddddddddd"
	server := "routervpn-chain-server-1-eeeeeeeeeeeeeeee"
	fixture := func() map[string]any {
		graph := fixtureGraph()
		graph["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": entry, "mtu": 1420, "private_key": "original", "peers": []any{map[string]any{"address": "192.0.2.2"}}}}
		graph["outbounds"] = []any{
			map[string]any{"type": "shadowsocks", "tag": local, "server": "192.0.2.1", "server_port": 8388, "password": "original", "method": "2022-blake3-aes-256-gcm", "detour": entry},
			map[string]any{"type": "selector", "tag": "proxy", "outbounds": []any{local, server}, "default": local, "interrupt_exist_connections": true},
			map[string]any{"type": "routervpn-node-chain-gate", "tag": "routervpn-chain-application", "detour": "proxy"},
			map[string]any{"type": "socks", "tag": server, "server": "10.77.0.1", "server_port": 32003, "version": "5", "username": "original-user", "password": "original-pass", "detour": entry, "network": []any{"tcp", "udp"}, "udp_over_tcp": map[string]any{"enabled": true, "version": 2}},
		}
		graph["route"].(map[string]any)["final"] = "routervpn-chain-application"
		return graph
	}
	graph := fixture()
	config := encoded(graph)
	var prefixes []*Plan
	for _, tag := range []string{entry, local} {
		graph["route"].(map[string]any)["final"] = tag
		plan, err := NewPlan(encoded(graph), 1380)
		if err != nil {
			t.Fatal(err)
		}
		prefixes = append(prefixes, plan)
	}
	plan, err := CombineExecutionPlans(config, 1380, prefixes)
	if err != nil || plan.source != config || plan.Ceiling != 1420 || plan.Original != 1380 || plan.captured != plan.captureDigest() {
		t.Fatal("original execution plan or packet bound was replaced", err)
	}
	for _, fault := range []string{"object-choices", "object-default", "missing-choice", "same-choice", "reordered-choices", "unowned-choice", "gate-detour", "uot-v1", "missing-prefix", "foreign-prefix", "forged-ceiling"} {
		t.Run(fault, func(t *testing.T) {
			graph := fixture()
			rows := graph["outbounds"].([]any)
			selector := rows[1].(map[string]any)
			candidates := append([]*Plan(nil), prefixes...)
			switch fault {
			case "object-choices":
				selector["outbounds"] = []any{map[string]any{"tag": local}, map[string]any{"tag": server}}
			case "object-default":
				selector["default"] = map[string]any{"tag": local}
			case "missing-choice":
				selector["outbounds"] = []any{local}
			case "same-choice":
				selector["outbounds"] = []any{local, local}
			case "reordered-choices":
				selector["outbounds"] = []any{server, local}
			case "unowned-choice":
				selector["outbounds"] = []any{local, "direct"}
			case "gate-detour":
				rows[2].(map[string]any)["detour"] = local
			case "uot-v1":
				rows[3].(map[string]any)["udp_over_tcp"] = map[string]any{"enabled": true, "version": 1}
			case "missing-prefix":
				candidates = candidates[:1]
			case "foreign-prefix":
				candidates[1] = candidates[0]
			case "forged-ceiling":
				forged := *candidates[0]
				forged.Ceiling = 9000
				candidates[0] = &forged
			}
			if _, err := CombineExecutionPlans(encoded(graph), 1380, candidates); err == nil {
				t.Fatal("unowned execution MTU authority admitted", fault)
			}
		})
	}
}
