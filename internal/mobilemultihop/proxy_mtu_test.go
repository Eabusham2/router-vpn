package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"testing"
)

func proxyMTUGraph(t *testing.T, mode, tag string, packetExit bool) string {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal([]byte(mtuGraph(t)), &root); err != nil {
		t.Fatal(err)
	}
	entry := proxyEntry(t, mode)
	entry["tag"] = tag
	if packetExit {
		exit := root["endpoints"].([]any)[1].(map[string]any)
		exit["detour"] = tag
		root["endpoints"] = []any{exit}
		root["outbounds"] = []any{entry}
	} else {
		delete(root, "endpoints")
		root["outbounds"] = []any{entry, map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "198.51.100.9", "server_port": 8443, "method": "chacha20-ietf-poly1305", "password": "independent-exit-secret", "detour": tag}}
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func TestProxyMTUUsesOneRealInterfaceAndNeverInventsEntryMTU(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "hysteria2"} {
		for _, tag := range []string{"entry-wg", "routervpn-hop-entry"} {
			for _, packet := range []bool{false, true} {
				config := proxyMTUGraph(t, mode, tag, packet)
				for _, tc := range []struct {
					profile   string
					tun, exit int
					fixed     bool
				}{
					{`{"entry":{},"exit":{}}`, 1280, 1420, false},
					{`{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"auto"}}`, 1500, 1500, true},
					{`{"entry":{},"exit":{"mtu_policy":"manual","manual_mtu":1340}}`, 1340, 1340, true},
					{`{"entry":{"mtu_policy":"fixed","manual_mtu":9000},"exit":{"mtu_policy":"fixed","manual_mtu":9000}}`, 9000, 9000, true},
					{`{"entry":{"effective_mtu":9000},"exit":{"effective_mtu":9000}}`, 1280, 1420, false},
				} {
					var before, after map[string]any
					json.Unmarshal([]byte(config), &before)
					result, err := ApplyMTUPolicy(config, tc.profile)
					if err != nil {
						t.Fatal(mode, packet, err)
					}
					json.Unmarshal([]byte(result), &after)
					entry := after["outbounds"].([]any)[0].(map[string]any)
					if entry["mtu"] != nil || !reflect.DeepEqual(before["outbounds"], after["outbounds"]) {
						t.Fatal("MTU invented or changed a proxy interface/credential")
					}
					if int(after["inbounds"].([]any)[0].(map[string]any)["mtu"].(float64)) != tc.tun {
						t.Fatal("wrong shared TUN MTU")
					}
					if packet && int(after["endpoints"].([]any)[0].(map[string]any)["mtu"].(float64)) != tc.exit {
						t.Fatal("invented outer IP envelope or ignored fixed exit")
					}
					metadata, err := MultihopMTUProfile(config, tc.profile)
					if err != nil {
						t.Fatal(err)
					}
					var profile map[string]any
					json.Unmarshal([]byte(metadata), &profile)
					value, err := fixedMTU(profile)
					if err != nil {
						t.Fatal(err)
					}
					if (value != 0) != tc.fixed || tc.fixed && value != tc.tun {
						t.Fatal("optimizer could overwrite the fixed shared TUN policy")
					}
					repeated, err := ApplyMTUPolicy(result, tc.profile)
					if err != nil || repeated != result {
						t.Fatal("MTU projection changed on reapplication")
					}
				}
			}
		}
	}
}
func TestProxyEntryMTURejectsConflictsAndWrongOwnership(t *testing.T) {
	config := proxyMTUGraph(t, "shadowsocks", "entry-wg", true)
	for _, profile := range []string{
		`{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"fixed","manual_mtu":1400}}`,
		`{"entry":{"mtu_policy":"fixed","manual_mtu":1279},"exit":{}}`,
		`{"entry":{"mtu_policy":"fixed","manual_mtu":true},"exit":{}}`,
		`{"entry":{"mtu_policy":"fixed","manual_mtu":1400.5},"exit":{}}`,
		`{"entry":{"mtu_policy":false},"exit":{}}`,
		`{"entry":{},"exit":{"mtu_policy":"unknown"}}`,
	} {
		if _, err := ApplyMTUPolicy(config, profile); err == nil {
			t.Fatal("ambiguous fixed policy accepted")
		}
		if _, err := MultihopMTUProfile(config, profile); err == nil {
			t.Fatal("invalid optimizer policy published")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(g map[string]any) { g["outbounds"] = append(g["outbounds"].([]any), g["outbounds"].([]any)[0]) },
		func(g map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["type"] = "socks" },
		func(g map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["mtu"] = 1500 },
		func(g map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["detour"] = "bypass" },
		func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["detour"] = "not-entry" },
		func(g map[string]any) { g["endpoints"] = "invalid" },
	} {
		var graph map[string]any
		json.Unmarshal([]byte(config), &graph)
		mutate(graph)
		raw, _ := json.Marshal(graph)
		if _, err := ApplyMTUPolicy(string(raw), `{"entry":{},"exit":{}}`); err == nil {
			t.Fatal("MTU lost owned proxy entry")
		}
	}
}
func TestPacketEntryFixedMTURemainsSeparateFromExitOptimizer(t *testing.T) {
	pair := `{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"id":"exit","api_token":"preserve","mtu_policy":"auto","effective_mtu":9000}}`
	got, err := MultihopMTUProfile(mtuGraph(t), pair)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]map[string]any
	json.Unmarshal([]byte(pair), &decoded)
	var profile map[string]any
	json.Unmarshal([]byte(got), &profile)
	if !reflect.DeepEqual(profile, decoded["exit"]) {
		t.Fatal("separate packet entry setting replaced exit policy or identity")
	}
}
