package mobilemtu

import (
	"encoding/base64"
	"encoding/json"
	"router-vpn/internal/nativeopenvpn"
	"strings"
	"testing"
)

func mappedOpenVPNMTUGraph(t *testing.T, mode string) map[string]any {
	t.Helper()
	profile := nativeopenvpn.Profile{Config: "client\nremote 192.0.2.60 1194 udp\nremote 192.0.2.61 443 tcp\nauth-user-pass\npeer-fingerprint " + strings.Repeat("a", 64) + "\nverify-x509-name provider.example name\ntun-mtu 1382\n", Username: "local-user", Password: "local-secret"}
	endpoint, err := nativeopenvpn.CompileProfile(profile, "custom-exit", "owned-layer-map")
	if err != nil {
		t.Fatal(err)
	}
	remotes, err := nativeopenvpn.Remotes(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	layers := nativeopenvpn.StartLayers{}
	for index, host := range []string{"192.0.2.60", "192.0.2.61"} {
		layers[host] = nativeopenvpn.StartLayer{Mode: mode, API: "http://10.93.0.1:8787", Transport: map[string]any{"type": "shadowsocks", "tag": "private-start", "server": host, "server_port": float64(8388 + index*2), "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+index)), 32)))}}
	}
	mapping := nativeopenvpn.LayerMap{Mode: mode, Remotes: remotes, Layers: layers, Detour: "entry"}
	raw, _ := json.Marshal(mapping)
	var outer map[string]any
	_ = json.Unmarshal(raw, &outer)
	outer["type"], outer["tag"] = nativeopenvpn.LayerMapType, "owned-layer-map"
	graph := fixtureGraph()
	graph["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1280
	graph["endpoints"] = []any{endpoint, map[string]any{"type": "wireguard", "tag": "entry", "mtu": 1600}}
	graph["outbounds"] = []any{outer}
	graph["route"].(map[string]any)["final"] = "custom-exit"
	return graph
}

func TestMappedOpenVPNMTURetestPreservesEveryPermittedBranch(t *testing.T) {
	for _, mode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(mode, func(t *testing.T) {
			graph := mappedOpenVPNMTUGraph(t, mode)
			plan, err := NewPlan(encoded(graph), 1280)
			if err != nil || plan.Ceiling != 1382 {
				t.Fatal("real typed-number graph lost mapped endpoint bound", err)
			}
			if _, err := plan.Config(1383); err == nil {
				t.Fatal("MTU retest exceeded captured OpenVPN/layer envelope")
			}
			for _, candidate := range plan.Candidates(1500) {
				if candidate > 1382 {
					t.Fatal("cached historical MTU bypassed captured map")
				}
			}
			changed, err := plan.Config(1382)
			if err != nil {
				t.Fatal(err)
			}
			var after map[string]any
			_ = json.Unmarshal([]byte(changed), &after)
			for _, family := range []string{"endpoints", "outbounds", "route", "dns"} {
				if encoded(graph[family]) != encoded(after[family]) {
					t.Fatal("MTU optimizer altered private mapped path", family)
				}
			}
		})
	}
}

func TestMappedOpenVPNMTURejectsForeignRemoteAndAccountsLargestLayer(t *testing.T) {
	base := mappedOpenVPNMTUGraph(t, "aes-256-gcm")
	raw := encoded(base)
	for name, mutate := range map[string]func(map[string]any){
		"mapper host": func(g map[string]any) {
			g["outbounds"].([]any)[0].(map[string]any)["remotes"].([]any)[1].(map[string]any)["host"] = "192.0.2.62"
		},
		"mapper port": func(g map[string]any) {
			g["outbounds"].([]any)[0].(map[string]any)["remotes"].([]any)[1].(map[string]any)["port"] = 1194
		},
		"mapper network": func(g map[string]any) {
			g["outbounds"].([]any)[0].(map[string]any)["remotes"].([]any)[1].(map[string]any)["network"] = "udp"
		},
		"unknown mapper option": func(g map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["fallback"] = "direct" },
		"foreign entry":         func(g map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["detour"] = "unowned" },
		"missing layer": func(g map[string]any) {
			delete(g["outbounds"].([]any)[0].(map[string]any)["layers"].(map[string]any), "192.0.2.61")
		},
		"unsafe current MTU": func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1500 },
	} {
		t.Run(name, func(t *testing.T) {
			var graph map[string]any
			_ = json.Unmarshal([]byte(raw), &graph)
			mutate(graph)
			actual := 1280
			if name == "unsafe current MTU" {
				actual = 1500
			}
			if _, err := NewPlan(encoded(graph), actual); err == nil {
				t.Fatal("unowned mapped MTU path accepted")
			}
		})
	}
	var graph map[string]any
	_ = json.Unmarshal([]byte(raw), &graph)
	second := graph["outbounds"].([]any)[0].(map[string]any)["layers"].(map[string]any)["192.0.2.61"].(map[string]any)
	second["api"] = "http://[fd93::1]:8787"
	password := second["transport"].(map[string]any)["password"].(string)
	second["transport"].(map[string]any)["password"] = password + ":" + password + ":" + password
	plan, err := NewPlan(encoded(graph), 1280)
	// 1600 entry -160 conservative IPv6/OpenVPN -94 largest SS2022 branch.
	if err != nil || plan.Ceiling != 1346 {
		t.Fatal("smaller first layer hid larger IPv6/multi-key branch", err, plan)
	}
}
