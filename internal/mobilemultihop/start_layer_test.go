package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func baseStartFixture(t *testing.T, rawMode, start, service string) (string, string, string) {
	t.Helper()
	var text, id, config string
	var err error
	if rawMode == "wg" {
		text, id = wireGuardFixture()
		config, err = WireGuardExitConfig(text, id)
	} else {
		text, id = amneziaFixture()
		config, err = AmneziaExitConfig(text, id)
	}
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	outer := map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "method": NativeStartLayerMethod, "password": key, "server": "192.0.2.1", "server_port": 8388}}}
	source, _ := json.Marshal(outer)
	meta, _ := json.Marshal(map[string]string{"mode": start, "raw_mode": rawMode, "node_kind": "router-vpn", "router_api": service})
	return config, string(source), string(meta)
}
func startObject(t *testing.T, text string) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func startJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func TestNativeBaseStartLayerPreservesEveryOwnedSetting(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, start := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, service := range []string{"http://10.77.0.1:8787", "https://[fd77:77::1]:8787"} {
				t.Run(mode+"/"+start+"/"+service, func(t *testing.T) {
					config, source, metadata := baseStartFixture(t, mode, start, service)
					before := startObject(t, config)
					result, err := ComposeNativeBaseStartLayer(config, source, metadata)
					if err != nil {
						t.Fatal(err)
					}
					next := startObject(t, result)
					for _, field := range []string{"inbounds", "dns", "route"} {
						if startJSON(t, before[field]) != startJSON(t, next[field]) {
							t.Fatal("altered", field)
						}
					}
					epBefore := before["endpoints"].([]any)[0].(map[string]any)
					epAfter := next["endpoints"].([]any)[0].(map[string]any)
					expectedAddress := "10.77.0.1"
					if strings.Contains(service, "fd77") {
						expectedAddress = "fd77:77::1"
					}
					epBefore["detour"] = NativeStartLayerTag
					epBefore["peers"].([]any)[0].(map[string]any)["address"] = expectedAddress
					if startJSON(t, epBefore) != startJSON(t, epAfter) {
						t.Fatal("changed endpoint credentials, AWG parameters, MTU or peer policy")
					}
					out := next["outbounds"].([]any)
					if len(out) != 1 {
						t.Fatal("extra transport")
					}
					aes := out[0].(map[string]any)
					expected := startObject(t, source)["outbounds"].([]any)[0].(map[string]any)
					expected["tag"] = NativeStartLayerTag
					if start == "aes-256-gcm+xor-whitening" {
						expected["type"] = "routervpn-aes-xor"
						expected["server_port"] = 8389
					}
					if startJSON(t, aes) != startJSON(t, expected) {
						t.Fatal("outer authenticated configuration changed")
					}
					if _, err = ComposeNativeBaseStartLayer(result, source, metadata); err == nil {
						t.Fatal("duplicate encapsulation accepted")
					}
				})
			}
		}
	}
}
func TestNativeBaseStartLayerRejectsForeignOrAmbiguousGraphs(t *testing.T) {
	config, source, metadata := baseStartFixture(t, "wg", "aes-256-gcm", "http://10.77.0.1:8787")
	cases := map[string]func(map[string]any){
		"no TUN":                  func(g map[string]any) { g["inbounds"] = []any{} },
		"two TUNs":                func(g map[string]any) { g["inbounds"] = append(g["inbounds"].([]any), g["inbounds"].([]any)[0]) },
		"direct final":            func(g map[string]any) { g["route"].(map[string]any)["final"] = "direct" },
		"unknown endpoint":        func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["type"] = "openvpn-client" },
		"second endpoint":         func(g map[string]any) { g["endpoints"] = append(g["endpoints"].([]any), g["endpoints"].([]any)[0]) },
		"foreign detour":          func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["detour"] = "other" },
		"empty existing detour":   func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["detour"] = "" },
		"second system VPN":       func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["system"] = true },
		"unknown endpoint option": func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["bind_interface"] = "unowned" },
		"conflicting tag": func(g map[string]any) {
			g["outbounds"] = []any{map[string]any{"tag": NativeStartLayerTag, "type": "direct"}}
		},
		"proxy tag collision": func(g map[string]any) { g["outbounds"] = []any{map[string]any{"tag": "proxy", "type": "direct"}} },
		"anonymous outbound":  func(g map[string]any) { g["outbounds"] = []any{map[string]any{"type": "direct"}} },
		"missing peer":        func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["peers"] = []any{} },
		"fractional port": func(g map[string]any) {
			g["endpoints"].([]any)[0].(map[string]any)["peers"].([]any)[0].(map[string]any)["port"] = 51820.5
		},
		"boolean port": func(g map[string]any) {
			g["endpoints"].([]any)[0].(map[string]any)["peers"].([]any)[0].(map[string]any)["port"] = true
		},
		"private key missing": func(g map[string]any) { delete(g["endpoints"].([]any)[0].(map[string]any), "private_key") },
		"public key malformed": func(g map[string]any) {
			g["endpoints"].([]any)[0].(map[string]any)["peers"].([]any)[0].(map[string]any)["public_key"] = "invalid"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			g := startObject(t, config)
			change(g)
			if _, err := ComposeNativeBaseStartLayer(startJSON(t, g), source, metadata); err == nil {
				t.Fatal("unsafe graph accepted")
			}
		})
	}
	for _, bad := range []string{config + "{}", strings.Replace(config, `"endpoints":`, `"endpoints":[],"endpoints":`, 1), strings.Repeat("x", 4<<20+1)} {
		if _, err := ComposeNativeBaseStartLayer(bad, source, metadata); err == nil {
			t.Fatal("ambiguous/oversized source accepted")
		}
	}
}
func TestNativeBaseStartLayerRejectsPolicySubstitution(t *testing.T) {
	config, source, metadata := baseStartFixture(t, "wg", "aes-256-gcm", "http://10.77.0.1:8787")
	for _, pair := range [][2]string{{"mode", "xor"}, {"mode", "off"}, {"node_kind", "external"}, {"raw_mode", "all"}, {"raw_mode", "awg2-fast"}, {"router_api", "http://public.example:8787"}, {"router_api", "http://127.0.0.1:8787"}, {"router_api", "http://8.8.8.8:8787"}, {"router_api", "http://10.77.0.1:8787/other"}, {"router_api", "http://user@10.77.0.1:8787"}, {"router_api", "http://10.77.0.1:8787?token=x"}, {"router_api", "http://[fe80::1%25eth0]:8787"}, {"router_api", "http://10.77.0.1:99999"}} {
		t.Run(pair[0]+"="+pair[1], func(t *testing.T) {
			m := startObject(t, metadata)
			m[pair[0]] = pair[1]
			if _, err := ComposeNativeBaseStartLayer(config, source, startJSON(t, m)); err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
	for _, pair := range []struct {
		key   string
		value any
	}{{"method", "none"}, {"method", "2022-blake3-aes-128-gcm"}, {"password", "plain-password-not-a-key"}, {"server_port", true}, {"server_port", 8388.5}, {"server_port", "8388"}, {"server_port", 0}, {"server_port", 65536}, {"server", "127.0.0.1"}, {"server", "::1"}, {"server", "localhost"}, {"plugin", "unowned"}, {"detour", "foreign"}, {"multiplex", map[string]any{"enabled": true}}} {
		t.Run(pair.key+" invalid", func(t *testing.T) {
			g := startObject(t, source)
			g["outbounds"].([]any)[0].(map[string]any)[pair.key] = pair.value
			_, err := ComposeNativeBaseStartLayer(config, startJSON(t, g), metadata)
			if err == nil {
				t.Fatal("unsafe outer accepted")
			}
			if strings.Contains(err.Error(), "plain-password-not-a-key") {
				t.Fatal("secret in error")
			}
		})
	}
}
func TestNativeBaseStartLayerValidatesAWGBeforeReturn(t *testing.T) {
	config, source, metadata := baseStartFixture(t, "awg2-strong", "aes-256-gcm+xor-whitening", "http://10.77.0.1:8787")
	g := startObject(t, config)
	g["endpoints"].([]any)[0].(map[string]any)["amnezia"].(map[string]any)["s4"] = "wrong"
	if _, err := ComposeNativeBaseStartLayer(startJSON(t, g), source, metadata); err == nil {
		t.Fatal("invalid AWG options accepted")
	}
}
