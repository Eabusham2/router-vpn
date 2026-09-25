package applexray

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleConfig(mode string) []byte {
	user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
	stream := map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "www.example.com", "fingerprint": "chrome", "password": "public-key-fixture", "shortId": "0123456789abcdef"}}
	if mode == "reality-pq-vision" || mode == "reality-xhttp" || mode == "max" {
		user["encryption"] = "mlkem768x25519plus.native.0rtt.public-authentication-fixture"
	}
	if mode == "reality-xhttp" {
		delete(user, "flow")
		stream["network"] = "xhttp"
		stream["xhttpSettings"] = map[string]any{"path": "/assets/sync", "mode": "auto"}
		stream["finalmask"] = map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "100-300", "delay": "10-30", "maxSplit": "3-7"}}}}
	}
	out := map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "192.0.2.1", "port": 10443, "users": []any{user}}}}, "streamSettings": stream}
	raw, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": 1090, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{out}})
	return raw
}
func sampleWrapper() []byte {
	return []byte(`{"inbounds":[{"type":"tun","auto_route":true,"strict_route":true}],"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1090,"version":"5"},{"type":"direct","tag":"direct"}],"dns":{"servers":[{"type":"https","tag":"selected","server":"1.1.1.1","detour":"proxy","tls":{"enabled":true,"server_name":"cloudflare-dns.com"}}]},"route":{"rules":[{"protocol":"dns","action":"hijack-dns"}],"final":"proxy"}}`)
}
func TestNativePlanPreservesEveryProtocolField(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp", "split", "max"} {
		t.Run(mode, func(t *testing.T) {
			raw := sampleConfig(mode)
			old, _ := Object(raw)
			plan, err := Prepare(mode, raw)
			if err != nil {
				t.Fatal(err)
			}
			next, _ := Object(plan.JSON)
			before, _ := json.Marshal(old["outbounds"])
			after, _ := json.Marshal(next["outbounds"])
			if string(before) != string(after) {
				t.Fatal("protocol security or transport changed")
			}
			if len(next["inbounds"].([]any)) != 0 || next["log"].(map[string]any)["loglevel"] != "none" {
				t.Fatal("unowned ingress/logging survived")
			}
			if plan.Server.String() != "192.0.2.1:10443" || plan.ListenerPort != 1090 {
				t.Fatal("wrong frozen route")
			}
			composed, err := Compile(mode, wrapperFor(mode), raw)
			if err != nil {
				t.Fatal(err)
			}
			wrapper, _ := Object(composed)
			newProxy := wrapper["outbounds"].([]any)[0].(map[string]any)
			if newProxy["type"] != Type || newProxy["config_json"] != string(raw) || newProxy["mode"] != mode || newProxy["tag"] != "proxy" {
				t.Fatal("native protocol or route identity lost")
			}
			original, _ := Object(wrapperFor(mode))
			for _, key := range []string{"dns", "route", "inbounds"} {
				a, _ := json.Marshal(original[key])
				b, _ := json.Marshal(wrapper[key])
				if string(a) != string(b) {
					t.Fatal("surrounding policy overwritten:", key)
				}
			}
		})
	}
}
func TestPolicyRejectsHiddenCapabilitiesAndDowngrades(t *testing.T) {
	paths := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"public ingress", func(v map[string]any) { v["inbounds"].([]any)[0].(map[string]any)["listen"] = "0.0.0.0" }},
		{"hidden API", func(v map[string]any) { v["api"] = map[string]any{} }},
		{"global DNS", func(v map[string]any) { v["dns"] = map[string]any{"servers": []string{"8.8.8.8"}} }},
		{"file log", func(v map[string]any) { v["log"].(map[string]any)["access"] = "/private/host" }},
		{"wrong peer", func(v map[string]any) { remote(v)["address"] = "127.0.0.1" }},
		{"scoped peer", func(v map[string]any) { remote(v)["address"] = "fe80::1%utun2" }},
		{"missing port", func(v map[string]any) { delete(remote(v), "port") }},
		{"fractional port", func(v map[string]any) { remote(v)["port"] = json.Number("1.5") }},
		{"missing PQ", func(v map[string]any) { remote(v)["users"].([]any)[0].(map[string]any)["encryption"] = "none" }},
		{"no REALITY", func(v map[string]any) { out(v)["streamSettings"].(map[string]any)["security"] = "none" }},
		{"socket override", func(v map[string]any) {
			out(v)["streamSettings"].(map[string]any)["sockopt"] = map[string]any{"interface": "utun3"}
		}},
		{"direct escape", func(v map[string]any) {
			v["outbounds"] = append(v["outbounds"].([]any), map[string]any{"protocol": "freedom"})
		}},
		{"proxy override", func(v map[string]any) { out(v)["proxySettings"] = map[string]any{"tag": "escape"} }},
	}
	for _, c := range paths {
		t.Run(c.name, func(t *testing.T) {
			v, _ := Object(sampleConfig("reality-pq-vision"))
			c.mutate(v)
			raw, _ := json.Marshal(v)
			if _, err := Prepare("reality-pq-vision", raw); err == nil {
				t.Fatal("unsafe or downgraded profile accepted")
			}
		})
	}
	for _, mode := range []string{"wg", "awg2-pq", "max-tls-wg", "unknown"} {
		if _, err := Prepare(mode, sampleConfig("reality-pq-vision")); err == nil {
			t.Fatal("unimplemented mode mislabeled as native", mode)
		}
	}
}
func out(v map[string]any) map[string]any { return v["outbounds"].([]any)[0].(map[string]any) }
func remote(v map[string]any) map[string]any {
	return out(v)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
}
func TestWrapperOwnershipAndRepeatedComposition(t *testing.T) {
	raw := sampleConfig("reality-vision")
	first, err := Compile("reality-vision", sampleWrapper(), raw)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := Compile("reality-vision", first, raw)
	if err != nil || string(first) != string(repeated) {
		t.Fatal("same exact saved wrapper not idempotent", err)
	}
	for _, pair := range [][2]string{{`"server_port":1090`, `"server_port":1091`}, {`"server":"127.0.0.1"`, `"server":"::1"`}, {`"version":"5"`, `"version":"4"`}, {`"version":"5"`, `"version":"5","detour":"direct"`}, {`"type":"socks"`, `"type":"http"`}} {
		if _, err := Compile("reality-vision", []byte(strings.Replace(string(sampleWrapper()), pair[0], pair[1], 1)), raw); err == nil {
			t.Fatal("wrong helper adopted", pair)
		}
	}
	v, _ := Object(first)
	v["outbounds"].([]any)[0].(map[string]any)["config_json"] = string(sampleConfig("reality-pq-vision"))
	tampered, _ := json.Marshal(v)
	if _, err := Compile("reality-vision", tampered, raw); err == nil {
		t.Fatal("different saved native config adopted")
	}
}
func TestXrayInputIsExactBoundedJSON(t *testing.T) {
	for _, raw := range []string{"{}{}", "[]", `{"log":{},"log":{}}`, `{"outbounds":[{"tag":"a","tag":"b"}]}`, strings.Repeat("[", 60) + strings.Repeat("]", 60), string([]byte{0xff}), strings.Repeat(" ", MaxConfig+1)} {
		if _, err := Object([]byte(raw)); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}

func wrapperFor(mode string) []byte {
	if mode != "split" && mode != "max" {
		return sampleWrapper()
	}
	root, _ := Object(sampleWrapper())
	list := root["outbounds"].([]any)
	root["outbounds"] = append(list, map[string]any{"type": "hysteria2", "tag": "udp-stack", "server": "192.0.2.1", "server_port": 8443, "password": "fixture"})
	route := root["route"].(map[string]any)
	route["rules"] = append(route["rules"].([]any), map[string]any{"network": "tcp", "outbound": "proxy"}, map[string]any{"network": "udp", "outbound": "udp-stack"})
	out, _ := json.Marshal(root)
	return out
}
func TestDualTransportCannotDropARequiredLayer(t *testing.T) {
	for _, mode := range []string{"split", "max"} {
		raw := sampleConfig(mode)
		if _, err := Compile(mode, sampleWrapper(), raw); err == nil {
			t.Fatal("dual transport silently became Xray-only")
		}
		graph, _ := Object(wrapperFor(mode))
		graph["route"].(map[string]any)["final"] = "direct"
		bad, _ := json.Marshal(graph)
		if _, err := Compile(mode, bad, raw); err == nil {
			t.Fatal("direct final route accepted")
		}
	}
	for _, in := range []string{`{"type":"tun"}`, `{"type":"socks","listen":"0.0.0.0"}`} {
		graph, _ := Object(sampleWrapper())
		node, _ := Object([]byte(in))
		graph["inbounds"] = []any{node}
		bad, _ := json.Marshal(graph)
		if _, err := Compile("reality-vision", bad, sampleConfig("reality-vision")); err == nil {
			t.Fatal("unowned TUN/listener accepted")
		}
	}
}
