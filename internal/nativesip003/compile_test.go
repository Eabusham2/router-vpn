package nativesip003

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func fixture(dns string) ([]byte, []byte) {
	helper := map[string]any{"server": "192.0.2.1", "server_port": 10443, "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "method": "2022-blake3-aes-256-gcm", "local_address": "127.0.0.1", "local_port": 1092, "mode": "tcp_only", "plugin": "v2ray-plugin", "plugin_opts": "tls;host=vpn.example.com;path=/shadowsocks"}
	config := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true, "mtu": 1320}},
		"outbounds": []any{map[string]any{"type": "socks", "tag": "tcp-stack", "server": "127.0.0.1", "server_port": 1092, "version": "5"}, map[string]any{"type": "hysteria2", "tag": "udp-stack", "server": "192.0.2.1", "server_port": 8443, "password": "ephemeral-hysteria-fixture", "obfs": map[string]any{"type": "salamander", "password": "fixture-mask"}, "tls": map[string]any{"enabled": true, "server_name": "node.test", "certificate_path": "cert.pem"}}, map[string]any{"type": "direct", "tag": "direct"}},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": dns, "tag": "selected", "server": "1.1.1.1", "detour": "tcp-stack"}}, "final": "selected"},
		"route":     map[string]any{"rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"network": "tcp", "action": "route", "outbound": "tcp-stack"}, map[string]any{"network": "udp", "action": "route", "outbound": "udp-stack"}}, "auto_detect_interface": true, "final": "tcp-stack"},
	}
	a, _ := json.Marshal(config)
	b, _ := json.Marshal(helper)
	return a, b
}
func encoded(v any) []byte { b, _ := json.Marshal(v); return b }
func TestNativeCompilerRetainsTransportAndCorrectlyRoutesDNS(t *testing.T) {
	for _, dns := range []string{"udp", "tcp", "tls", "https", "h3", "quic"} {
		t.Run(dns, func(t *testing.T) {
			wrapper, helper := fixture(dns)
			before, _ := Object(wrapper)
			original := append([]byte(nil), wrapper...)
			result, e := Compile(wrapper, helper)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(wrapper, original) {
				t.Fatal("caller-owned original changed")
			}
			root, _ := Object(result)
			list := root["outbounds"].([]any)
			ss := list[0].(map[string]any)
			h, _ := Object(helper)
			for _, field := range []string{"server", "server_port", "password", "method", "plugin", "plugin_opts"} {
				if !bytes.Equal(encoded(ss[field]), encoded(h[field])) {
					t.Fatal("protocol field changed", field)
				}
			}
			if ss["type"] != "shadowsocks" || ss["network"] != "tcp" || ss["tag"] != "tcp-stack" {
				t.Fatal("incorrect native graph")
			}
			for _, field := range []string{"log", "inbounds", "route"} {
				if !bytes.Equal(encoded(before[field]), encoded(root[field])) {
					t.Fatal("surrounding policy changed", field)
				}
			}
			if !bytes.Equal(encoded(before["outbounds"].([]any)[1:]), encoded(list[1:])) {
				t.Fatal("UDP cryptography or direct declaration changed")
			}
			detour := "tcp-stack"
			if dns == "udp" || dns == "h3" || dns == "quic" {
				detour = "udp-stack"
			}
			server := root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if server["detour"] != detour || server["server"] != "1.1.1.1" || server["type"] != dns {
				t.Fatal("DNS policy changed or uses incompatible leg")
			}
			repeated, e := Compile(result, helper)
			if e != nil || !bytes.Equal(result, repeated) {
				t.Fatal("repeated compile not exact", e)
			}
		})
	}
}
func TestHelperCommandsAndDowngradesAreRejectedBeforeExecution(t *testing.T) {
	cases := map[string]func(map[string]any){
		"external plugin":  func(h map[string]any) { h["plugin"] = "/bin/helper" },
		"extra command":    func(h map[string]any) { h["command"] = "do not run" },
		"unprotected":      func(h map[string]any) { h["method"] = "none" },
		"wrong key":        func(h map[string]any) { h["password"] = "not a valid key" },
		"weak key":         func(h map[string]any) { h["password"] = base64.StdEncoding.EncodeToString(make([]byte, 16)) },
		"public helper":    func(h map[string]any) { h["local_address"] = "0.0.0.0" },
		"invalid port":     func(h map[string]any) { h["server_port"] = 65536 },
		"fractional port":  func(h map[string]any) { h["local_port"] = 1092.5 },
		"udp helper":       func(h map[string]any) { h["mode"] = "tcp_and_udp" },
		"missing tls":      func(h map[string]any) { h["plugin_opts"] = "host=vpn.example.com;path=/x" },
		"insecure tls":     func(h map[string]any) { h["plugin_opts"] = "tls;host=vpn.example.com;path=/x;insecure" },
		"duplicate option": func(h map[string]any) { h["plugin_opts"] = "tls;host=vpn.example.com;path=/x;tls" },
		"path injection":   func(h map[string]any) { h["plugin_opts"] = "tls;host=vpn.example.com;path=/x\ncommand" },
		"server option":    func(h map[string]any) { h["plugin_opts"] = "tls;host=vpn.example.com;path=/x;server" },
		"file certificate": func(h map[string]any) { h["plugin_opts"] = "tls;host=vpn.example.com;path=/x;cert=/private/file" },
		"bad inline cert":  func(h map[string]any) { h["plugin_opts"] = "tls;host=vpn.example.com;path=/x;certRaw=YmFk" },
		"wrong websocket":  func(h map[string]any) { h["plugin_opts"] = "tls;host=vpn.example.com;path=/x;mode=quic" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, b := fixture("udp")
			h, _ := Object(b)
			mutate(h)
			if _, e := Compile(a, encoded(h)); e == nil {
				t.Fatal("unsafe helper accepted")
			}
		})
	}
	for _, host := range []string{"localhost", "127.0.0.1", "127.1", "2130706433", "::ffff:127.0.0.1", "::", "fe80::1%en0", "224.0.0.1", "x/y", "x..y"} {
		t.Run(host, func(t *testing.T) {
			a, b := fixture("udp")
			h, _ := Object(b)
			h["server"] = host
			if _, e := Compile(a, encoded(h)); e == nil {
				t.Fatal("unsafe endpoint accepted")
			}
		})
	}
}
func TestNativeGraphCannotDropALayerOrAdoptAnotherHelper(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wrong local port": func(r map[string]any) { r["outbounds"].([]any)[0].(map[string]any)["server_port"] = 1093 },
		"wrong local auth": func(r map[string]any) { r["outbounds"].([]any)[0].(map[string]any)["username"] = "wrong" },
		"direct default":   func(r map[string]any) { r["route"].(map[string]any)["final"] = "direct" },
		"no UDP leg":       func(r map[string]any) { list := r["outbounds"].([]any); r["outbounds"] = []any{list[0], list[2]} },
		"wrong UDP route": func(r map[string]any) {
			r["route"].(map[string]any)["rules"].([]any)[2].(map[string]any)["outbound"] = "tcp-stack"
		},
		"unprotected UDP TLS": func(r map[string]any) {
			r["outbounds"].([]any)[1].(map[string]any)["tls"].(map[string]any)["insecure"] = true
		},
		"duplicate tag": func(r map[string]any) { r["outbounds"].([]any)[1].(map[string]any)["tag"] = "tcp-stack" },
		"no full route": func(r map[string]any) { r["inbounds"].([]any)[0].(map[string]any)["auto_route"] = false },
		"foreign DNS": func(r map[string]any) {
			r["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] = "direct"
		},
		"extra service": func(r map[string]any) { r["services"] = []any{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, b := fixture("udp")
			r, _ := Object(a)
			mutate(r)
			if _, e := Compile(encoded(r), b); e == nil {
				t.Fatal("mismatched graph accepted")
			}
		})
	}
	a, b := fixture("udp")
	compiled, e := Compile(a, b)
	if e != nil {
		t.Fatal(e)
	}
	r, _ := Object(compiled)
	r["outbounds"].([]any)[0].(map[string]any)["plugin_opts"] = "tls;host=other.example;path=/other"
	if _, e := Compile(encoded(r), b); e == nil {
		t.Fatal("different native transport adopted")
	}
}
func TestCompilerJSONMustBeBoundedAndUnambiguous(t *testing.T) {
	for _, raw := range []string{`{"key":1,"key":2}`, `{} {}`, `[]`, strings.Repeat("[", 60) + strings.Repeat("]", 60), strings.Repeat(" ", MaxConfig+1), string([]byte{0xff})} {
		if _, e := Object([]byte(raw)); e == nil {
			t.Fatal("ambiguous or unbounded input accepted")
		}
	}
}
