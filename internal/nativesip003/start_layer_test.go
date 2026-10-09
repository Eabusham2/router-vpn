package nativesip003

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func startFixture(mode, api string) ([]byte, []byte) {
	source := map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{29}, 32)), "server": "192.0.2.1", "server_port": 8388}}}
	return encoded(source), encoded(map[string]any{"mode": mode, "raw_mode": Mode, "node_kind": "router-vpn", "router_api": api})
}
func TestStartLayerRetainsBothLegsAndSelectedDNS(t *testing.T) {
	for _, mode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, api := range []string{"http://10.77.0.1:8787", "https://[fd77:77::1]:8787"} {
			for _, dns := range []string{"udp", "tcp", "tls", "https", "h3", "quic"} {
				t.Run(mode+api+dns, func(t *testing.T) {
					wrapper, helper := fixture(dns)
					a, b := startFixture(mode, api)
					normalized, e := Compile(wrapper, helper)
					if e != nil {
						t.Fatal(e)
					}
					before, _ := Object(normalized)
					got, e := ComposeStartLayer(wrapper, helper, a, b)
					if e != nil {
						t.Fatal(e)
					}
					after, _ := Object(got)
					for _, field := range []string{"inbounds", "route", "dns", "log"} {
						if !bytes.Equal(encoded(before[field]), encoded(after[field])) {
							t.Fatal("changed policy", field)
						}
					}
					original := before["outbounds"].([]any)
					current := after["outbounds"].([]any)
					if len(current) != len(original)+1 {
						t.Fatal("unexpected graph size")
					}
					host := "10.77.0.1"
					if strings.Contains(api, "fd77") {
						host = "fd77:77::1"
					}
					for i, item := range original {
						expected := item.(map[string]any)
						if expected["type"] == "shadowsocks" || expected["type"] == "hysteria2" {
							expected["server"] = host
							expected["detour"] = StartLayerTag
						}
						if !bytes.Equal(encoded(expected), encoded(current[i])) {
							t.Fatal("dropped inner TLS, authentication or packet routing")
						}
					}
					outer := current[len(current)-1].(map[string]any)
					if outer["tag"] != StartLayerTag || outer["server"] != "192.0.2.1" {
						t.Fatal("outer endpoint changed")
					}
					expectedType := "shadowsocks"
					if mode == "aes-256-gcm+xor-whitening" {
						expectedType = "routervpn-aes-xor"
					}
					if outer["type"] != expectedType {
						t.Fatal("wrong native encryption engine")
					}
					fresh, _ := fixture(dns)
					if !bytes.Equal(wrapper, fresh) {
						t.Fatal("mutated original bundle")
					}
					if _, e = ComposeStartLayer(got, helper, a, b); e == nil {
						t.Fatal("duplicate wrapping accepted")
					}
				})
			}
		}
	}
}
func TestStartLayerRejectsAmbiguousSecurityAndForeignTargets(t *testing.T) {
	w, h := fixture("h3")
	a, b := startFixture("aes-256-gcm", "http://10.77.0.1:8787")
	for _, change := range []func(map[string]any){
		func(p map[string]any) { p["mode"] = "xor" }, func(p map[string]any) { p["node_kind"] = "external" }, func(p map[string]any) { p["raw_mode"] = "max" },
		func(p map[string]any) { p["router_api"] = "http://127.0.0.1:8787" }, func(p map[string]any) { p["router_api"] = "http://10.77.0.1:8787/path" }, func(p map[string]any) { p["router_api"] = "http://user@10.77.0.1:8787" }, func(p map[string]any) { p["router_api"] = "http://10.77.0.1:65536" }, func(p map[string]any) { p["router_api"] = "http://unresolved:8787" }, func(p map[string]any) { p["unused"] = true },
	} {
		p, _ := Object(b)
		change(p)
		if _, e := ComposeStartLayer(w, h, a, encoded(p)); e == nil {
			t.Fatal("invalid captured policy accepted")
		}
	}
	for _, change := range []func(map[string]any){
		func(p map[string]any) { p["server"] = "192.0.2.9" }, func(p map[string]any) { p["server"] = "127.0.0.1" }, func(p map[string]any) { p["method"] = "none" }, func(p map[string]any) { p["password"] = "secret-invalid" }, func(p map[string]any) { p["server_port"] = 1.5 }, func(p map[string]any) { p["server_port"] = true }, func(p map[string]any) { p["plugin"] = "unowned" }, func(p map[string]any) { p["detour"] = "foreign" },
	} {
		p, _ := Object(a)
		out := p["outbounds"].([]any)[0].(map[string]any)
		change(out)
		if _, e := ComposeStartLayer(w, h, encoded(p), b); e == nil {
			t.Fatal("invalid AES policy accepted")
		} else if strings.Contains(e.Error(), "secret-invalid") {
			t.Fatal("secret exposed")
		}
	}
	g, _ := Object(w)
	g["outbounds"].([]any)[1].(map[string]any)["server"] = "192.0.2.99"
	if _, e := ComposeStartLayer(encoded(g), h, a, b); e == nil {
		t.Fatal("foreign UDP service retargeted")
	}
	p, _ := Object(a)
	p["outbounds"] = append(p["outbounds"].([]any), p["outbounds"].([]any)[0])
	if _, e := ComposeStartLayer(w, h, encoded(p), b); e == nil {
		t.Fatal("ambiguous outer accepted")
	}
	if _, e := ComposeStartLayer(w, h, a, []byte(`{"mode":"aes-256-gcm","mode":"xor"}`)); e == nil {
		t.Fatal("duplicate member accepted")
	}
}
