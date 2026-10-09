package applexray

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func startBytes(v any) []byte { raw, _ := json.Marshal(v); return raw }
func startSource(layer, mode, api string) ([]byte, []byte) {
	source := map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.1", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32))}}}
	policy := map[string]string{"mode": layer, "raw_mode": mode, "node_kind": "router-vpn", "router_api": api}
	return startBytes(source), startBytes(policy)
}
func TestStartLayerPreservesNativeAuthenticationAndBothRoutes(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp", "split", "max"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, api := range []string{"http://10.77.0.1:8787", "https://[fd77:77::1]:8787"} {
				t.Run(mode+layer+api, func(t *testing.T) {
					a, b := startSource(layer, mode, api)
					raw := sampleConfig(mode)
					wrapper := wrapperFor(mode)
					normalized, e := Compile(mode, wrapper, raw)
					if e != nil {
						t.Fatal(e)
					}
					old, _ := Object(normalized)
					got, e := ComposeStartLayer(mode, wrapper, raw, a, b)
					if e != nil {
						t.Fatal(e)
					}
					next, _ := Object(got)
					for _, field := range []string{"dns", "route", "inbounds", "log"} {
						if !bytes.Equal(startBytes(old[field]), startBytes(next[field])) {
							t.Fatal("policy changed", field)
						}
					}
					wanted, _ := Object(raw)
					host := "10.77.0.1"
					if strings.Contains(api, "fd77") {
						host = "fd77:77::1"
					}
					remote(wanted)["address"] = host
					before := old["outbounds"].([]any)
					after := next["outbounds"].([]any)
					if len(after) != len(before)+1 {
						t.Fatal("extra or missing transport")
					}
					for i, item := range before {
						expected := item.(map[string]any)
						if expected["type"] == Type {
							expected["config_json"] = string(startBytes(wanted))
							expected["detour"] = StartLayerTag
						}
						if expected["type"] == "hysteria2" {
							expected["server"] = host
							expected["detour"] = StartLayerTag
						}
						if !bytes.Equal(startBytes(expected), startBytes(after[i])) {
							t.Fatal("changed protocol, TLS, PQ, flow, FinalMask, or packet routing")
						}
					}
					source, _ := Object(a)
					outer := source["outbounds"].([]any)[0].(map[string]any)
					outer["tag"] = StartLayerTag
					if layer == "aes-256-gcm+xor-whitening" {
						outer["type"] = "routervpn-aes-xor"
						outer["server_port"] = 8389
					}
					if !bytes.Equal(startBytes(outer), startBytes(after[len(after)-1])) {
						t.Fatal("changed AES authentication")
					}
					if _, e = ComposeStartLayer(mode, got, raw, a, b); e == nil {
						t.Fatal("duplicate encapsulation accepted")
					}
					if !bytes.Equal(raw, sampleConfig(mode)) {
						t.Fatal("source secret/profile modified")
					}
					if _, e = Prepare(mode, []byte(after[0].(map[string]any)["config_json"].(string))); e != nil {
						t.Fatal("native binding rejects composed endpoint", e)
					}
				})
			}
		}
	}
}
func TestStartLayerRejectsForeignMetadataAndDowngrades(t *testing.T) {
	mode := "max"
	a, b := startSource("aes-256-gcm", mode, "http://10.77.0.1:8787")
	raw := sampleConfig(mode)
	wrapper := wrapperFor(mode)
	for _, change := range []func(map[string]any){
		func(p map[string]any) { p["mode"] = "xor" }, func(p map[string]any) { p["mode"] = true }, func(p map[string]any) { p["raw_mode"] = "split" }, func(p map[string]any) { p["node_kind"] = "external" }, func(p map[string]any) { p["extra"] = true },
		func(p map[string]any) { p["router_api"] = "http://127.0.0.1:8787" }, func(p map[string]any) { p["router_api"] = "http://8.8.8.8:8787" }, func(p map[string]any) { p["router_api"] = "http://unknown:8787" }, func(p map[string]any) { p["router_api"] = "http://10.77.0.1:70000" }, func(p map[string]any) { p["router_api"] = "http://u@10.77.0.1:8787" }, func(p map[string]any) { p["router_api"] = "http://10.77.0.1:8787/wrong" }, func(p map[string]any) { p["router_api"] = "http://[fe80::1%25eth0]:8787" },
	} {
		p, _ := Object(b)
		change(p)
		if _, e := ComposeStartLayer(mode, wrapper, raw, a, startBytes(p)); e == nil {
			t.Fatal("unsafe policy accepted")
		}
	}
	for _, change := range []func(map[string]any){
		func(p map[string]any) { p["server"] = "192.0.2.99" }, func(p map[string]any) { p["server"] = "127.0.0.1" }, func(p map[string]any) { p["password"] = "not-a-secret-key" }, func(p map[string]any) { p["method"] = "none" }, func(p map[string]any) { p["server_port"] = 1.5 }, func(p map[string]any) { p["server_port"] = true }, func(p map[string]any) { p["plugin"] = "hidden" }, func(p map[string]any) { p["detour"] = "escape" },
	} {
		p, _ := Object(a)
		change(p["outbounds"].([]any)[0].(map[string]any))
		_, e := ComposeStartLayer(mode, wrapper, raw, startBytes(p), b)
		if e == nil {
			t.Fatal("unsafe AES input accepted")
		}
		if strings.Contains(e.Error(), "not-a-secret-key") {
			t.Fatal("secret exposed in diagnostic")
		}
	}
	g, _ := Object(wrapper)
	g["outbounds"].([]any)[2].(map[string]any)["server"] = "192.0.2.99"
	if _, e := ComposeStartLayer(mode, startBytes(g), raw, a, b); e == nil {
		t.Fatal("foreign UDP node moved")
	}
	p, _ := Object(raw)
	remote(p)["users"].([]any)[0].(map[string]any)["encryption"] = "none"
	if _, e := ComposeStartLayer(mode, wrapper, startBytes(p), a, b); e == nil {
		t.Fatal("PQ promise downgraded")
	}
	if _, e := ComposeStartLayer(mode, wrapper, raw, a, []byte(`{"mode":"xor","mode":"aes-256-gcm"}`)); e == nil {
		t.Fatal("duplicate field accepted")
	}
}
func TestStartLayerHostnamesRemainOnTheOwnedOuterPath(t *testing.T) {
	mode := "split"
	a, b := startSource("aes-256-gcm", mode, "http://10.77.0.1:8787")
	raw, _ := Object(sampleConfig(mode))
	remote(raw)["address"] = "node.example.test"
	source, _ := Object(a)
	source["outbounds"].([]any)[0].(map[string]any)["server"] = "NODE.EXAMPLE.TEST."
	wrapper, _ := Object(wrapperFor(mode))
	wrapper["outbounds"].([]any)[2].(map[string]any)["server"] = "node.example.test"
	compiled, e := ComposeStartLayer(mode, startBytes(wrapper), startBytes(raw), startBytes(source), b)
	if e != nil {
		t.Fatal(e)
	}
	graph, _ := Object(compiled)
	outs := graph["outbounds"].([]any)
	if outs[len(outs)-1].(map[string]any)["server"] != "NODE.EXAMPLE.TEST." {
		t.Fatal("outer hostname replaced by guessed address")
	}
	inner, _ := Object([]byte(outs[0].(map[string]any)["config_json"].(string)))
	if remote(inner)["address"] != "10.77.0.1" {
		t.Fatal("inner native path did not freeze private service")
	}
}
