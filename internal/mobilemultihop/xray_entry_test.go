package mobilemultihop

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func xrayEntryFixture(t *testing.T, mode string) (string, map[string]any) {
	t.Helper()
	key, e := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("e", 32)))
	if e != nil {
		t.Fatal(e)
	}
	user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
	stream := map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "entry.example.test", "fingerprint": "chrome", "password": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "0123456789abcdef"}}
	if mode != "reality-vision" {
		user["encryption"] = "mlkem768x25519plus.native.0rtt.private-entry-pq-fixture"
	}
	if mode == "reality-xhttp" {
		delete(user, "flow")
		stream["network"] = "xhttp"
		stream["xhttpSettings"] = map[string]any{"path": "/entry/authenticated", "mode": "auto"}
		stream["finalmask"] = map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "100-300", "delay": "10-30", "maxSplit": "3-7"}}}}
	}
	raw := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"protocol": "socks", "listen": "127.0.0.1", "port": 1090, "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": "vless", "tag": "proxy", "settings": map[string]any{"vnext": []any{map[string]any{"address": "192.0.2.44", "port": 443, "users": []any{user}}}}, "streamSettings": stream}}}
	wrapper := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1090, "version": "5"}, map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "proxy", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}}}
	encode := func(v any) string {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	files := map[string]string{"xray.json": encode(raw), "sing-box.json": encode(wrapper)}
	out, e := json.Marshal(files)
	if e != nil {
		t.Fatal(e)
	}
	return string(out), raw
}
func xrayEntryObject(t *testing.T, mode string) map[string]any {
	t.Helper()
	profile, _ := xrayEntryFixture(t, mode)
	compiled, e := CompileProxyEntry(profile, mode)
	if e != nil {
		t.Fatal(e)
	}
	var entry map[string]any
	if json.Unmarshal([]byte(compiled), &entry) != nil {
		t.Fatal("bad native JSON")
	}
	return entry
}
func TestXrayEntryPreservesFullNativeProtocolAndNoHelper(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		t.Run(mode, func(t *testing.T) {
			profile, original := xrayEntryFixture(t, mode)
			got, e := CompileProxyEntry(profile, mode)
			if e != nil {
				t.Fatal(e)
			}
			var entry map[string]any
			json.Unmarshal([]byte(got), &entry)
			if len(entry) != 4 || entry["type"] != "routervpn-xray" || entry["tag"] != "routervpn-hop-entry" || entry["mode"] != mode {
				t.Fatal("wrong native owner or extra helper")
			}
			var files map[string]string
			json.Unmarshal([]byte(profile), &files)
			raw, _ := base64.StdEncoding.DecodeString(files["xray.json"])
			if entry["config_json"] != string(raw) {
				t.Fatal("changed peer keys, PQ settings, Vision, XHTTP or FinalMask")
			}
			var decoded map[string]any
			json.Unmarshal(raw, &decoded)
			beforeJSON, _ := json.Marshal(original)
			decodedJSON, _ := json.Marshal(decoded)
			if string(beforeJSON) != string(decodedJSON) {
				t.Fatal("input not preserved")
			}
			if again, e := CompileProxyEntry(profile, mode); e != nil || again != got {
				t.Fatal("nondeterministic entry compiler")
			}
			if mode == "reality-xhttp" {
				delete(files, "sing-box.json")
				bytes, _ := json.Marshal(files)
				if _, e = CompileProxyEntry(string(bytes), mode); e != nil {
					t.Fatal("exact legacy raw XHTTP was rejected", e)
				}
			}
		})
	}
	if ProxyEntryMode("split") || ProxyEntryMode("max") {
		t.Fatal("dual-transport selected mode silently collapsed")
	}
}
func TestXrayEntryRejectsForeignPolicyBeforeStaging(t *testing.T) {
	profile, _ := xrayEntryFixture(t, "reality-pq-vision")
	var files map[string]string
	json.Unmarshal([]byte(profile), &files)
	change := func(name string, mutate func(map[string]any)) string {
		copy := map[string]string{}
		for k, v := range files {
			copy[k] = v
		}
		bytes, _ := base64.StdEncoding.DecodeString(copy[name])
		var v map[string]any
		json.Unmarshal(bytes, &v)
		mutate(v)
		bytes, _ = json.Marshal(v)
		copy[name] = base64.StdEncoding.EncodeToString(bytes)
		bytes, _ = json.Marshal(copy)
		return string(bytes)
	}
	for _, mutate := range []func(map[string]any){
		func(g map[string]any) {
			g["route"].(map[string]any)["rules"] = []any{map[string]any{"network": "tcp", "outbound": "direct"}}
		},
		func(g map[string]any) { g["route"].(map[string]any)["rule_set"] = []any{} },
		func(g map[string]any) {
			g["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"] = []any{"0.0.0.0/0"}
		},
		func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["include_package"] = []any{} },
		func(g map[string]any) { g["outbounds"] = append(g["outbounds"].([]any), g["outbounds"].([]any)[0]) },
	} {
		if _, e := CompileProxyEntry(change("sing-box.json", mutate), "reality-pq-vision"); e == nil {
			t.Fatal("discarded bypass/routing policy")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(g map[string]any) {
			g["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["security"] = "none"
		},
		func(g map[string]any) {
			g["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["encryption"] = "none"
		},
		func(g map[string]any) {
			g["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = "entry.example.test"
		},
		func(g map[string]any) {
			g["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = "127.0.0.1"
		},
		func(g map[string]any) { g["dns"] = map[string]any{} },
	} {
		if _, e := CompileProxyEntry(change("xray.json", mutate), "reality-pq-vision"); e == nil {
			t.Fatal("native authentication/routing weakened")
		}
	}
	for _, name := range []string{"extra.conf", "cert.pem", "../xray.json", "stack.json"} {
		copy := map[string]string{}
		for k, v := range files {
			copy[k] = v
		}
		copy[name] = base64.StdEncoding.EncodeToString([]byte("unowned"))
		b, _ := json.Marshal(copy)
		if _, e := CompileProxyEntry(string(b), "reality-pq-vision"); e == nil {
			t.Fatal("unowned helper discarded")
		}
	}
	for _, bad := range []string{profile + "{}", `{"xray.json":"AAAA","xray.json":"BBBB"}`} {
		if _, e := CompileProxyEntry(bad, "reality-pq-vision"); e == nil {
			t.Fatal("ambiguous source accepted")
		}
	}
	entry := xrayEntryObject(t, "reality-pq-vision")
	for _, field := range []string{"detour", "bind_interface", "network", "domain_resolver", "mtu", "server"} {
		entry[field] = "unowned"
		if e := validateProxyEntry(entry, "reality-pq-vision"); e == nil {
			t.Fatal("pre-existing dial policy overwritten")
		}
		delete(entry, field)
	}
	if e := validateProxyEntry(entry, "reality-vision"); e == nil {
		t.Fatal("PQ mode relabeled")
	}
}
func TestXrayEntryRetainsLocalServerAutoAndMTUOwnership(t *testing.T) {
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, execution := range []string{"local", "server", "auto"} {
			cfg, meta := fixture(t, execution)
			var g map[string]any
			json.Unmarshal([]byte(cfg), &g)
			delete(g, "endpoints")
			entry := xrayEntryObject(t, mode)
			entry["tag"] = "entry-wg"
			g["outbounds"] = append(g["outbounds"].([]any), entry)
			var m Metadata
			json.Unmarshal([]byte(meta), &m)
			m.EntryMode = mode
			b, _ := json.Marshal(g)
			p, _ := json.Marshal(m)
			controller, e := New(string(b), string(p))
			if e != nil {
				t.Fatal(mode, execution, e)
			}
			engine := makeEngine(t)
			if e = controller.Run(context.Background(), engine); e != nil {
				t.Fatal(mode, execution, e)
			}
			if e = controller.Close(); e != nil {
				t.Fatal(e)
			}
			if engine.lease != nil || engine.secretLeak || len(engine.errors) != 0 {
				t.Fatal("lease/proof/credential ownership changed")
			}
			var after map[string]any
			json.Unmarshal([]byte(controller.Config()), &after)
			for _, raw := range after["outbounds"].([]any) {
				v := raw.(map[string]any)
				if v["tag"] == entry["tag"] && !reflect.DeepEqual(v, entry) {
					t.Fatal("comparison rewrote entry")
				}
			}
			g["endpoints"] = []any{entry}
			g["outbounds"] = g["outbounds"].([]any)[:1]
			b, _ = json.Marshal(g)
			if _, e = New(string(b), string(p)); e == nil {
				t.Fatal("native proxy in packet endpoint manager accepted")
			}
		}
	}
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, packet := range []bool{false, true} {
			text := proxyMTUGraph(t, "shadowsocks", "entry-wg", packet)
			var g map[string]any
			json.Unmarshal([]byte(text), &g)
			entry := xrayEntryObject(t, mode)
			entry["tag"] = "entry-wg"
			g["outbounds"].([]any)[0] = entry
			b, _ := json.Marshal(g)
			fixed := `{"entry":{"mtu_policy":"fixed","manual_mtu":1380},"exit":{"mtu_policy":"auto"}}`
			result, e := ApplyMTUPolicy(string(b), fixed)
			if e != nil {
				t.Fatal(e)
			}
			var v map[string]any
			json.Unmarshal([]byte(result), &v)
			if v["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1380) {
				t.Fatal("fixed proxy MTU ignored")
			}
			if !reflect.DeepEqual(v["outbounds"].([]any)[0], entry) {
				t.Fatal("invented entry packet envelope")
			}
			if _, e = MultihopMTUProfile(string(b), fixed); e != nil {
				t.Fatal(e)
			}
		}
	}
}
