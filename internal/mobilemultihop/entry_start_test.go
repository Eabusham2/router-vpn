package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"router-vpn/internal/awgpolicy"
	"strings"
	"testing"
)

func entryLayerFixture(t *testing.T, mode, layer, execution string) (string, string, string, map[string]any) {
	t.Helper()
	config, metadata := fixture(t, execution)
	graph := startObject(t, config)
	meta := startObject(t, metadata)
	meta["entry_mode"] = mode
	var entry map[string]any
	if awgpolicy.WireGuardFamily(mode) {
		single, _, _ := baseStartFixture(t, mode, layer, "http://10.77.0.1:8787")
		entry = startObject(t, single)["endpoints"].([]any)[0].(map[string]any)
	} else if XrayEntryMode(mode) {
		entry = xrayEntryObject(t, mode)
	} else {
		entry = proxyEntry(t, mode)
	}
	entry["tag"] = "entry-wg"
	if awgpolicy.WireGuardFamily(mode) {
		graph["endpoints"] = []any{entry}
	} else {
		graph["endpoints"] = []any{}
		graph["outbounds"] = append(graph["outbounds"].([]any), entry)
	}
	host, err := entryStartHost(entry, mode)
	if err != nil {
		t.Fatal(err)
	}
	outer := proxyEntryGraph("shadowsocks")
	transport := outer["outbounds"].([]any)[0].(map[string]any)
	transport["server"] = host
	transport["method"] = NativeStartLayerMethod
	transport["server_port"] = 8388
	transport["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	var profile map[string]string
	json.Unmarshal([]byte(proxyEntryProfile(t, outer, "")), &profile)
	source := startJSON(t, EntryStartLayer{Mode: layer, Profile: profile})
	return startJSON(t, graph), startJSON(t, meta), source, entry
}
func graphEntry(t *testing.T, g map[string]any, tag string) map[string]any {
	t.Helper()
	for _, field := range []string{"endpoints", "outbounds"} {
		for _, raw := range g[field].([]any) {
			value := raw.(map[string]any)
			if value["tag"] == tag {
				return value
			}
		}
	}
	t.Fatal("missing tag", tag)
	return nil
}
func TestEntryStartLayerPreservesAllNativeModesAndChoicePaths(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, execution := range []string{"local", "server", "auto"} {
				t.Run(mode+layer+execution, func(t *testing.T) {
					config, meta, source, original := entryLayerFixture(t, mode, layer, execution)
					before := startObject(t, config)
					snapshot := startJSON(t, original)
					controller, err := NewWithEntryStartLayer(config, meta, source)
					if err != nil {
						t.Fatal(err)
					}
					defer controller.Close()
					after := startObject(t, controller.Config())
					for _, key := range []string{"dns", "inbounds", "route"} {
						if startJSON(t, before[key]) != startJSON(t, after[key]) {
							t.Fatal("changed client policy", key)
						}
					}
					entry := graphEntry(t, after, "entry-wg")
					outer := graphEntry(t, after, EntryStartLayerTag)
					if entry["detour"] != EntryStartLayerTag || outer["detour"] != nil {
						t.Fatal("entry physical transport escaped or became circular")
					}
					host, err := entryStartHost(entryWithoutLayer(entry), mode)
					if err != nil || host != "10.77.0.1" {
						t.Fatal("inner node service was not routed through AES", err)
					}
					originalHost, _ := entryStartHost(original, mode)
					if outer["server"] != originalHost || outer["password"] != base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))) {
						t.Fatal("outer node or credential changed")
					}
					if layer == "aes-256-gcm" {
						if outer["type"] != "shadowsocks" || outer["server_port"] != float64(8388) {
							t.Fatal("wrong AES transport")
						}
					} else if outer["type"] != "routervpn-aes-xor" || outer["server_port"] != float64(8389) {
						t.Fatal("wrong AES/XOR native transport")
					}
					expected := startObject(t, snapshot)
					if err = rewriteEntryStartHost(expected, mode, "10.77.0.1"); err != nil {
						t.Fatal(err)
					}
					expected["detour"] = EntryStartLayerTag
					if startJSON(t, entry) != startJSON(t, expected) {
						t.Fatal("inner keys, MTU, TLS or PQ policy changed")
					}
					for _, tag := range []string{LocalTag, ServerTag} {
						if graphEntry(t, after, tag)["detour"] != "entry-wg" {
							t.Fatal("candidate stopped traversing captured entry")
						}
					}
					if startJSON(t, original) != snapshot {
						t.Fatal("input profile was mutated")
					}
					if strings.Contains(controller.ProgressJSON(), "private-token") || strings.Contains(controller.ProgressJSON(), outer["password"].(string)) {
						t.Fatal("public progress exposed source credentials")
					}
				})
			}
		}
	}
}
func entryWithoutLayer(entry map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range entry {
		if k != "detour" {
			out[k] = v
		}
	}
	return out
}
func TestEntryStartLayerRejectsMismatchedOrAmbiguousSource(t *testing.T) {
	config, meta, source, _ := entryLayerFixture(t, "wg", "aes-256-gcm", "auto")
	for _, bad := range []string{source + "{}", `{"mode":"aes-256-gcm","mode":"xor"}`, `{"mode":true,"profile":{}}`, strings.Repeat(" ", 16385)} {
		if c, e := NewWithEntryStartLayer(config, meta, bad); e == nil || c != nil {
			t.Fatal("ambiguous entry source accepted")
		}
	}
	for _, mode := range []string{"xor", "off", "", "unknown"} {
		s := startObject(t, source)
		s["mode"] = mode
		if c, e := NewWithEntryStartLayer(config, meta, startJSON(t, s)); e == nil || c != nil {
			t.Fatal("unrequested or plaintext entry layer accepted")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(out map[string]any) { out["server"] = "192.0.2.99" }, func(out map[string]any) { out["server"] = "entry.example.test" },
		func(out map[string]any) { out["password"] = "must-not-leak" }, func(out map[string]any) { out["method"] = "aes-128-gcm" },
		func(out map[string]any) { out["detour"] = "other" }, func(out map[string]any) { out["network"] = "tcp" }, func(out map[string]any) { out["plugin"] = "other" },
	} {
		s := startObject(t, source)
		profile := s["profile"].(map[string]any)
		raw, _ := base64.StdEncoding.DecodeString(profile["sing-box.json"].(string))
		g := startObject(t, string(raw))
		mutate(g["outbounds"].([]any)[0].(map[string]any))
		profile["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, g)))
		c, e := NewWithEntryStartLayer(config, meta, startJSON(t, s))
		if e == nil || c != nil || strings.Contains(e.Error(), "must-not-leak") {
			t.Fatal("invalid credential or transport accepted/leaked")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["detour"] = "other" },
		func(g map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"tag": EntryStartLayerTag, "type": "direct"})
		},
	} {
		g := startObject(t, config)
		mutate(g)
		if c, e := NewWithEntryStartLayer(startJSON(t, g), meta, source); e == nil || c != nil {
			t.Fatal("existing transport owner overwritten")
		}
	}
}
func TestEntryLayerLeavesExecutionLifecycleOwned(t *testing.T) {
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	for _, execution := range []string{"local", "server", "auto"} {
		config, meta, source, _ := entryLayerFixture(t, "hysteria2", "aes-256-gcm+xor-whitening", execution)
		c, e := NewWithEntryStartLayer(config, meta, source)
		if e != nil {
			t.Fatal(e)
		}
		engine := makeEngine(t)
		if e = c.Run(context.Background(), engine); e != nil {
			t.Fatal(e)
		}
		if e = c.Close(); e != nil {
			t.Fatal(e)
		}
		if engine.lease != nil || engine.secretLeak || len(engine.errors) != 0 {
			t.Fatal("entry layer changed lease or cancellation ownership")
		}
	}
}

func TestEntryStartLayerCannotDisappearOrChangeAfterCapture(t *testing.T) {
	config, meta, source, _ := entryLayerFixture(t, "wg", "aes-256-gcm", "local")
	captured := startObject(t, meta)
	captured["entry_start_layer"] = "aes-256-gcm"
	for _, missing := range []string{"", `{"mode":"aes-256-gcm+xor-whitening","profile":{}}`} {
		if c, e := NewWithEntryStartLayer(config, startJSON(t, captured), missing); e == nil || c != nil {
			t.Fatal("requested layer was omitted or changed")
		}
	}
	if c, e := New(config, startJSON(t, captured)); e == nil || c != nil {
		t.Fatal("ordinary controller silently omitted entry layer")
	}
	c, e := NewWithEntryStartLayer(config, startJSON(t, captured), source)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if c.meta.EntryStartLayer != "aes-256-gcm" {
		t.Fatal("captured layer forgotten")
	}
	captured["entry_start_layer"] = "aes-256-gcm+xor-whitening"
	if c, e := NewWithEntryStartLayer(config, startJSON(t, captured), source); e == nil || c != nil {
		t.Fatal("captured layer was downgraded")
	}
}
