package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

func exitLayerFixture(t *testing.T, entryMode, exitMode, entryLayer, exitLayer, execution string) (string, string, string, string) {
	t.Helper()
	config, metadata, entrySource, _ := entryLayerFixture(t, entryMode, "aes-256-gcm", execution)
	graph := startObject(t, config)
	meta := startObject(t, metadata)
	if entryLayer == "" {
		entrySource = ""
	} else {
		source := startObject(t, entrySource)
		source["mode"] = entryLayer
		entrySource = startJSON(t, source)
		meta["entry_start_layer"] = entryLayer
	}
	var exit map[string]any
	if awgpolicy.WireGuardFamily(exitMode) {
		text, _, _ := baseStartFixture(t, exitMode, "aes-256-gcm", "http://10.88.0.1:8787")
		exit = startObject(t, text)["endpoints"].([]any)[0].(map[string]any)
	} else if XrayEntryMode(exitMode) {
		exit = xrayEntryObject(t, exitMode)
	} else {
		exit = proxyEntry(t, exitMode)
	}
	exit["tag"] = "proxy"
	if e := rewriteEntryStartHost(exit, exitMode, "192.0.2.77"); e != nil {
		t.Fatal(e)
	}
	exit["detour"] = "entry-wg"
	for _, kind := range []string{"outbounds", "endpoints"} {
		values, _ := graph[kind].([]any)
		filtered := []any{}
		for _, raw := range values {
			if raw.(map[string]any)["tag"] != "proxy" {
				filtered = append(filtered, raw)
			}
		}
		graph[kind] = filtered
	}
	field := "outbounds"
	if awgpolicy.WireGuardFamily(exitMode) {
		field = "endpoints"
	}
	graph[field] = append(graph[field].([]any), exit)
	meta["exit_mode"] = exitMode
	meta["exit_start_layer"] = exitLayer
	aes := proxyEntryGraph("shadowsocks")
	outer := aes["outbounds"].([]any)[0].(map[string]any)
	outer["server"] = "192.0.2.77"
	outer["server_port"] = 8388
	outer["method"] = NativeStartLayerMethod
	outer["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	var profile map[string]string
	json.Unmarshal([]byte(proxyEntryProfile(t, aes, "")), &profile)
	return startJSON(t, graph), startJSON(t, meta), entrySource, startJSON(t, EntryStartLayer{Mode: exitLayer, Profile: profile})
}
func TestBothStartLayersPreserveAllNativeExitOwners(t *testing.T) {
	modes := []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp"}
	for _, entryMode := range modes {
		for _, exitMode := range modes {
			for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, execution := range []string{"local", "server", "auto"} {
					config, meta, entry, exit := exitLayerFixture(t, entryMode, exitMode, layer, layer, execution)
					c, e := NewWithStartLayers(config, meta, entry, exit)
					if e != nil {
						t.Fatalf("%s %s %s %s: %v", entryMode, exitMode, layer, execution, e)
					}
					before := startObject(t, config)
					after := startObject(t, c.Config())
					for _, field := range []string{"inbounds", "dns", "route"} {
						if startJSON(t, before[field]) != startJSON(t, after[field]) {
							t.Fatal("dropped node/route/DNS policy", field)
						}
					}
					local := graphEntry(t, after, LocalTag)
					outer := graphEntry(t, after, multihoprelay.ExitStartLayerTag)
					if local["detour"] != multihoprelay.ExitStartLayerTag || outer["detour"] != "entry-wg" || outer["server"] != "192.0.2.77" {
						t.Fatal("local exit layer escaped captured entry")
					}
					if graphEntry(t, after, ServerTag)["detour"] != "entry-wg" || graphEntry(t, after, "entry-wg")["detour"] != EntryStartLayerTag || graphEntry(t, after, EntryStartLayerTag)["detour"] != nil {
						t.Fatal("entry/server proof or physical path changed")
					}
					expected := startObject(t, startJSON(t, graphEntry(t, before, "proxy")))
					delete(expected, "detour")
					expected["tag"] = LocalTag
					if e = rewriteEntryStartHost(expected, exitMode, "10.88.0.1"); e != nil {
						t.Fatal(e)
					}
					expected["detour"] = multihoprelay.ExitStartLayerTag
					if startJSON(t, expected) != startJSON(t, local) {
						t.Fatal("changed original native exit keys, TLS, PQ or MTU")
					}
					if c.meta.ExitStartLayer != layer || c.proposal.ExitStartLayer != layer || c.expected.Request != c.proposal {
						t.Fatal("server lease can silently omit requested layer")
					}
					if strings.Contains(c.ProgressJSON(), outer["password"].(string)) || strings.Contains(c.ProgressJSON(), "private-token") {
						t.Fatal("private layer source leaked")
					}
					if e = c.Close(); e != nil {
						t.Fatal(e)
					}
				}
			}
		}
	}
}
func TestExitLayerCannotBeMissingMismatchedOrPreowned(t *testing.T) {
	config, meta, entry, exit := exitLayerFixture(t, "wg", "reality-pq-vision", "aes-256-gcm", "aes-256-gcm", "auto")
	for _, bad := range []string{"", "{}", exit + "{}", strings.Repeat("x", 16385), strings.Replace(exit, "aes-256-gcm", "aes-256-gcm+xor-whitening", 1)} {
		if c, e := NewWithStartLayers(config, meta, entry, bad); e == nil || c != nil {
			t.Fatal("omitted/changed source silently selected raw exit")
		}
	}
	unrequested := startObject(t, meta)
	delete(unrequested, "exit_start_layer")
	if c, e := NewWithStartLayers(config, startJSON(t, unrequested), entry, exit); e == nil || c != nil {
		t.Fatal("unrequested extra encryption activated")
	}
	for _, operation := range []func() (*Controller, error){func() (*Controller, error) { return New(config, meta) }, func() (*Controller, error) { return NewWithEntryStartLayer(config, meta, entry) }} {
		if c, e := operation(); e == nil || c != nil {
			t.Fatal("old factory dropped required exit layer")
		}
	}
	graph := startObject(t, config)
	graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": multihoprelay.ExitStartLayerTag})
	if c, e := NewWithStartLayers(startJSON(t, graph), meta, entry, exit); e == nil || c != nil {
		t.Fatal("foreign tagged owner overwritten")
	}
	source := startObject(t, exit)
	profile := source["profile"].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(profile["sing-box.json"].(string))
	g := startObject(t, string(raw))
	g["outbounds"].([]any)[0].(map[string]any)["server"] = "192.0.2.99"
	profile["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, g)))
	if c, e := NewWithStartLayers(config, meta, entry, startJSON(t, source)); e == nil || c != nil {
		t.Fatal("exit AES belongs to foreign node")
	}
}
func TestExitLayerExecutionRejectsRawServerAndRetainsSessionLifecycle(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = previous }()
	for _, execution := range []string{"local", "server", "auto"} {
		for _, entryLayer := range []string{"", "aes-256-gcm+xor-whitening"} {
			config, meta, entry, exit := exitLayerFixture(t, "shadowsocks", "shadowsocks", entryLayer, "aes-256-gcm", execution)
			c, e := NewWithStartLayers(config, meta, entry, exit)
			if e != nil {
				t.Fatal(e)
			}
			engine := makeEngine(t)
			engine.exitLayer = "aes-256-gcm"
			if e = c.Run(context.Background(), engine); e != nil {
				t.Fatal(execution, e)
			}
			if execution != "local" && (engine.lease == nil || engine.lease.ExitStartLayer != "aes-256-gcm") {
				t.Fatal("server did not retain exact encryption in lease")
			}
			if e = c.Close(); e != nil || engine.lease != nil || engine.secretLeak || len(engine.errors) != 0 {
				t.Fatal("layered owner did not release private lease", e)
			}
		}
	}
	for _, execution := range []string{"server", "auto"} {
		config, meta, entry, exit := exitLayerFixture(t, "shadowsocks", "shadowsocks", "", "aes-256-gcm", execution)
		c, e := NewWithStartLayers(config, meta, entry, exit)
		if e != nil {
			t.Fatal(e)
		}
		engine := makeEngine(t)
		engine.badLocal = true // Neither raw server nor failed local may win.
		if e = c.Run(context.Background(), engine); e == nil || engine.lease != nil {
			t.Fatal("requested encrypted exit fell back to unlayered server")
		}
		_ = c.Close()
	}
}
