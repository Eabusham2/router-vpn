package mobilemultihop

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/nativecomposite"
)

func compositeHopSource(t *testing.T, mode, node, layer, api string) string {
	t.Helper()
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	helperPort, helperName := 1090, "xray.json"
	user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
	if mode == "max" {
		user["encryption"] = "mlkem768x25519plus.native.0rtt.public-fixture-key"
	}
	helper := map[string]any{"inbounds": []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": helperPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "192.0.2.44", "port": 10443, "users": []any{user}}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "entry.example", "fingerprint": "chrome", "password": "public-fixture-key", "shortId": "0123456789abcdef"}}}}}
	if mode == "ss-v2ray" {
		helperPort, helperName = 1092, "sslocal.json"
		helper = map[string]any{"server": "192.0.2.44", "server_port": 10443, "password": key, "method": "2022-blake3-aes-256-gcm", "local_address": "127.0.0.1", "local_port": helperPort, "mode": "tcp_only", "plugin": "v2ray-plugin", "plugin_opts": "tls;host=entry.example;path=/shadowsocks"}
	}
	graph := map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true, "mtu": 1280}},
		"outbounds": []any{map[string]any{"type": "socks", "tag": "tcp-stack", "server": "127.0.0.1", "server_port": helperPort, "version": "5"}, map[string]any{"type": "hysteria2", "tag": "udp-stack", "server": "192.0.2.44", "server_port": 8443, "password": "captured-hysteria-credential", "obfs": map[string]any{"type": "salamander", "password": "captured-mask"}, "tls": map[string]any{"enabled": true, "server_name": "entry.example", "certificate_path": "cert.pem"}}},
		"route":     map[string]any{"rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"network": "tcp", "action": "route", "outbound": "tcp-stack"}, map[string]any{"network": "udp", "action": "route", "outbound": "udp-stack"}}, "final": "tcp-stack"},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "selected", "server": "10.77.0.1", "detour": "tcp-stack"}}, "final": "selected"},
	}
	files := map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph))), helperName: base64.StdEncoding.EncodeToString([]byte(startJSON(t, helper))), "cert.pem": base64.StdEncoding.EncodeToString([]byte(entryCertificate(t)))}
	policy := map[string]any{"node_id": node, "node_kind": "router-vpn", "router_api": api, "start_layer": layer}
	start := ""
	if layer != "" {
		outer := map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.44", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": key}}}
		start = startJSON(t, map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString([]byte(startJSON(t, outer)))})
	}
	compiled, err := CompileCompositeProfile(mode, startJSON(t, files), startJSON(t, policy), start)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// MAX and paired-proxy composites coexist, while their independent source
// ownership checks and Start Layers remain in the shipping composition path.
func compositeFixture(t *testing.T, entry, exit, el, xl, execution string) (string, string, string, string, string, string) {
	t.Helper()
	e, x, a, b := entry, exit, el, xl
	if CompositeMode(entry) {
		e, a = "shadowsocks", ""
	}
	if CompositeMode(exit) {
		x, b = "shadowsocks", ""
	}
	config, metadata, maxEntry, maxExit, entryStart, exitStart := maxCompositeFixture(t, e, x, a, b, execution)
	if xl == "" {
		exitStart = ""
	}
	g, m := startObject(t, config), startObject(t, metadata)
	entrySource, exitSource := "", ""
	for _, isEntry := range []bool{true, false} {
		mode, layer, side, tag := exit, xl, "exit", "proxy"
		if isEntry {
			mode, layer, side, tag = entry, el, "entry", "entry-wg"
		}
		if !CompositeMode(mode) {
			continue
		}
		node, api := m[side+"_node_id"].(string), m[side+"_api"].(string)
		source := compositeHopSource(t, mode, node, layer, api)
		base, err := CompositeMultihopBase(source, mode, node, layer)
		if err != nil {
			t.Fatal(err)
		}
		value := startObject(t, base)["outbounds"].([]any)[0].(map[string]any)
		value["tag"] = tag
		if !isEntry {
			value["detour"] = "entry-wg"
		}
		values := g["outbounds"].([]any)
		found := false
		for i, raw := range values {
			if raw.(map[string]any)["tag"] == tag {
				values[i], found = value, true
			}
		}
		if !found {
			t.Fatal("fixture lost composite outbound slot")
		}
		m[side+"_mode"], m[side+"_start_layer"] = mode, layer
		if isEntry {
			entrySource, entryStart = source, ""
		} else {
			exitSource, exitStart = source, ""
		}
	}
	config, metadata = startJSON(t, g), startJSON(t, m)
	if MAXMode(entry) || MAXMode(exit) {
		var err error
		config, err = ComposeMAXMultihop(config, metadata, maxEntry, maxExit)
		if err != nil {
			t.Fatal(err)
		}
	}
	return config, metadata, entrySource, exitSource, entryStart, exitStart
}

func TestCompositeMultihopPreservesBothLanesAcrossEveryNativeFamily(t *testing.T) {
	modes := []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "ss-v2ray", "split", "max"}
	layers := [][2]string{{"", ""}, {"aes-256-gcm", "aes-256-gcm+xor-whitening"}, {"aes-256-gcm+xor-whitening", "aes-256-gcm"}}
	count := 0
	for _, entry := range modes {
		for _, exit := range modes {
			if !CompositeMode(entry) && !CompositeMode(exit) {
				continue
			}
			for _, layer := range layers {
				for _, execution := range []string{"local", "server", "auto"} {
					t.Run(entry+"/"+exit+"/"+layer[0]+"/"+layer[1]+"/"+execution, func(t *testing.T) {
						input, meta, a, b, al, bl := compositeFixture(t, entry, exit, layer[0], layer[1], execution)
						if c, err := New(input, meta); err == nil {
							c.Close()
							t.Fatal("unresolved construction placeholder was runnable")
						}
						complete, err := ComposeCompositeMultihop(input, meta, a, b)
						if err != nil {
							t.Fatal(err)
						}
						if _, err = ComposeCompositeMultihop(complete, meta, a, b); err == nil {
							t.Fatal("complete graph adopted a second owner")
						}
						before, original := startObject(t, complete), startObject(t, input)
						for _, field := range []string{"inbounds", "dns", "route"} {
							if !reflect.DeepEqual(before[field], original[field]) {
								t.Fatal("captured device policy changed", field)
							}
						}
						profiles := `{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`
						if ProxyEntryMode(entry) || CompositeMode(entry) {
							profiles = `{"entry":{"mtu_policy":"fixed","manual_mtu":1280},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`
						}
						sized, err := ApplyMTUPolicy(complete, profiles)
						if err != nil {
							t.Fatal(err)
						}
						c, err := NewWithStartLayers(sized, meta, al, bl)
						if err != nil {
							t.Fatal(err)
						}
						defer c.Close()
						after := startObject(t, c.Config())
						if c.Healthy() || c.meta.EntryMode != entry || c.meta.ExitMode != exit || c.candidate("local").Transport != exit || c.proposal.ExitStartLayer != layer[1] {
							t.Fatal("prepared graph weakened mode, layer or proof state")
						}
						if graphEntry(t, after, ServerTag)["detour"] != "entry-wg" {
							t.Fatal("server candidate bypassed captured entry")
						}
						for _, isEntry := range []bool{true, false} {
							mode, node, layerMode, root, prefix, via, source := exit, c.meta.ExitNodeID, layer[1], LocalTag, CompositeExitPrefix, "entry-wg", b
							if isEntry {
								mode, node, layerMode, root, prefix, via, source = entry, c.meta.EntryNodeID, layer[0], "entry-wg", CompositeEntryPrefix, "", a
							}
							if !CompositeMode(mode) {
								continue
							}
							actual, err := nativecomposite.Extract(after, mode, node, layerMode, root, prefix, via)
							captured, sourceErr := nativecomposite.Plan(source, mode, node, layerMode)
							if err != nil || sourceErr != nil || !reflect.DeepEqual(actual, captured) {
								t.Fatal("complete captured TCP/QUIC lane, key or detour changed", err, sourceErr)
							}
							if graphEntry(t, after, root)["mtu"] != nil {
								t.Fatal("composite invented a second IP interface")
							}
							if strings.Contains(c.ProgressJSON(), "captured-hysteria-credential") || strings.Contains(c.ProgressJSON(), "private-token") {
								t.Fatal("private node or lane credentials leaked")
							}
						}
						count++
					})
				}
			}
		}
	}
	if count != 945 {
		t.Fatal("composite entry/exit/layer/execution matrix incomplete", count)
	}
}

func TestCompositeMultihopRejectsChangedOwnersAndBypassedLanes(t *testing.T) {
	input, meta, a, b, _, _ := compositeFixture(t, "split", "max", "aes-256-gcm", "aes-256-gcm+xor-whitening", "auto")
	for _, fault := range []string{"missing-source", "swapped-source", "node", "mode", "one-lane", "root-detour", "child-preowned"} {
		t.Run("placeholder/"+fault, func(t *testing.T) {
			g, x, y := startObject(t, input), a, b
			switch fault {
			case "missing-source":
				y = ""
			case "swapped-source":
				x, y = y, x
			case "node":
				graphEntry(t, g, "proxy")["node_id"] = strings.Repeat("f", 64)
			case "mode":
				graphEntry(t, g, "proxy")["mode"] = "split"
			case "one-lane":
				graphEntry(t, g, "proxy")["udp"] = graphEntry(t, g, "proxy")["tcp"]
			case "root-detour":
				graphEntry(t, g, "proxy")["detour"] = "direct"
			case "child-preowned":
				g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": CompositeExitPrefix + "udp"})
			}
			if _, err := ComposeCompositeMultihop(startJSON(t, g), meta, x, y); err == nil {
				t.Fatal("changed captured construction owner accepted")
			}
		})
	}
	complete, err := ComposeCompositeMultihop(input, meta, a, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"TCP-bypass", "UDP-bypass", "outer-bypass", "entry-cycle", "foreign-node", "weak-UDP", "unsafe-TLS", "wrong-private-node", "layer-dropped", "unowned-child", "endpoint-child"} {
		t.Run("complete/"+fault, func(t *testing.T) {
			g, m := startObject(t, complete), startObject(t, meta)
			switch fault {
			case "TCP-bypass":
				graphEntry(t, g, CompositeExitPrefix+"tcp")["detour"] = "entry-wg"
			case "UDP-bypass":
				graphEntry(t, g, CompositeExitPrefix+"udp")["detour"] = "entry-wg"
			case "outer-bypass":
				delete(graphEntry(t, g, CompositeExitPrefix+"start"), "detour")
			case "entry-cycle":
				graphEntry(t, g, CompositeEntryPrefix+"start")["detour"] = "proxy"
			case "foreign-node":
				graphEntry(t, g, "proxy")["node_id"] = strings.Repeat("c", 64)
			case "weak-UDP":
				graphEntry(t, g, CompositeExitPrefix+"udp")["type"] = "direct"
			case "unsafe-TLS":
				graphEntry(t, g, CompositeExitPrefix+"udp")["tls"].(map[string]any)["insecure"] = true
			case "wrong-private-node":
				m["exit_api"] = "http://10.88.0.99:8787"
			case "layer-dropped":
				m["exit_start_layer"] = ""
			case "unowned-child":
				g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": CompositeExitPrefix + "bypass"})
			case "endpoint-child":
				g["endpoints"] = append(g["endpoints"].([]any), graphEntry(t, g, CompositeEntryPrefix+"udp"))
			}
			if c, err := New(startJSON(t, g), startJSON(t, m)); err == nil {
				c.Close()
				t.Fatal("unowned complete graph was adopted")
			}
		})
	}
	if c, err := NewWithStartLayers(complete, meta, `{}`, ""); err == nil {
		c.Close()
		t.Fatal("composite accepted a second entry Start Layer")
	}
	if c, err := NewWithStartLayers(complete, meta, "", `{}`); err == nil {
		c.Close()
		t.Fatal("composite accepted a second exit Start Layer")
	}
}

func TestCompositeMultihopExecutionOwnsExactLeaseAndNodeProofs(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = previous }()
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, execution := range []string{"local", "server", "auto"} {
			input, meta, a, b, al, bl := compositeFixture(t, mode, mode, "aes-256-gcm", "aes-256-gcm+xor-whitening", execution)
			complete, err := ComposeCompositeMultihop(input, meta, a, b)
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewWithStartLayers(complete, meta, al, bl)
			if err != nil {
				t.Fatal(err)
			}
			engine := makeEngine(t)
			engine.exitMode, engine.exitLayer = mode, "aes-256-gcm+xor-whitening"
			if err = c.Run(context.Background(), engine); err != nil {
				c.Close()
				t.Fatal(mode, execution, err)
			}
			if execution != "local" && (engine.lease == nil || engine.lease.ExitMode != mode || engine.lease.ExitStartLayer != "aes-256-gcm+xor-whitening") {
				t.Fatal("server lease weakened complete exit identity")
			}
			if err = c.Close(); err != nil || engine.lease != nil || engine.secretLeak || len(engine.errors) != 0 {
				t.Fatal("owned composite session did not release exact lease", err)
			}
		}
	}
}
