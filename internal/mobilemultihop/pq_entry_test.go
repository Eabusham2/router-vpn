package mobilemultihop

import (
	"context"
	"encoding/json"
	"net"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

func pqEntryGraph(t *testing.T, mode, exitMode, entryLayer, exitLayer, execution string) (string, string, string, string) {
	t.Helper()
	config, metadata, a, b := exitLayerFixture(t, "wg", exitMode, entryLayer, exitLayer, execution)
	graph, meta := startObject(t, config), startObject(t, metadata)
	files, node := pqFixture(mode)
	single, err := CompilePQProfile(mode, pqEncoded(files), node)
	if err != nil {
		t.Fatal(err)
	}
	ep := pqEndpoint(t, single)
	ep["tag"] = "entry-wg"
	endpoints := graph["endpoints"].([]any)
	for i, v := range endpoints {
		if v.(map[string]any)["tag"] == "entry-wg" {
			endpoints[i] = ep
		}
	}
	meta["entry_mode"], meta["entry_node_id"] = mode, node
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	tun["tag"], tun["mtu"] = "tun-in", 1280
	if exitLayer == "" {
		b = ""
	}
	return startJSON(t, graph), startJSON(t, meta), a, b
}

func TestPQEntriesPreserveAllExistingExitAndStartLayerPaths(t *testing.T) {
	exits := []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp"}
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, exit := range exits {
			for _, execution := range []string{"local", "server", "auto"} {
				for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					for _, v6 := range []bool{false, true} {
						t.Run(mode+"/"+exit+"/"+execution+"/"+layer+"/"+map[bool]string{false: "v4", true: "v6"}[v6], func(t *testing.T) {
							config, metadata, a, b := pqEntryGraph(t, mode, exit, layer, layer, execution)
							meta := startObject(t, metadata)
							if v6 {
								meta["entry_api"] = "http://[fd77:77::1]:8787"
								metadata = startJSON(t, meta)
							}
							sized, err := ApplyMTUPolicy(config, `{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`)
							if err != nil {
								t.Fatal(err)
							}
							before := startObject(t, sized)
							c, err := NewWithStartLayers(sized, metadata, a, b)
							if err != nil {
								t.Fatal(err)
							}
							defer c.Close()
							after := startObject(t, c.Config())
							original := graphEntry(t, before, "entry-wg")
							entry := graphEntry(t, after, "entry-wg")
							if layer != "" {
								host := "10.77.0.1"
								if v6 {
									host = "fd77:77::1"
								}
								original["peers"].([]any)[0].(map[string]any)["address"] = host
								original["pq"].(map[string]any)["endpoint"] = net.JoinHostPort(host, "51822")
								original["detour"] = EntryStartLayerTag
							}
							if startJSON(t, original) != startJSON(t, entry) {
								t.Fatal("entry key, base transport, handshake or MTU changed")
							}
							for _, field := range []string{"inbounds", "dns", "route"} {
								if startJSON(t, before[field]) != startJSON(t, after[field]) {
									t.Fatal("device policy changed", field)
								}
							}
							if graphEntry(t, after, ServerTag)["detour"] != "entry-wg" {
								t.Fatal("server candidate bypassed negotiated PQ")
							}
							route := "entry-wg"
							if layer != "" {
								route = multihoprelay.ExitStartLayerTag
							}
							// The exact exit layer tag is owned by the shared relay compiler.
							if graphEntry(t, after, LocalTag)["detour"] != route {
								t.Fatal("local candidate bypassed PQ")
							}
							raw, _ := json.Marshal(entry)
							runtime, err := PQRuntimeConfig(string(raw))
							if err != nil {
								t.Fatal(err)
							}
							runtime.PQ.Erase()
							if strings.Contains(c.ProgressJSON(), entry["private_key"].(string)) || strings.Contains(c.ProgressJSON(), "private-token") {
								t.Fatal("status leaked secrets")
							}
						})
					}
				}
			}
		}
	}
}

func TestPQEntryRejectsDowngradeWrongNodeAndIndependentHandshakeRoute(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		config, meta, _, _ := pqEntryGraph(t, mode, "shadowsocks", "", "", "auto")
		for name, mutate := range map[string]func(map[string]any){
			"mode":                   func(e map[string]any) { e["mode"] = "wg" },
			"node":                   func(e map[string]any) { e["node_id"] = strings.Repeat("e", 64) },
			"downgrade":              func(e map[string]any) { e["type"] = "wireguard" },
			"missing-pq":             func(e map[string]any) { delete(e, "pq") },
			"direct-entry":           func(e map[string]any) { e["detour"] = "direct" },
			"foreign-handshake":      func(e map[string]any) { e["pq"].(map[string]any)["endpoint"] = "192.0.2.9:51822" },
			"hidden-handshake-route": func(e map[string]any) { e["pq"].(map[string]any)["detour"] = "direct" },
			"system":                 func(e map[string]any) { e["system"] = true },
		} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				g := startObject(t, config)
				mutate(graphEntry(t, g, "entry-wg"))
				if _, err := New(startJSON(t, g), meta); err == nil {
					t.Fatal("unowned PQ entry accepted")
				}
			})
		}
		g := startObject(t, config)
		ep := graphEntry(t, g, "entry-wg")
		g["endpoints"] = []any{}
		g["outbounds"] = append(g["outbounds"].([]any), ep)
		if _, err := New(startJSON(t, g), meta); err == nil {
			t.Fatal("PQ endpoint in wrong manager")
		}
		mm := startObject(t, meta)
		mm["exit_mode"] = mode
		if _, err := New(config, startJSON(t, mm)); err == nil {
			t.Fatal("unimplemented PQ server exit advertised")
		}
	}
}

func TestPQEntryUsesExistingCompareAndLeaseLifecycle(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = previous }()
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, execution := range []string{"local", "server", "auto"} {
			config, meta, a, b := pqEntryGraph(t, mode, "shadowsocks", "aes-256-gcm+xor-whitening", "", execution)
			c, err := NewWithStartLayers(config, meta, a, b)
			if err != nil {
				t.Fatal(err)
			}
			engine := makeEngine(t)
			engine.entryNode = c.meta.EntryNodeID
			if err = c.Run(context.Background(), engine); err != nil {
				t.Fatal(mode, execution, err)
			}
			if engine.Selected() == "" {
				t.Fatal("comparison retained no proved path")
			}
			if err = c.Close(); err != nil || engine.lease != nil || engine.secretLeak || len(engine.errors) != 0 {
				t.Fatal("lease or private traffic escaped", err)
			}
		}
	}
}
