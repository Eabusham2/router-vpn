package mobilemultihop

import (
	"context"
	"reflect"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

func TestNaiveProfileCompilerOwnsHTTPVersionCredentialsAndTrust(t *testing.T) {
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		for _, inline := range []bool{false, true} {
			graph := proxyEntryGraph(mode)
			out := graph["outbounds"].([]any)[0].(map[string]any)
			cert := ""
			if inline {
				cert = entryCertificate(t)
				out["tls"].(map[string]any)["certificate_path"] = "cert.pem"
			}
			original := proxyEntryProfile(t, graph, cert)
			result, err := CompileProxyEntry(original, mode)
			if err != nil {
				t.Fatal(err)
			}
			value := startObject(t, result)
			expected := startObject(t, startJSON(t, out))
			expected["tag"] = "routervpn-hop-entry"
			if inline {
				tls := expected["tls"].(map[string]any)
				delete(tls, "certificate_path")
				tls["certificate"] = []any{cert}
			}
			if !reflect.DeepEqual(expected, value) {
				t.Fatal("compiler changed credentials, UOT or certificate bytes")
			}
			if proxyEntryType(mode) != "naive" || proxyModeForOutbound(value) != mode {
				t.Fatal("HTTP selection lost")
			}
			if result2, err := CompileProxyEntry(original, mode); err != nil || result2 != result {
				t.Fatal("non-deterministic compile")
			}
			if proxyEntryProfile(t, graph, cert) != original {
				t.Fatal("source mutated")
			}
			if inline {
				if _, err = CompileProxyEntry(proxyEntryProfile(t, graph, ""), mode); err == nil {
					t.Fatal("missing certificate borrowed from host/exit")
				}
				if _, err = CompileProxyEntry(proxyEntryProfile(t, graph, "unowned private material\n"+cert), mode); err == nil {
					t.Fatal("opaque data accepted as certificate")
				}
			}
		}
		for name, mutate := range map[string]func(map[string]any){
			"mismatched-quic": func(v map[string]any) { v["quic"] = mode != "naive-h3" },
			"lost-udp":        func(v map[string]any) { v["udp_over_tcp"] = false },
			"missing-auth":    func(v map[string]any) { delete(v, "password") },
			"plaintext":       func(v map[string]any) { v["tls"].(map[string]any)["enabled"] = false },
			"insecure":        func(v map[string]any) { v["tls"].(map[string]any)["insecure"] = true },
			"preowned":        func(v map[string]any) { v["detour"] = "foreign" },
		} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				graph := proxyEntryGraph(mode)
				mutate(graph["outbounds"].([]any)[0].(map[string]any))
				if _, err := CompileProxyEntry(proxyEntryProfile(t, graph, ""), mode); err == nil {
					t.Fatal("invalid mode became an entry")
				}
			})
		}
	}
}

func TestNaiveEveryExistingEntryExitLayerAndExecutionGraph(t *testing.T) {
	modes := []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "naive-h2", "naive-h3"}
	layers := [][2]string{{"", ""}, {"aes-256-gcm", ""}, {"", "aes-256-gcm+xor-whitening"}, {"aes-256-gcm+xor-whitening", "aes-256-gcm"}}
	count := 0
	for _, entry := range modes {
		for _, exit := range modes {
			if !multihoprelay.NaiveMode(entry) && !multihoprelay.NaiveMode(exit) {
				continue
			}
			for _, layer := range layers {
				for _, execution := range []string{"local", "server", "auto"} {
					t.Run(entry+"/"+exit+"/"+execution+"/"+layer[0]+"/"+layer[1], func(t *testing.T) {
						input, meta, a, b, al, bl := maxCompositeFixture(t, entry, exit, layer[0], layer[1], execution)
						if layer[0] == "" {
							al = ""
						}
						if layer[1] == "" {
							bl = ""
						}
						composed := input
						var err error
						if MAXMode(entry) || MAXMode(exit) {
							composed, err = ComposeMAXMultihop(input, meta, a, b)
							if err != nil {
								t.Fatal(err)
							}
						}
						profiles := `{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`
						if ProxyEntryMode(entry) {
							profiles = `{"entry":{"mtu_policy":"fixed","manual_mtu":1280},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`
						}
						sized, err := ApplyMTUPolicy(composed, profiles)
						if err != nil {
							t.Fatal(err)
						}
						before := startObject(t, sized)
						controller, err := NewWithStartLayers(sized, meta, al, bl)
						if err != nil {
							t.Fatal(err)
						}
						defer controller.Close()
						after := startObject(t, controller.Config())
						if controller.Healthy() {
							t.Fatal("graph preparation faked a proof/connection")
						}
						for _, field := range []string{"dns", "route", "inbounds"} {
							if !reflect.DeepEqual(before[field], after[field]) {
								t.Fatal("device policy changed", field)
							}
						}
						for _, isEntry := range []bool{true, false} {
							mode, tag, originalTag, requestedLayer, host := exit, LocalTag, "proxy", layer[1], "10.88.0.1"
							if isEntry {
								mode, tag, originalTag, requestedLayer, host = entry, "entry-wg", "entry-wg", layer[0], "10.77.0.1"
							}
							if !multihoprelay.NaiveMode(mode) {
								continue
							}
							want := startObject(t, startJSON(t, graphEntry(t, before, originalTag)))
							want["tag"] = tag
							if requestedLayer != "" {
								want["server"] = host
								want["detour"] = multihoprelay.ExitStartLayerTag
								if isEntry {
									want["detour"] = EntryStartLayerTag
								}
							}
							got := graphEntry(t, after, tag)
							if !reflect.DeepEqual(want, got) {
								t.Fatal("Naive version, credential, inline trust or owned path changed")
							}
							if strings.Contains(controller.ProgressJSON(), got["password"].(string)) {
								t.Fatal("progress leaked a credential")
							}
						}
						if graphEntry(t, after, ServerTag)["detour"] != "entry-wg" {
							t.Fatal("server candidate bypasses entry")
						}
						count++
					})
				}
			}
		}
	}
	if count != 720 {
		t.Fatal("incomplete Naive graph matrix", count)
	}
}

func TestNaiveUsesRealRetainedComparisonController(t *testing.T) {
	previous := Targets
	Targets = []string{"http://192.0.2.60/check"}
	defer func() { Targets = previous }()
	for _, entryMode := range []string{"naive-h2", "naive-h3"} {
		for _, exitMode := range []string{"naive-h2", "naive-h3"} {
			for _, execution := range []string{"local", "server", "auto"} {
				input, meta, _, _, _, _ := maxCompositeFixture(t, entryMode, exitMode, "", "", execution)
				controller, err := NewWithStartLayers(input, meta, "", "")
				if err != nil {
					t.Fatal(err)
				}
				engine := makeEngine(t)
				engine.exitMode = exitMode
				if err = controller.Run(context.Background(), engine); err != nil {
					t.Fatal(err)
				}
				if !controller.Healthy() {
					t.Fatal("retained candidate not healthy")
				}
				if err = controller.Close(); err != nil {
					t.Fatal(err)
				}
				if engine.lease != nil || engine.secretLeak || len(engine.errors) != 0 {
					t.Fatal("node proof or lease ownership failed")
				}
			}
		}
	}
}

func TestNaiveExitCannotBypassModeOrDatagramValidation(t *testing.T) {
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		input, meta := fixture(t, "auto")
		g, m := startObject(t, input), startObject(t, meta)
		out := proxyEntry(t, mode)
		out["tag"] = "proxy"
		out["detour"] = "entry-wg"
		g["outbounds"] = []any{out}
		m["exit_mode"] = mode
		if _, err := New(startJSON(t, g), startJSON(t, m)); err != nil {
			t.Fatal(err)
		}
		for _, fault := range []string{"quic", "udp", "tls", "detour", "manager"} {
			changed := startObject(t, startJSON(t, g))
			value := changed["outbounds"].([]any)[0].(map[string]any)
			switch fault {
			case "quic":
				value["quic"] = !(value["quic"].(bool))
			case "udp":
				value["udp_over_tcp"] = false
			case "tls":
				value["tls"].(map[string]any)["insecure"] = true
			case "detour":
				value["detour"] = "direct"
			case "manager":
				changed["endpoints"] = append(changed["endpoints"].([]any), value)
				changed["outbounds"] = []any{}
			}
			c, err := New(startJSON(t, changed), startJSON(t, m))
			if err == nil {
				c.Close()
				t.Fatal("unsafe Naive exit accepted", fault)
			}
		}
	}
}
