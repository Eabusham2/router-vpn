package mobilemultihop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

func pqExitGraph(t *testing.T, entryMode, exitMode, entryLayer, exitLayer, execution string, ipv6 bool) (string, string, string, string) {
	t.Helper()
	var graph, meta, a, b string
	if IsPQMode(entryMode) {
		graph, meta, a, b = pqEntryGraph(t, entryMode, "wg", entryLayer, exitLayer, execution)
	} else {
		graph, meta, a, b = exitLayerFixture(t, entryMode, "wg", entryLayer, exitLayer, execution)
	}
	g, m := startObject(t, graph), startObject(t, meta)
	files, _ := pqFixture(exitMode)
	asset := "wg.conf"
	if exitMode == "awg2-pq" {
		asset = "awg.conf"
	}
	public := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32)))
	original := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	pqReplace(files, asset, original, public)
	pqReplace(files, "rosenpass.env", original, public)
	hash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
	node := hex.EncodeToString(hash[:])
	files["rosenpass-client-public"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 128)))
	compiled, err := CompilePQProfile(exitMode, pqEncoded(files), node)
	if err != nil {
		t.Fatal(err)
	}
	ep := pqEndpoint(t, compiled)
	host := "192.0.2.77"
	if ipv6 {
		host = "2001:db8::77"
	}
	if err = rewriteEntryStartHost(ep, exitMode, host); err != nil {
		t.Fatal(err)
	}
	ep["tag"], ep["detour"] = "proxy", "entry-wg"
	endpoints := g["endpoints"].([]any)
	for i, raw := range endpoints {
		if raw.(map[string]any)["tag"] == "proxy" {
			endpoints[i] = ep
		}
	}
	m["exit_mode"], m["exit_node_id"] = exitMode, node
	if ipv6 {
		m["exit_api"] = "http://[fd88::1]:8787"
	}
	g["inbounds"].([]any)[0].(map[string]any)["tag"] = "tun-in"
	g["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1280
	if exitLayer != "" {
		source := startObject(t, b)
		profile := source["profile"].(map[string]any)
		encoded := profile["sing-box.json"].(string)
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		profile["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(string(raw), "192.0.2.77", host)))
		b = startJSON(t, source)
	} else {
		b = ""
	}
	return startJSON(t, g), startJSON(t, m), a, b
}

func TestPQExitsPreserveNativeKeysAndEveryEntryFamily(t *testing.T) {
	entries := []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "wg-pq", "awg2-pq"}
	layers := [][2]string{{"", ""}, {"aes-256-gcm", ""}, {"", "aes-256-gcm+xor-whitening"}, {"aes-256-gcm+xor-whitening", "aes-256-gcm"}}
	count := 0
	for _, entry := range entries {
		for _, exit := range []string{"wg-pq", "awg2-pq"} {
			for _, execution := range []string{"local", "server", "auto"} {
				for _, layer := range layers {
					for _, v6 := range []bool{false, true} {
						t.Run(entry+"/"+exit+"/"+execution+"/"+layer[0]+"/"+layer[1]+"/"+map[bool]string{false: "v4", true: "v6"}[v6], func(t *testing.T) {
							graph, meta, a, b := pqExitGraph(t, entry, exit, layer[0], layer[1], execution, v6)
							profiles := `{"entry":{"mtu_policy":"fixed","manual_mtu":1280},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`
							if !ProxyEntryMode(entry) {
								profiles = `{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`
							}
							sized, err := ApplyMTUPolicy(graph, profiles)
							if err != nil {
								t.Fatal(err)
							}
							before := startObject(t, sized)
							original := graphEntry(t, before, "proxy")
							controller, err := NewWithStartLayers(sized, meta, a, b)
							if err != nil {
								t.Fatal(err)
							}
							defer controller.Close()
							after := startObject(t, controller.Config())
							actual := graphEntry(t, after, LocalTag)
							expected := startObject(t, startJSON(t, original))
							expected["tag"] = LocalTag
							if layer[1] != "" {
								delete(expected, "detour")
								host := "10.88.0.1"
								if v6 {
									host = "fd88::1"
								}
								if err = rewriteEntryStartHost(expected, exit, host); err != nil {
									t.Fatal(err)
								}
								expected["detour"] = multihoprelay.ExitStartLayerTag
								if graphEntry(t, after, multihoprelay.ExitStartLayerTag)["detour"] != "entry-wg" {
									t.Fatal("outer exit bypasses entry")
								}
							}
							if startJSON(t, expected) != startJSON(t, actual) {
								t.Fatal("PQ exit keys, mode, MTU or independent handshake changed")
							}
							for _, field := range []string{"dns", "route", "inbounds"} {
								if startJSON(t, before[field]) != startJSON(t, after[field]) {
									t.Fatal("device policy changed", field)
								}
							}
							if graphEntry(t, after, ServerTag)["detour"] != "entry-wg" || controller.localPublicKey == "" || len(controller.localPQIdentity) != 64 {
								t.Fatal("comparison route or independent identities missing")
							}
							if strings.Contains(controller.ProgressJSON(), actual["private_key"].(string)) || strings.Contains(controller.ProgressJSON(), actual["pq"].(map[string]any)["secret"].(string)) {
								t.Fatal("progress leaked a private key")
							}
							count++
						})
					}
				}
			}
		}
	}
	if count != 480 {
		t.Fatal("incomplete matrix", count)
	}
}

func TestPQExitsRejectUnownedGraphAndWrongNode(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		graph, meta, _, _ := pqExitGraph(t, "wg", mode, "", "", "auto", false)
		for name, mutate := range map[string]func(map[string]any){
			"mode":              func(e map[string]any) { e["mode"] = "wg" },
			"type":              func(e map[string]any) { e["type"] = "wireguard" },
			"node":              func(e map[string]any) { e["node_id"] = strings.Repeat("a", 64) },
			"detour":            func(e map[string]any) { e["detour"] = "direct" },
			"no-pq":             func(e map[string]any) { delete(e, "pq") },
			"foreign-handshake": func(e map[string]any) { e["pq"].(map[string]any)["endpoint"] = "192.0.2.78:51822" },
			"handshake-detour":  func(e map[string]any) { e["pq"].(map[string]any)["detour"] = "direct" },
			"unknown-policy":    func(e map[string]any) { e["bind_interface"] = "wan" },
		} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				g := startObject(t, graph)
				mutate(graphEntry(t, g, "proxy"))
				if _, err := New(startJSON(t, g), meta); err == nil {
					t.Fatal("invalid PQ exit accepted")
				}
			})
		}
	}
}

func TestPQExitMTUIncludesNativeAWGEnvelope(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, v6 := range []bool{false, true} {
			graph, _, _, _ := pqExitGraph(t, "wg", mode, "", "", "local", v6)
			value, err := ApplyMTUPolicy(graph, `{"entry":{"mtu_policy":"fixed","manual_mtu":1420},"exit":{}}`)
			if err != nil {
				t.Fatal(err)
			}
			overhead := 60
			if v6 {
				overhead = 80
			}
			if mode == "awg2-pq" {
				overhead += 32
			}
			expected := (1420 - overhead) / 16 * 16
			ep := graphEntry(t, startObject(t, value), "proxy")
			if ep["mtu"] != float64(expected) {
				t.Fatal("wrong negotiated packet envelope", mode, v6, ep["mtu"], expected)
			}
			if _, err = ApplyMTUPolicy(graph, `{"entry":{"mtu_policy":"fixed","manual_mtu":1420},"exit":{"mtu_policy":"fixed","manual_mtu":1400}}`); err == nil {
				t.Fatal("oversize fixed inner MTU accepted")
			}
		}
	}
}

func TestPQServerComparisonNeedsIndependentWGAndPQIdentities(t *testing.T) {
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, kind := range []string{"same-wg", "same-pq", "missing-pq", "invalid-pq", "independent"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				graph, meta, _, _ := pqExitGraph(t, "wg", mode, "", "", "auto", false)
				c, err := New(graph, meta)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				e := makeEngine(t)
				e.exitMode = mode
				e.exitNode = c.meta.ExitNodeID
				e.clientPublic = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
				e.pqIdentity = strings.Repeat("a", 64)
				switch kind {
				case "same-wg":
					e.clientPublic = c.localPublicKey
				case "same-pq":
					e.pqIdentity = c.localPQIdentity
				case "missing-pq":
					e.pqIdentity = ""
				case "invalid-pq":
					e.pqIdentity = "invalid"
				}
				if err = c.Run(context.Background(), e); err != nil {
					t.Fatal(err)
				}
				var progress Progress
				if err = json.Unmarshal([]byte(c.ProgressJSON()), &progress); err != nil {
					t.Fatal(err)
				}
				want := "local"
				if kind == "independent" {
					want = "server"
				}
				if progress.Execution != want {
					t.Fatal("unsafe server comparison outcome", kind, c.ProgressJSON())
				}
				if want == "local" && e.lease != nil {
					t.Fatal("unproved server lease was created")
				}
			})
		}
	}
}
