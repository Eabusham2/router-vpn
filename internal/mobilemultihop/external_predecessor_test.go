package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/applexray"
	"router-vpn/internal/mobileperf"
)

var predecessorFamilies = []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "ss-v2ray", "split", "max", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "naive-h2", "naive-h3"}

// Produce real compiler output, including real generated PQ/MAX assets and
// embedded Xray protocol documents. The plain host wrapper only supplies the
// same one-TUN/DNS scaffolding used by the mobile single-node assemblers.
func externalPredecessorFixture(t *testing.T, mode, layer string, cover bool) (string, map[string]any) {
	t.Helper()
	raw, id := wireGuardFixture()
	var config string
	var err error
	aes := map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.44", "server_port": 8388, "method": NativeStartLayerMethod, "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))}}}
	policy := map[string]any{"mode": layer, "raw_mode": mode, "node_kind": "router-vpn", "router_api": "http://10.77.0.1:8787"}
	switch {
	case MAXMode(mode):
		files, metadata := maxFixture(t, mode)
		selected := startObject(t, metadata)
		selected["start_layer"] = layer
		id = selected["node_id"].(string)
		config, err = CompileMAXProfile(mode, pqEncoded(files), startJSON(t, selected))
	case CompositeMode(mode):
		config = compositeHopSource(t, mode, id, layer, "http://10.77.0.1:8787")
	case IsPQMode(mode):
		var files map[string]string
		files, id = pqFixture(mode)
		config, err = CompilePQProfile(mode, pqEncoded(files), id)
		if err == nil && layer != "" {
			config, err = ComposeNativeBaseStartLayer(config, startJSON(t, aes), startJSON(t, policy))
		}
	case mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong":
		if mode == "wg" {
			config, err = WireGuardExitConfig(raw, id)
		} else {
			raw, id = amneziaFixture()
			config, err = AmneziaExitConfig(raw, id)
		}
		if err == nil && layer != "" {
			config, err = ComposeNativeBaseStartLayer(config, startJSON(t, aes), startJSON(t, policy))
		}
	case XrayEntryMode(mode):
		files, _ := xrayEntryFixture(t, mode)
		var assets map[string]string
		_ = json.Unmarshal([]byte(files), &assets)
		wrapper, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
		xray, _ := base64.StdEncoding.DecodeString(assets["xray.json"])
		var compiled []byte
		if layer == "" {
			compiled, err = applexray.Compile(mode, wrapper, xray)
		} else {
			compiled, err = applexray.ComposeStartLayer(mode, wrapper, xray, []byte(startJSON(t, aes)), []byte(startJSON(t, policy)))
		}
		config = string(compiled)
	default:
		root := proxyEntryGraph(mode)
		out := proxyEntry(t, mode)
		out["tag"] = "proxy"
		if mode == "shadowsocks" && layer != "" {
			out["method"], out["password"] = NativeStartLayerMethod, aes["outbounds"].([]any)[0].(map[string]any)["password"]
			if layer == "aes-256-gcm+xor-whitening" {
				out["type"], out["server_port"] = "routervpn-aes-xor", 8389
			}
		}
		outs := []any{out, map[string]any{"type": "direct", "tag": "direct"}}
		if layer != "" && mode != "shadowsocks" {
			outer := predecessorCopy(aes["outbounds"].([]any)[0].(map[string]any))
			outer["tag"] = NativeStartLayerTag
			if layer == "aes-256-gcm+xor-whitening" {
				outer["type"], outer["server_port"] = "routervpn-aes-xor", 8389
			}
			out["server"], out["detour"] = "127.0.0.1", NativeStartLayerTag
			outs = append(outs, outer)
		}
		root["outbounds"] = outs
		config = startJSON(t, root)
	}
	if err != nil {
		t.Fatal(mode, layer, err)
	}
	graph := startObject(t, config)
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	if tun["mtu"] == nil {
		tun["mtu"] = float64(1280)
	}
	if tun["address"] == nil {
		tun["address"] = []any{"172.29.94.1/30", "fd29:94::1/126"}
	}
	if graph["dns"] == nil {
		graph["dns"] = map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "selected-dns", "server": "9.9.9.9", "detour": "proxy"}}, "final": "selected-dns"}
	}
	profile := map[string]any{"id": "full-native-entry", "node_kind": "router-vpn", "node_proof_id": id, "router_api": "http://10.77.0.1:8787", "api_token": "exact-captured-entry-token", "start_layer": layer, "mtu_policy": "auto", "ipv6_mode": "on", "home_lan_access": true, "adguard_ipv4": "10.77.0.1", "daita_enabled": cover, "daita_host": "10.77.0.1", "daita_rate_kbps": 64}
	config = startJSON(t, graph)
	if cover {
		config, err = mobileperf.Apply(config, startJSON(t, map[string]any{"entry": profile, "exit": profile}))
		if err != nil {
			t.Fatal(mode, layer, "performance fixture", err)
		}
	}
	return config, profile
}

func TestExternalFullPredecessorGeneratedFamiliesPreserveEveryOwner(t *testing.T) {
	count := 0
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, cover := range []bool{false, true} {
				for _, protocol := range externalTestProtocols {
					name := mode + "/" + layer + "/" + protocol
					t.Run(name, func(t *testing.T) {
						source, profile := externalPredecessorFixture(t, mode, layer, cover)
						graph, capture := externalTestFixture(t, protocol, "")
						capture["entry"], capture["entry_tag"], capture["predecessor_config"] = profile, externalEntryTag, source
						capture["profile"].(map[string]any)["multihop_entry_mode"] = mode
						before, selected := startJSON(t, graph), startJSON(t, capture)
						compiled, err := NewExternalPolicy(before, selected)
						if err != nil {
							t.Fatal(mode, layer, cover, protocol, err)
						}
						count++
						result, metadata := startObject(t, compiled.Config()), startObject(t, compiled.Metadata())
						if metadata["predecessor_sha256"] != externalDigest([]byte(source)) || metadata["entry_tag"] != externalEntryTag || metadata["entry_id"] != profile["id"] || result["route"].(map[string]any)["final"] != ExternalFinalTag {
							t.Fatal("captured predecessor identity or final routing lost")
						}
						if len(result["inbounds"].([]any)) != 2 || externalTestFind(t, result, ExternalFinalTag)["detour"] != externalEntryTag {
							t.Fatal("exit bypassed complete predecessor or acquired a second TUN")
						}
						original := startObject(t, source)
						for _, family := range []string{"endpoints", "outbounds"} {
							rows, _ := original[family].([]any)
							for _, raw := range rows {
								owner := raw.(map[string]any)
								tag := predecessorText(owner, "tag")
								wantTag := predecessorNamespace("node", tag)
								if tag == original["route"].(map[string]any)["final"] {
									wantTag = externalEntryTag
								}
								actual := predecessorCopy(externalTestFind(t, result, wantTag))
								for _, key := range []string{"tag", "detour", "tcp", "udp", "domain_resolver"} {
									delete(owner, key)
									delete(actual, key)
								}
								if !reflect.DeepEqual(owner, actual) {
									t.Fatal("captured keys, parameters, certificate, native protocol or MTU changed", mode, tag)
								}
							}
						}
						if cover {
							service := result["services"].([]any)[0].(map[string]any)
							if service["node_id"] != profile["node_proof_id"] || service["proof_tag"] != externalEntryTag || service["packet_tag"] != externalEntryTag || service["rate_kbps"] != float64(64) {
								t.Fatal("cover service left its captured entry owner")
							}
						}
						if before != startJSON(t, graph) || selected != startJSON(t, capture) {
							t.Fatal("compiler changed the caller's captured source")
						}
						if directory := os.Getenv("ROUTERVPN_EXTERNAL_PREDECESSOR_GRAPHS"); directory != "" && !cover {
							file := strings.ReplaceAll(mode+"-"+layer+"-"+protocol, "/", "-") + ".json"
							if err := os.WriteFile(filepath.Join(directory, file), []byte(compiled.Config()), 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
	if count != 684 {
		t.Fatal("incomplete predecessor family coverage", count)
	}
}

func TestExternalPredecessorRejectsDifferentCapturedMode(t *testing.T) {
	for _, mode := range predecessorFamilies {
		t.Run(mode, func(t *testing.T) {
			source, entry := externalPredecessorFixture(t, mode, "", false)
			graph, capture := externalTestFixture(t, "hysteria2", "")
			capture["entry"], capture["entry_tag"], capture["predecessor_config"] = entry, externalEntryTag, source
			for _, wrong := range []any{"unknown", "auto", true, map[string]any{}, "wg-pq", "max-tls-awg"} {
				if wrong == mode {
					continue
				}
				capture["profile"].(map[string]any)["multihop_entry_mode"] = wrong
				if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
					t.Fatal("accepted changed mode", mode, wrong)
				}
			}
		})
	}
}

func TestExternalFullPredecessorRejectsChangedOwnersAndBypasses(t *testing.T) {
	mutations := map[string]func(map[string]any, map[string]any){
		"second interface": func(g, _ map[string]any) { g["inbounds"] = append(g["inbounds"].([]any), g["inbounds"].([]any)[0]) },
		"unowned listener": func(g, _ map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["type"] = "mixed" },
		"tun route bypass": func(g, _ map[string]any) {
			g["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"] = []any{"0.0.0.0/0"}
		},
		"wrong proof node": func(g, _ map[string]any) {
			g["endpoints"].([]any)[0].(map[string]any)["node_id"] = strings.Repeat("f", 64)
		},
		"unknown endpoint option":  func(g, _ map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["bind_interface"] = "wlan0" },
		"unknown service":          func(g, _ map[string]any) { g["services"] = []any{map[string]any{"type": "extra", "tag": "unowned"}} },
		"discarded cover":          func(g, c map[string]any) { c["daita_enabled"] = true },
		"missing start":            func(g, _ map[string]any) { g["outbounds"] = g["outbounds"].([]any)[:0] },
		"forgotten selected start": func(g, c map[string]any) { c["start_layer"] = "off" },
		"extra encrypted node": func(g, _ map[string]any) {
			n := predecessorCopy(g["outbounds"].([]any)[0].(map[string]any))
			n["tag"] = "unowned"
			g["outbounds"] = append(g["outbounds"].([]any), n)
		},
		"physical fallback": func(g, _ map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": "plain"})
			g["endpoints"].([]any)[0].(map[string]any)["detour"] = "plain"
		},
		"cycle":      func(g, _ map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["detour"] = "proxy" },
		"unresolved": func(g, _ map[string]any) { g["outbounds"].([]any)[0].(map[string]any)["detour"] = "missing" },
		"extra DNS rules": func(g, _ map[string]any) {
			g["dns"].(map[string]any)["rules"] = []any{map[string]any{"server": "ambient"}}
		},
		"ambient DNS": func(g, _ map[string]any) {
			g["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["type"] = "local"
		},
		"missing private authentication": func(g, c map[string]any) { delete(c, "api_token") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			source, entry := externalPredecessorFixture(t, "wg-pq", "aes-256-gcm", false)
			predecessor := startObject(t, source)
			mutate(predecessor, entry)
			graph, capture := externalTestFixture(t, "shadowsocks", "")
			capture["entry"], capture["entry_tag"], capture["predecessor_config"] = entry, externalEntryTag, startJSON(t, predecessor)
			if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
				t.Fatal("changed/unowned predecessor became runnable", name)
			}
		})
	}
}

func TestExternalPredecessorDNSNamesCannotShadowSelectedExitOrRecurse(t *testing.T) {
	source, entry := externalPredecessorFixture(t, "naive-h3", "aes-256-gcm+xor-whitening", false)
	predecessor := startObject(t, source)
	dns := predecessor["dns"].(map[string]any)
	server := dns["servers"].([]any)[0].(map[string]any)
	server["tag"], server["server"], server["type"], server["server_port"] = "selected-dns", "9.9.9.9", "tcp", float64(5353)
	dns["final"] = "selected-dns"
	graph, capture := externalTestFixture(t, "shadowsocks", "")
	capture["entry"], capture["entry_tag"], capture["predecessor_config"] = entry, externalEntryTag, startJSON(t, predecessor)
	plan, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	result := startObject(t, plan.Config())
	root := externalTestFind(t, result, externalEntryTag)
	query := root["domain_resolver"].(map[string]any)
	servers := result["dns"].(map[string]any)["servers"].([]any)
	var bootstrap map[string]any
	for _, raw := range servers {
		value := raw.(map[string]any)
		if value["tag"] == query["server"] {
			bootstrap = value
		}
	}
	if query["server"] == ExternalDNSTag || bootstrap == nil || bootstrap["type"] != "tcp" || bootstrap["server"] != "9.9.9.9" || bootstrap["server_port"] != float64(5353) || bootstrap["detour"] != root["detour"] {
		t.Fatal("Naive resolver lost its captured lower path or was shadowed by exit DNS")
	}
	if servers[0].(map[string]any)["detour"] != ExternalFinalTag || result["route"].(map[string]any)["default_domain_resolver"] != nil {
		t.Fatal("application DNS inherited predecessor bootstrap")
	}
	predecessor["outbounds"].([]any)[0].(map[string]any)["domain_resolver"] = map[string]any{"server": "selected-dns"}
	capture["predecessor_config"] = startJSON(t, predecessor)
	if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
		t.Fatal("explicit resolver cycle was hidden by replacing the resolver")
	}
}

func TestExternalPredecessorDevicePolicyConjunctionAndFixedMTU(t *testing.T) {
	source, entry := externalPredecessorFixture(t, "hysteria2", "", false)
	entry["mtu_policy"], entry["manual_mtu"] = "fixed", 1440
	entry["ipv6_mode"], entry["home_lan_access"] = "off", false
	predecessor := startObject(t, source)
	predecessor["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1440
	graph, capture := externalTestFixture(t, "shadowsocks", "")
	capture["entry"], capture["entry_tag"], capture["predecessor_config"] = entry, externalEntryTag, startJSON(t, predecessor)
	plan, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	meta := startObject(t, plan.Metadata())
	if meta["configured_mtu"] != float64(1440) || meta["mtu_policy"] != "fixed" || meta["ipv6_mode"] != "off" || meta["home_lan_access"] != false {
		t.Fatal("exit policy weakened the captured predecessor")
	}
	capture["profile"].(map[string]any)["mtu_policy"] = "fixed"
	capture["profile"].(map[string]any)["manual_mtu"] = 1400
	if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
		t.Fatal("conflicting fixed TUN owners silently won")
	}
}
