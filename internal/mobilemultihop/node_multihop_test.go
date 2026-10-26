package mobilemultihop

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativecomposite"
)

func multihopNodeSources(t *testing.T, mode, layer, id string) (string, map[string]any, string) {
	t.Helper()
	files, profile, start := nodeProfileFixture(t, mode, layer)
	profile["id"] = id
	if id == "exit" {
		profile["node_proof_id"] = strings.Repeat("f", 64)
		profile["router_api"], profile["adguard_ipv4"] = "http://10.88.0.1:8787", "10.88.0.53"
		if NodeMultihopPacketExitMode(mode) {
			asset := "wg.conf"
			if awgpolicy.IsMode(mode) || mode == "awg2-pq" {
				asset = "awg.conf"
			}
			var assets map[string]string
			if err := json.Unmarshal([]byte(files), &assets); err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(assets[asset])
			if err != nil {
				t.Fatal(err)
			}
			server, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("z", 32)))
			if err != nil {
				t.Fatal(err)
			}
			public := base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())
			text := strings.ReplaceAll(string(raw), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))), public)
			text = strings.ReplaceAll(text, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
			text = strings.ReplaceAll(text, "10.77.0.2", "10.88.0.2")
			assets[asset] = base64.StdEncoding.EncodeToString([]byte(text))
			if IsPQMode(mode) {
				pqReplace(assets, "rosenpass.env", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))), public)
			}
			files = startJSON(t, assets)
			proof := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
			if mode == "wg" || mode == "wg-pq" {
				profile["node_proof_id"] = hex.EncodeToString(proof[:])
			}
		}
	}
	profile["daita_enabled"], profile["daita_rate_kbps"], profile["daita_host"] = true, float64(64), "10.77.0.1"
	profile["ipv6_mode"], profile["home_lan_access"] = "off", false
	return files, profile, start
}

func multihopNodeFixture(t *testing.T, mode, layer, id string) *NodeProfile {
	return multihopNodeCapacityFixture(t, mode, layer, id, 0)
}

func multihopNodeCapacityFixture(t *testing.T, mode, layer, id string, capacity int) *NodeProfile {
	t.Helper()
	files, profile, start := multihopNodeSources(t, mode, layer, id)
	if capacity != 0 {
		profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(capacity)
	}
	compiled, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestNodeMultihopPreservesCompleteCapturedBasesAndLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, entryLayer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, exitMode := range NodeMultihopExitModes() {
				for _, exitLayer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(mode+"/"+entryLayer+"/"+exitMode+"/"+exitLayer, func(t *testing.T) {
						capacity := 0
						// S4=32 plus an exit Start Layer exceeds a 1420-byte
						// entry for the minimum 1280-byte nested packet. This
						// positive composition explicitly captures a larger bound.
						if (awgpolicy.IsMode(exitMode) || exitMode == "awg2-pq") && exitLayer != "" {
							capacity = 1500
						}
						entry, exit := multihopNodeCapacityFixture(t, mode, entryLayer, "entry", capacity), multihopNodeFixture(t, exitMode, exitLayer, "exit")
						entryBefore, exitBefore := entry.Config(), exit.Config()
						compiled, err := NodeMultihopConfig(entry, exit)
						if err != nil {
							t.Fatal(err)
						}
						graph := startObject(t, compiled)
						if len(graph["inbounds"].([]any)) != 1 || graph["route"].(map[string]any)["final"] != "proxy" || entry.Config() != entryBefore || exit.Config() != exitBefore {
							t.Fatal("composition changed source, TUN ownership or final route")
						}
						nodes := map[string]map[string]any{}
						for _, family := range []string{"endpoints", "outbounds"} {
							for _, raw := range graph[family].([]any) {
								node := raw.(map[string]any)
								if nodes[predecessorText(node, "tag")] != nil {
									t.Fatal("duplicate transport owner")
								}
								nodes[predecessorText(node, "tag")] = node
							}
						}
						prior := startObject(t, entryBefore)["endpoints"].([]any)[0].(map[string]any)
						actual := predecessorCopy(nodes["entry-wg"])
						actual["tag"] = "proxy"
						delete(prior, "mtu")
						delete(actual, "mtu")
						if entryLayer != "" {
							if actual["detour"] != predecessorNamespace("node", NativeStartLayerTag) {
								t.Fatal("entry Start Layer bypassed")
							}
							actual["detour"] = NativeStartLayerTag
						}
						if !reflect.DeepEqual(prior, actual) {
							t.Fatal("captured WG/AWG parameters changed", prior, actual)
						}
						outer := nodes["proxy"]
						if CompositeMode(exitMode) {
							captured, err := nativecomposite.Extract(startObject(t, exitBefore), exitMode, predecessorText(exit.profile, "node_proof_id"), exitLayer, "proxy", nativecomposite.SourcePrefix, "")
							actual, actualErr := nativecomposite.Extract(graph, exitMode, predecessorText(exit.profile, "node_proof_id"), exitLayer, "proxy", CompositeExitPrefix, "entry-wg")
							if err != nil || actualErr != nil || !reflect.DeepEqual(captured, actual) || len(nodes["proxy"]) != 6 || nodes["proxy"]["detour"] != nil {
								t.Fatal("composite lost either complete captured lane or gained a generic root detour", err, actualErr)
							}
							for tag := range nodes {
								if strings.HasPrefix(tag, nativecomposite.SourcePrefix) {
									t.Fatal("standalone composite child remained beside its relabeled owner")
								}
							}
							outer = nodes[CompositeExitPrefix+"tcp"]
							if exitLayer != "" {
								outer = nodes[CompositeExitPrefix+"start"]
							}
						} else if exitLayer != "" && exitMode != "shadowsocks" {
							if outer["detour"] != NativeStartLayerTag {
								t.Fatal("exit Start Layer bypassed")
							}
							outer = nodes[NativeStartLayerTag]
						}
						if outer["detour"] != "entry-wg" {
							t.Fatal("exit did not retain the selected entry")
						}
						for _, raw := range startObject(t, exitBefore)["outbounds"].([]any) {
							prior := raw.(map[string]any)
							if CompositeMode(exitMode) && (prior["tag"] == "proxy" || strings.HasPrefix(predecessorText(prior, "tag"), nativecomposite.SourcePrefix)) {
								continue // Exact complete lane/credential equality is proved above.
							}
							actual := predecessorCopy(nodes[predecessorText(prior, "tag")])
							if prior["tag"] == outer["tag"] {
								delete(actual, "detour")
							}
							if !reflect.DeepEqual(prior, actual) {
								t.Fatal("captured exit credentials, TLS, Xray document or UDP framing changed")
							}
						}
						if NodeMultihopPacketExitMode(exitMode) {
							prior := startObject(t, exitBefore)["endpoints"].([]any)[0].(map[string]any)
							actual := predecessorCopy(nodes["proxy"])
							delete(prior, "mtu")
							delete(actual, "mtu")
							if exitLayer == "" {
								delete(actual, "detour")
							}
							if !reflect.DeepEqual(prior, actual) {
								t.Fatal("WG/AWG exit keys, parameters, peer, assigned addresses or packet owner changed")
							}
						}
						servers := graph["dns"].(map[string]any)["servers"].([]any)
						count := 2
						if multihoprelay.NaiveMode(exitMode) {
							count++
							bootstrap := servers[1].(map[string]any)
							via := "entry-wg"
							if exitLayer != "" {
								via = NativeStartLayerTag
							}
							if bootstrap["server"] != "10.88.0.53" || bootstrap["detour"] != via || nodes["proxy"]["domain_resolver"].(map[string]any)["server"] != bootstrap["tag"] {
								t.Fatal("Naive bootstrap lost selected DNS or bypassed its lower encrypted path")
							}
						}
						if len(servers) != count || servers[0].(map[string]any)["server"] != "10.88.0.53" || servers[0].(map[string]any)["detour"] != "proxy" || servers[count-1].(map[string]any)["server"] != "192.168.50.133" || servers[count-1].(map[string]any)["detour"] != "entry-wg" {
							t.Fatal("captured per-node DNS owners were substituted")
						}
						services := graph["services"].([]any)
						if len(services) != 2 || services[0].(map[string]any)["tag"] != "routervpn-cover-entry" || services[0].(map[string]any)["proof_tag"] != "entry-wg" || services[1].(map[string]any)["tag"] != "routervpn-cover-exit" || services[1].(map[string]any)["proof_tag"] != "proxy" {
							t.Fatal("per-node cover identity changed")
						}
						if len(graph["route"].(map[string]any)["rules"].([]any)) < 6 {
							t.Fatal("captured IPv6/LAN restrictions dropped")
						}
					})
				}
			}
		}
	}
}

func TestNodeMultihopRejectsUnownedAndUnsupportedCaptures(t *testing.T) {
	entry, exit := multihopNodeFixture(t, "awg2-strong", "aes-256-gcm", "entry"), multihopNodeFixture(t, "hysteria2", "", "exit")
	unsupported := *entry
	unsupported.mode = "unknown-entry"
	for _, pair := range [][2]*NodeProfile{{nil, exit}, {entry, nil}, {entry, entry}, {&unsupported, exit}, {&NodeProfile{config: entry.config}, exit}} {
		if _, err := NodeMultihopConfig(pair[0], pair[1]); err == nil {
			t.Fatal("unowned or unsupported capture accepted")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(g map[string]any) { g["endpoints"].([]any)[0].(map[string]any)["type"] = "wireguard" },
		func(g map[string]any) { delete(g, "outbounds") },
		func(g map[string]any) { delete(g, "services") },
		func(g map[string]any) {
			g["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] = "direct"
		},
	} {
		broken := *entry
		graph := startObject(t, entry.config)
		mutate(graph)
		broken.config = startJSON(t, graph)
		if _, err := NodeMultihopConfig(&broken, exit); err == nil {
			t.Fatal("incomplete captured predecessor accepted")
		}
	}
}

func TestNodeMultihopRejectsIncompleteNativeProxyAndWrongNode(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3"} {
		for _, fault := range []string{"same-node", "protocol", "packet-path", "foreign-detour", "DNS", "missing-cover"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				entry := multihopNodeFixture(t, "awg2-strong", "aes-256-gcm", "entry")
				exit := multihopNodeFixture(t, mode, "aes-256-gcm+xor-whitening", "exit")
				graph := startObject(t, exit.config)
				proxy := graph["outbounds"].([]any)[0].(map[string]any)
				switch fault {
				case "same-node":
					exit.profile["node_proof_id"] = entry.profile["node_proof_id"]
				case "protocol":
					proxy["type"] = "socks"
				case "packet-path":
					if multihoprelay.NaiveMode(mode) {
						delete(proxy, "udp_over_tcp")
					} else {
						proxy["config_json"] = `{"outbounds":[{"protocol":"socks"}]}`
					}
				case "foreign-detour":
					proxy["detour"] = "entry-wg"
				case "DNS":
					graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] = "missing"
				case "missing-cover":
					delete(graph, "services")
				}
				exit.config = startJSON(t, graph)
				if _, err := NodeMultihopConfig(entry, exit); err == nil {
					t.Fatal("incomplete native exit or substituted node was accepted")
				}
			})
		}
	}
}
