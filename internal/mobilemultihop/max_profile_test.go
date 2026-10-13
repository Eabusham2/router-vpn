package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func maxFixture(t *testing.T, mode string) (map[string]string, string) {
	t.Helper()
	pqMode, file, compat, tool, tunnel := "wg-pq", "wg.conf", "wg-socks.conf", "wg", "10.77.0.1"
	if strings.HasSuffix(mode, "-awg") {
		pqMode, file, compat, tool, tunnel = "awg2-pq", "awg.conf", "awg-socks.conf", "awg", "10.78.0.1"
	}
	files, id := pqFixture(pqMode)
	raw, _ := base64.StdEncoding.DecodeString(files[file])
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		key, _, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "Endpoint") {
			lines[i] = "Endpoint=127.0.0.1:51830"
		}
	}
	files[file] = base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
	files[compat] = files[file]
	pqReplace(files, "rosenpass.toml", "original-router.example", tunnel)
	encode := func(v any) string {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	ss := map[string]any{"type": "shadowsocks", "tag": "ss-hop", "server": "127.0.0.1", "server_port": 8388, "method": NativeStartLayerMethod, "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))), "detour": "outer"}
	var outer map[string]any
	engine, layers := "sing-box", "rosenpass-pq>base>shadowsocks2022>hysteria2-quic"
	if strings.HasPrefix(mode, "max-tls-") {
		engine, layers = "xray", "rosenpass-pq>base>shadowsocks2022>xray-vless-pq-reality-xhttp-finalmask"
		_, xray := xrayEntryFixture(t, "reality-xhttp")
		files["outer-xray.json"] = encode(xray)
		outer = map[string]any{"type": "socks", "tag": "outer", "server": "127.0.0.1", "server_port": 1090, "version": "5"}
	} else {
		outer = map[string]any{"type": "hysteria2", "tag": "outer", "server": "192.0.2.44", "server_port": 8443, "password": "exact-quic-credential", "tls": map[string]any{"enabled": true, "server_name": "entry.example", "certificate_path": "cert.pem"}}
		files["cert.pem"] = base64.StdEncoding.EncodeToString([]byte(entryCertificate(t)))
	}
	port := 51820
	if tool == "awg" {
		port = 585
	}
	middle := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{map[string]any{"type": "direct", "tag": "base-relay", "listen": "127.0.0.1", "listen_port": 51830, "network": "udp", "override_address": "127.0.0.1", "override_port": port}}, "outbounds": []any{outer, ss}, "route": map[string]any{"final": "ss-hop"}}
	files["middle-sing-box.json"] = encode(middle)
	files["chain.env"] = base64.StdEncoding.EncodeToString([]byte("CHAIN_READY=1\nOUTER_ENGINE=" + engine + "\nCHAIN_LAYERS=" + layers + "\nLOCAL_RELAY_PORT=51830\nPQ_BASE=1\n"))
	metadata, _ := json.Marshal(maxPolicy{NodeID: id, NodeKind: "router-vpn", RouterAPI: "http://10.77.0.1:8787", Endpoint: "192.0.2.44"})
	return files, string(metadata)
}
func maxObject(t *testing.T, encoded string) map[string]any {
	t.Helper()
	raw, e := base64.StdEncoding.Strict().DecodeString(encoded)
	if e != nil {
		t.Fatal(e)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("bad fixture JSON")
	}
	return value
}
func maxChange(t *testing.T, files map[string]string, name string, change func(map[string]any)) {
	t.Helper()
	value := maxObject(t, files[name])
	change(value)
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	files[name] = base64.StdEncoding.EncodeToString(raw)
}
func TestCompleteMAXNativeChainsRetainEveryLayer(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, service := range []string{"10.77.0.1", "fd77:77::1"} {
			t.Run(mode+"/"+service, func(t *testing.T) {
				files, policy := maxFixture(t, mode)
				if strings.Contains(service, ":") {
					policy = strings.Replace(policy, "http://10.77.0.1:8787", "https://[fd77:77::1]:8787", 1)
				}
				before := pqEncoded(files)
				result, err := CompileMAXProfile(mode, before, policy)
				if err != nil {
					t.Fatal(err)
				}
				if pqEncoded(files) != before {
					t.Fatal("saved sources changed")
				}
				var root map[string]any
				json.Unmarshal([]byte(result), &root)
				inbounds, eps, outs := root["inbounds"].([]any), root["endpoints"].([]any), root["outbounds"].([]any)
				if len(inbounds) != 1 || inbounds[0].(map[string]any)["type"] != "tun" || len(eps) != 1 || len(outs) != 2 {
					t.Fatal("complete MAX must own one VPN and all encrypted layers")
				}
				ep := eps[0].(map[string]any)
				ss := outs[0].(map[string]any)
				outer := outs[1].(map[string]any)
				wantedMode, rawName, port := "wg-pq", "wg.conf", float64(51820)
				if strings.HasSuffix(mode, "-awg") {
					wantedMode, rawName, port = "awg2-pq", "awg.conf", 585
				}
				if ep["type"] != PQType || ep["mode"] != wantedMode || ep["detour"] != MAXShadowsocksTag || ep["tag"] != "proxy" {
					t.Fatal("PQ base downgraded or bypassed")
				}
				peer := ep["peers"].([]any)[0].(map[string]any)
				pq := ep["pq"].(map[string]any)
				rp := service + ":51822"
				if strings.Contains(service, ":") {
					rp = "[" + service + "]:51822"
				}
				if peer["address"] != service || peer["port"] != port || pq["endpoint"] != rp {
					t.Fatal("WG and PQ do not share the same owned nested transport")
				}
				for field, name := range map[string]string{"secret": "rosenpass-client-secret", "public": "rosenpass-client-public", "peer": "rosenpass-server-public"} {
					if pq[field] != files[name] {
						t.Fatal("captured key material changed", field)
					}
				}
				raw, _ := base64.StdEncoding.DecodeString(files[rawName])
				if !strings.Contains(string(raw), ep["private_key"].(string)) {
					t.Fatal("base private key replaced")
				}
				if wantedMode == "awg2-pq" {
					if len(ep["amnezia"].(map[string]any)) != 11 {
						t.Fatal("AWG parameters missing")
					}
				} else if ep["amnezia"] != nil {
					t.Fatal("WG silently became AWG")
				}
				if ss["type"] != "shadowsocks" || ss["method"] != NativeStartLayerMethod || ss["tag"] != MAXShadowsocksTag || ss["detour"] != MAXOuterTag || ss["server"] != service {
					t.Fatal("SS2022 middle layer lost")
				}
				if ss["password"] != maxObject(t, files["middle-sing-box.json"])["outbounds"].([]any)[1].(map[string]any)["password"] {
					t.Fatal("SS2022 credentials changed")
				}
				if outer["tag"] != MAXOuterTag || outer["detour"] != nil {
					t.Fatal("unexpected outer routing")
				}
				if strings.HasPrefix(mode, "max-tls-") {
					source, _ := base64.StdEncoding.DecodeString(files["outer-xray.json"])
					if outer["type"] != "routervpn-xray" || outer["mode"] != "reality-xhttp" || outer["config_json"] != string(source) {
						t.Fatal("PQ VLESS/REALITY/XHTTP/FinalMask/uTLS changed")
					}
				} else {
					cert, _ := base64.StdEncoding.DecodeString(files["cert.pem"])
					tls := outer["tls"].(map[string]any)
					if outer["type"] != "hysteria2" || outer["password"] != "exact-quic-credential" || tls["certificate_path"] != nil || tls["certificate"].([]any)[0] != string(cert) {
						t.Fatal("QUIC credentials or captured trust changed")
					}
				}
				dns := root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["detour"] != "proxy" || dns["server"] != "192.168.50.133" {
					t.Fatal("home AdGuard bypassed or replaced")
				}
				encoded, _ := json.Marshal(ep)
				parsed, e := PQRuntimeConfig(string(encoded))
				if e != nil {
					t.Fatal(e)
				}
				parsed.PQ.Erase()
				again, e := CompileMAXProfile(mode, before, policy)
				if e != nil || again != result {
					t.Fatal("compiler changed input or is nondeterministic")
				}
			})
		}
	}
}
func TestCompleteMAXRejectsOmittedDowngradedAndUnownedLayers(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		file := "wg.conf"
		if strings.HasSuffix(mode, "-awg") {
			file = "awg.conf"
		}
		mutations := map[string]func(map[string]string){
			"wrong-PQ-tunnel": func(f map[string]string) {
				pqReplace(f, "rosenpass.toml", "10.77.0.1", "10.78.0.1")
				if strings.HasSuffix(mode, "-awg") {
					pqReplace(f, "rosenpass.toml", "10.78.0.1", "10.77.0.1")
				}
			},
			"missing-PQ-secret":   func(f map[string]string) { delete(f, "rosenpass-client-secret") },
			"wrong-PQ-peer":       func(f map[string]string) { f["rosenpass-server-public"] = f["rosenpass-client-public"] },
			"base-bypass":         func(f map[string]string) { pqReplace(f, file, "127.0.0.1:51830", "198.51.100.9:51830") },
			"base-local-port":     func(f map[string]string) { pqReplace(f, file, "127.0.0.1:51830", "127.0.0.1:51831") },
			"missing-PQ-label":    func(f map[string]string) { pqReplace(f, "chain.env", "PQ_BASE=1", "PQ_BASE=0") },
			"omitted-layer-label": func(f map[string]string) { pqReplace(f, "chain.env", "shadowsocks2022>", "") },
			"unready":             func(f map[string]string) { pqReplace(f, "chain.env", "CHAIN_READY=1", "CHAIN_READY=0") },
			"execute-env":         func(f map[string]string) { pqReplace(f, "chain.env", "PQ_BASE=1", "PQ_BASE=1\nCOMMAND=anything") },
			"duplicate-env":       func(f map[string]string) { pqReplace(f, "chain.env", "PQ_BASE=1", "PQ_BASE=1\nPQ_BASE=1") },
			"unowned-asset": func(f map[string]string) {
				f["unowned.sh"] = base64.StdEncoding.EncodeToString([]byte("do not execute"))
			},
			"ambiguous-encoding": func(f map[string]string) { f["chain.env"] += "\n" },
			"middle-no-SS": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { g["outbounds"] = g["outbounds"].([]any)[:1] })
			},
			"middle-plaintext": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { g["outbounds"].([]any)[1].(map[string]any)["method"] = "none" })
			},
			"middle-weak-cipher": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { g["outbounds"].([]any)[1].(map[string]any)["method"] = "aes-128-gcm" })
			},
			"middle-wrong-key": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { g["outbounds"].([]any)[1].(map[string]any)["password"] = "incorrect" })
			},
			"middle-host": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { g["outbounds"].([]any)[1].(map[string]any)["server"] = "192.0.2.12" })
			},
			"middle-no-outer": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { delete(g["outbounds"].([]any)[1].(map[string]any), "detour") })
			},
			"middle-extra-listener": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { g["inbounds"] = append(g["inbounds"].([]any), g["inbounds"].([]any)[0]) })
			},
			"middle-hidden-route": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { g["route"].(map[string]any)["rules"] = []any{} })
			},
			"middle-hidden-field": func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) { g["services"] = []any{} })
			},
		}
		if strings.HasPrefix(mode, "max-tls-") {
			mutations["outer-VLESS-no-PQ"] = func(f map[string]string) {
				maxChange(t, f, "outer-xray.json", func(g map[string]any) {
					g["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["encryption"] = "none"
				})
			}
			mutations["outer-missing-FinalMask"] = func(f map[string]string) {
				maxChange(t, f, "outer-xray.json", func(g map[string]any) {
					delete(g["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any), "finalmask")
				})
			}
			mutations["outer-missing-Chrome"] = func(f map[string]string) { pqReplace(f, "outer-xray.json", "chrome", "firefox") }
			mutations["outer-wrong-node"] = func(f map[string]string) { pqReplace(f, "outer-xray.json", "192.0.2.44", "192.0.2.45") }
			mutations["outer-port-not-correlated"] = func(f map[string]string) { pqReplace(f, "outer-xray.json", "1090", "1091") }
		} else {
			mutations["outer-wrong-node"] = func(f map[string]string) { pqReplace(f, "middle-sing-box.json", "192.0.2.44", "192.0.2.45") }
			mutations["outer-missing-trust"] = func(f map[string]string) { delete(f, "cert.pem") }
			mutations["outer-unverified-TLS"] = func(f map[string]string) {
				maxChange(t, f, "middle-sing-box.json", func(g map[string]any) {
					g["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["insecure"] = true
				})
			}
		}
		for name, mutate := range mutations {
			t.Run(mode+"/"+name, func(t *testing.T) {
				files, policy := maxFixture(t, mode)
				mutate(files)
				before := pqEncoded(files)
				if _, err := CompileMAXProfile(mode, before, policy); err == nil {
					t.Fatal("incomplete or unowned chain accepted")
				}
				if before != pqEncoded(files) {
					t.Fatal("rejected inputs changed")
				}
			})
		}
	}
}
func TestCompleteMAXCapturedPolicyCannotBeReassigned(t *testing.T) {
	files, policy := maxFixture(t, "max-tls-wg")
	for _, value := range []string{strings.Replace(policy, "10.77.0.1", "127.0.0.1", 1), strings.Replace(policy, "http://10.77.0.1:8787", "http://10.77.0.1:8787/path", 1), strings.Replace(policy, "router-vpn", "imported", 1), strings.Replace(policy, "192.0.2.44", "192.0.2.45", 1), strings.Replace(policy, "192.0.2.44", "node.example.test", 1), strings.TrimSuffix(policy, "}") + `,"unowned":true}`} {
		if _, err := CompileMAXProfile("max-tls-wg", pqEncoded(files), value); err == nil {
			t.Fatal("changed captured node policy accepted")
		}
	}
	for _, mode := range []string{"max", "all", "MAX-TLS-WG", "max-tls-wg\n", "max-tls", "wg-pq"} {
		if _, err := CompileMAXProfile(mode, pqEncoded(files), policy); err == nil {
			t.Fatal("another mode mislabeled as complete MAX")
		}
	}
	var parsed map[string]any
	json.Unmarshal([]byte(policy), &parsed)
	parsed["node_id"] = strings.Repeat("f", 64)
	changed, _ := json.Marshal(parsed)
	if _, err := CompileMAXProfile("max-tls-wg", pqEncoded(files), string(changed)); err == nil {
		t.Fatal("wrong base node proof accepted")
	}
	if reflect.DeepEqual(files, map[string]string{}) {
		t.Fatal("fixture missing")
	}
}
