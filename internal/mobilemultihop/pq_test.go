package mobilemultihop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func pqFixture(mode string) (map[string]string, string) {
	raw, id := wireGuardFixture()
	asset, tool := "wg.conf", "wg"
	if mode == "awg2-pq" {
		raw, id = amneziaFixture()
		asset, tool = "awg.conf", "awg"
	}
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("b"), 32))
	files := map[string][]byte{
		asset:                     []byte(raw),
		"rosenpass-client-secret": bytes.Repeat([]byte{1}, 64),
		"rosenpass-client-public": bytes.Repeat([]byte{2}, 128),
		"rosenpass-server-public": bytes.Repeat([]byte{3}, 128),
		"rosenpass.env":           []byte("ROSENPASS_TOOL=" + tool + "\nROSENPASS_INTERFACE=" + tool + "\nROSENPASS_WG_PEER=" + public + "\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n"),
		"rosenpass.toml":          []byte("public_key = \"rosenpass-client-public\"\nsecret_key = \"rosenpass-client-secret\"\nlisten = []\nverbosity = \"Quiet\"\n\n[[peers]]\npublic_key = \"rosenpass-server-public\"\nendpoint = \"original-router.example:51822\"\nkey_out = \"rosenpass.psk\"\n"),
	}
	encoded := map[string]string{}
	for name, data := range files {
		encoded[name] = base64.StdEncoding.EncodeToString(data)
	}
	return encoded, id
}
func pqEncoded(files map[string]string) string { out, _ := json.Marshal(files); return string(out) }
func pqEndpoint(t *testing.T, graph string) map[string]any {
	t.Helper()
	var root map[string]any
	if json.Unmarshal([]byte(graph), &root) != nil {
		t.Fatal("invalid graph")
	}
	return root["endpoints"].([]any)[0].(map[string]any)
}
func pqReplace(files map[string]string, name, old, replacement string) {
	data, _ := base64.StdEncoding.DecodeString(files[name])
	files[name] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(data), old, replacement, 1)))
}

func TestPQCompilerPreservesSelectedNativePeerAndDevicePolicy(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		t.Run(mode, func(t *testing.T) {
			files, id := pqFixture(mode)
			before := pqEncoded(files)
			graph, err := CompilePQProfile(mode, before, id)
			if err != nil {
				t.Fatal(err)
			}
			if pqEncoded(files) != before {
				t.Fatal("saved private asset map changed")
			}
			var root map[string]any
			_ = json.Unmarshal([]byte(graph), &root)
			if len(root["outbounds"].([]any)) != 0 || len(root["endpoints"].([]any)) != 1 || len(root["inbounds"].([]any)) != 1 {
				t.Fatal("extra interface or fallback added")
			}
			ep := pqEndpoint(t, graph)
			if ep["type"] != PQType || ep["mode"] != mode || ep["tag"] != "proxy" || ep["node_id"] != id || ep["mtu"] != float64(1420) {
				t.Fatal("captured endpoint policy changed")
			}
			pq := ep["pq"].(map[string]any)
			if pq["endpoint"] != "192.0.2.1:51822" || pq["version"] != float64(2) {
				t.Fatal("native PQ did not capture the original peer IP")
			}
			for source, target := range map[string]string{"rosenpass-client-secret": "secret", "rosenpass-client-public": "public", "rosenpass-server-public": "peer"} {
				if pq[target] != files[source] {
					t.Fatal("captured binary key changed", source)
				}
			}
			dns := root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if dns["server"] != "192.168.50.133" || dns["detour"] != "proxy" {
				t.Fatal("selected AdGuard was replaced")
			}
			raw, _ := json.Marshal(ep)
			runtime, err := PQRuntimeConfig(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			var base map[string]any
			_ = json.Unmarshal([]byte(runtime.BaseJSON), &base)
			if base["type"] != nil || base["tag"] != nil || runtime.Mode != mode || !bytes.Equal(runtime.PeerPublic, bytes.Repeat([]byte("b"), 32)) {
				t.Fatal("native adapter identity changed")
			}
			if !reflect.DeepEqual(base["peers"], ep["peers"]) || !reflect.DeepEqual(base["address"], ep["address"]) {
				t.Fatal("native peer or addresses changed")
			}
			if mode == "awg2-pq" {
				if len(base["amnezia"].(map[string]any)) != 11 {
					t.Fatal("AWG parameters dropped")
				}
			} else if base["amnezia"] != nil {
				t.Fatal("ordinary WG became AWG")
			}
		})
	}
}
func TestPQCompilerRejectsMalformedOrWrongPeerAssets(t *testing.T) {
	mutations := map[string]func(map[string]string){
		"missing-secret":  func(f map[string]string) { delete(f, "rosenpass-client-secret") },
		"invalid-base64":  func(f map[string]string) { f["rosenpass-server-public"] = "!" },
		"same-native-key": func(f map[string]string) { f["rosenpass-server-public"] = f["rosenpass-client-public"] },
		"empty-secret": func(f map[string]string) {
			f["rosenpass-client-secret"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		},
		"path": func(f map[string]string) { f["../peer"] = f["rosenpass-server-public"] },
		"extra-env": func(f map[string]string) {
			pqReplace(f, "rosenpass.env", "ROSENPASS_TOOL=", "INJECTED=command\nROSENPASS_TOOL=")
		},
		"shell-env": func(f map[string]string) {
			pqReplace(f, "rosenpass.env", "ROSENPASS_PORT=51822", "ROSENPASS_PORT=$(command)")
		},
		"wrong-tool": func(f map[string]string) { pqReplace(f, "rosenpass.env", "ROSENPASS_TOOL=wg", "ROSENPASS_TOOL=awg") },
		"wrong-interface": func(f map[string]string) {
			pqReplace(f, "rosenpass.env", "ROSENPASS_INTERFACE=wg", "ROSENPASS_INTERFACE=other")
		},
		"wrong-peer": func(f map[string]string) {
			pqReplace(f, "rosenpass.env", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("b"), 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 32)))
		},
		"duplicate-env": func(f map[string]string) {
			pqReplace(f, "rosenpass.env", "ROSENPASS_PORT=51822", "ROSENPASS_PORT=51822\nROSENPASS_PORT=51822")
		},
		"wrong-port": func(f map[string]string) { pqReplace(f, "rosenpass.toml", ":51822", ":51823") },
		"listener": func(f map[string]string) {
			pqReplace(f, "rosenpass.toml", "listen = []", "listen = [\"0.0.0.0:51822\"]")
		},
		"second-peer": func(f map[string]string) { pqReplace(f, "rosenpass.toml", "[[peers]]", "[[peers]]\n[[peers]]") },
		"absolute-key": func(f map[string]string) {
			pqReplace(f, "rosenpass.toml", "\"rosenpass-client-secret\"", "\"/other/private-key\"")
		},
		"unknown-toml": func(f map[string]string) { pqReplace(f, "rosenpass.toml", "[[peers]]", "command = \"no\"\n[[peers]]") },
		"duplicate-toml": func(f map[string]string) {
			pqReplace(f, "rosenpass.toml", "verbosity = \"Quiet\"", "verbosity = \"Quiet\"\nverbosity = \"Quiet\"")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			files, id := pqFixture("wg-pq")
			mutate(files)
			if _, err := CompilePQProfile("wg-pq", pqEncoded(files), id); err == nil {
				t.Fatal("invalid PQ asset set accepted")
			}
		})
	}
	files, id := pqFixture("wg-pq")
	for _, mode := range []string{"wg", "max", "awg2-fast", "fake-pq"} {
		if _, err := CompilePQProfile(mode, pqEncoded(files), id); err == nil {
			t.Fatal("unimplemented composition relabeled", mode)
		}
	}
	if _, err := CompilePQProfile("wg-pq", pqEncoded(files), strings.Repeat("f", 64)); err == nil {
		t.Fatal("wrong node accepted")
	}
	if _, err := CompilePQProfile("wg-pq", `{"wg.conf":"","wg.conf":""}`, id); err == nil {
		t.Fatal("duplicate source asset accepted")
	}
}
func TestPQRuntimeRejectsReassignedTransportAndHiddenDirectives(t *testing.T) {
	files, id := pqFixture("wg-pq")
	graph, err := CompilePQProfile("wg-pq", pqEncoded(files), id)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(map[string]any){
		"unknown":        func(ep map[string]any) { ep["bind_interface"] = "public" },
		"unknown-pq":     func(ep map[string]any) { ep["pq"].(map[string]any)["fallback"] = true },
		"different-host": func(ep map[string]any) { ep["pq"].(map[string]any)["endpoint"] = "192.0.2.2:51822" },
		"hostname":       func(ep map[string]any) { ep["pq"].(map[string]any)["endpoint"] = "resolver.example:51822" },
		"system":         func(ep map[string]any) { ep["system"] = true },
		"listen":         func(ep map[string]any) { ep["listen_port"] = 51820 },
		"peer-count":     func(ep map[string]any) { ep["peers"] = append(ep["peers"].([]any), ep["peers"].([]any)[0]) },
		"downgrade":      func(ep map[string]any) { ep["type"] = "wireguard" },
		"missing-pq":     func(ep map[string]any) { delete(ep, "pq") },
		"wrong-mode":     func(ep map[string]any) { ep["mode"] = "awg2-pq" },
		"wg-obfuscation": func(ep map[string]any) { ep["amnezia"] = map[string]any{"jc": "3"} },
		"invalid-detour": func(ep map[string]any) { ep["detour"] = "../other" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			ep := pqEndpoint(t, graph)
			mutate(ep)
			raw, _ := json.Marshal(ep)
			if _, err := PQRuntimeConfig(string(raw)); err == nil {
				t.Fatal("unowned runtime configuration accepted")
			}
		})
	}
	ep := pqEndpoint(t, graph)
	ep["detour"] = "captured-entry"
	raw, _ := json.Marshal(ep)
	runtime, err := PQRuntimeConfig(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(runtime.BaseJSON, `"detour":"captured-entry"`) {
		t.Fatal("entry ownership dropped")
	}
}
