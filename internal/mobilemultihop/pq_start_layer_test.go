package mobilemultihop

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPQStartLayerOwnsBothEncryptedExchanges(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, service := range []string{"http://10.77.0.1:8787", "https://[fd77:77::1]:8787"} {
				t.Run(mode+"/"+layer+"/"+service, func(t *testing.T) {
					files, id := pqFixture(mode)
					graph, err := CompilePQProfile(mode, pqEncoded(files), id)
					if err != nil {
						t.Fatal(err)
					}
					_, outer, metadata := baseStartFixture(t, "wg", layer, service)
					meta := startObject(t, metadata)
					meta["raw_mode"] = mode
					result, err := ComposeNativeBaseStartLayer(graph, outer, startJSON(t, meta))
					if err != nil {
						t.Fatal(err)
					}
					before, after := startObject(t, graph), startObject(t, result)
					for _, field := range []string{"dns", "route", "inbounds"} {
						if startJSON(t, before[field]) != startJSON(t, after[field]) {
							t.Fatal("device policy changed", field)
						}
					}
					ep := pqEndpoint(t, result)
					original := pqEndpoint(t, graph)
					host := "10.77.0.1"
					address := host + ":51822"
					if strings.Contains(service, "fd77") {
						host = "fd77:77::1"
						address = "[" + host + "]:51822"
					}
					original["detour"] = NativeStartLayerTag
					original["peers"].([]any)[0].(map[string]any)["address"] = host
					original["pq"].(map[string]any)["endpoint"] = address
					if startJSON(t, original) != startJSON(t, ep) {
						t.Fatal("base identity, negotiated-key inputs, MTU or AWG parameters changed")
					}
					raw, _ := json.Marshal(ep)
					runtime, err := PQRuntimeConfig(string(raw))
					if err != nil {
						t.Fatal(err)
					}
					runtime.PQ.Erase()
					if runtime.Mode != mode || len(after["outbounds"].([]any)) != 1 {
						t.Fatal("protocol or outer transport ownership changed")
					}
					if _, err = ComposeNativeBaseStartLayer(result, outer, startJSON(t, meta)); err == nil {
						t.Fatal("duplicate outer ownership accepted")
					}
				})
			}
		}
	}
}

func TestPQStartLayerRejectsDowngradedOrReassignedHandshake(t *testing.T) {
	files, id := pqFixture("wg-pq")
	graph, err := CompilePQProfile("wg-pq", pqEncoded(files), id)
	if err != nil {
		t.Fatal(err)
	}
	_, outer, metadata := baseStartFixture(t, "wg", "aes-256-gcm", "http://10.77.0.1:8787")
	meta := startObject(t, metadata)
	meta["raw_mode"] = "wg-pq"
	for name, change := range map[string]func(map[string]any){
		"missing-handshake":        func(ep map[string]any) { delete(ep, "pq") },
		"downgraded-base":          func(ep map[string]any) { ep["type"] = "wireguard" },
		"wrong-mode":               func(ep map[string]any) { ep["mode"] = "awg2-pq" },
		"wrong-node":               func(ep map[string]any) { ep["node_id"] = strings.Repeat("f", 64) },
		"different-handshake-host": func(ep map[string]any) { ep["pq"].(map[string]any)["endpoint"] = "192.0.2.2:51822" },
		"hidden-handshake-route":   func(ep map[string]any) { ep["pq"].(map[string]any)["detour"] = "direct" },
		"unknown-endpoint-option":  func(ep map[string]any) { ep["bind_interface"] = "physical" },
	} {
		t.Run(name, func(t *testing.T) {
			g := startObject(t, graph)
			change(g["endpoints"].([]any)[0].(map[string]any))
			if _, err := ComposeNativeBaseStartLayer(startJSON(t, g), outer, startJSON(t, meta)); err == nil {
				t.Fatal("unowned PQ composition accepted")
			}
		})
	}
	if _, err = ComposeNativeBaseStartLayer(graph, outer, metadata); err == nil {
		t.Fatal("PQ endpoint relabeled as ordinary WireGuard")
	}
}
