package multihoprelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func naiveFixture(mode string) map[string]any {
	return map[string]any{"type": "naive", "tag": "proxy", "server": "192.0.2.4", "server_port": float64(13443),
		"username": "private-test-user", "password": "private-test-password", "quic": mode == "naive-h3",
		"udp_over_tcp": map[string]any{"enabled": true, "version": float64(2)},
		"tls":          map[string]any{"enabled": true, "server_name": "fixture.example.test"}}
}
func TestNaivePairedRelayPreservesFullTransport(t *testing.T) {
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				cfg := config()
				exit := &cfg.Exits[0]
				exit.Mode = mode
				exit.DNS = "192.168.50.133"
				exit.Transport = naiveFixture(mode)
				if layer != "" {
					exit.StartLayer = &StartLayer{Mode: layer, API: "http://10.88.0.1:8787", Transport: map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.4", "server_port": float64(8388), "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))}}
				}
				before, _ := json.Marshal(cfg)
				run := &runner{}
				manager, err := New(cfg, req().EntryNodeID, run)
				if err != nil {
					t.Fatal(err)
				}
				request := req()
				request.ExitMode = mode
				request.ExitStartLayer = layer
				lease, err := manager.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), request)
				if err != nil {
					t.Fatal(err)
				}
				if len(run.configs) != 1 || lease.ExitMode != mode {
					t.Fatal("relay selected a different mode")
				}
				var graph map[string]any
				if json.Unmarshal(run.configs[0], &graph) != nil {
					t.Fatal("invalid graph")
				}
				out := graph["outbounds"].([]any)[0].(map[string]any)
				expected, _ := copyMap(exit.Transport)
				expected["tag"] = "exit"
				if layer != "" {
					expected["detour"] = ExitStartLayerTag
					expected["server"] = "10.88.0.1"
				}
				if !reflect.DeepEqual(expected, out) {
					t.Fatal("Naive credentials, HTTP version or trust changed")
				}
				dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["server"] != "192.168.50.133" || dns["detour"] != "exit" {
					t.Fatal("AdGuard is not exit-routed")
				}
				if len(graph["inbounds"].([]any)) != 1 || graph["endpoints"] != nil {
					t.Fatal("extra VPN or tunnel owner")
				}
				after, _ := json.Marshal(cfg)
				if string(after) != string(before) {
					t.Fatal("paired source mutated")
				}
				if err = manager.Delete(context.Background(), netip.MustParseAddr("10.77.0.2"), request); err != nil || run.processes[0].alive {
					t.Fatal("lease teardown failed", err)
				}
			})
		}
	}
}
func TestNaiveRejectsUnownedOrDowngradedTransport(t *testing.T) {
	faults := map[string]func(map[string]any){
		"http-proxy":              func(v map[string]any) { v["type"] = "http" },
		"wrong-http-version":      func(v map[string]any) { v["quic"] = !(v["quic"].(bool)) },
		"missing-http-version":    func(v map[string]any) { delete(v, "quic") },
		"nonboolean-http-version": func(v map[string]any) { v["quic"] = "true" },
		"tcp-only":                func(v map[string]any) { v["udp_over_tcp"] = false },
		"uot-version1":            func(v map[string]any) { v["udp_over_tcp"].(map[string]any)["version"] = float64(1) },
		"uot-version-string":      func(v map[string]any) { v["udp_over_tcp"].(map[string]any)["version"] = "2" },
		"uot-unowned":             func(v map[string]any) { v["udp_over_tcp"].(map[string]any)["detour"] = "direct" },
		"username":                func(v map[string]any) { delete(v, "username") },
		"ambiguous-basic-auth":    func(v map[string]any) { v["username"] = "user:other" },
		"password":                func(v map[string]any) { v["password"] = "" },
		"unbounded-password":      func(v map[string]any) { v["password"] = strings.Repeat("x", 4097) },
		"invalid-utf8":            func(v map[string]any) { v["password"] = string([]byte{255}) },
		"unverified":              func(v map[string]any) { v["tls"].(map[string]any)["insecure"] = true },
		"no-tls":                  func(v map[string]any) { v["tls"].(map[string]any)["enabled"] = false },
		"no-sni":                  func(v map[string]any) { delete(v["tls"].(map[string]any), "server_name") },
		"sni-injection":           func(v map[string]any) { v["tls"].(map[string]any)["server_name"] = "fixture.example.test\r\n" },
		"certificate-path":        func(v map[string]any) { v["tls"].(map[string]any)["certificate_path"] = "exit.pem" },
		"unowned-ech-dns":         func(v map[string]any) { v["tls"].(map[string]any)["ech"] = map[string]any{"enabled": true} },
		"empty-certificate":       func(v map[string]any) { v["tls"].(map[string]any)["certificate"] = []any{} },
		"invalid-certificate":     func(v map[string]any) { v["tls"].(map[string]any)["certificate"] = "not a cert" },
		"direct-detour":           func(v map[string]any) { v["detour"] = "direct" },
		"bind-interface":          func(v map[string]any) { v["bind_interface"] = "eth0" },
		"system-dns":              func(v map[string]any) { v["domain_resolver"] = "local" },
		"localhost":               func(v map[string]any) { v["server"] = "127.0.0.1" },
		"hostname":                func(v map[string]any) { v["server"] = "node.example.test" },
		"port":                    func(v map[string]any) { v["server_port"] = float64(3.5) },
	}
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		for name, mutate := range faults {
			t.Run(mode+"/"+name, func(t *testing.T) {
				value := naiveFixture(mode)
				mutate(value)
				if err := ValidateNaiveTransport(value, mode); err == nil {
					t.Fatal("unowned Naive transport accepted")
				}
				exit := Exit{ID: "exit", NodeID: strings.Repeat("b", 64), Mode: mode, DNS: "192.168.50.133", Transport: value}
				if _, err := validateTransport(exit); err == nil {
					t.Fatal("paired registry bypassed Naive validation")
				}
			})
		}
	}
}
