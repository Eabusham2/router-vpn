package mobilemultihop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func entryCertificate(t *testing.T) string {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "entry.example"}, DNSNames: []string{"entry.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	data, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}))
}
func proxyEntryGraph(mode string) map[string]any {
	outbound := map[string]any{"type": mode, "tag": "proxy", "server": "192.0.2.44", "server_port": float64(443), "password": "entry-private-credential"}
	if mode == "shadowsocks" {
		outbound["method"] = "chacha20-ietf-poly1305"
	} else {
		outbound["tls"] = map[string]any{"enabled": true, "server_name": "entry.example", "certificate_path": "cert.pem"}
		outbound["obfs"] = map[string]any{"type": "salamander", "password": "entry-obfuscation"}
	}
	return map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true, "mtu": 1280}}, "outbounds": []any{outbound, map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"auto_detect_interface": true, "final": "proxy", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}}, "dns": map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "home-dns", "server": "10.77.0.1", "detour": "proxy"}}, "final": "home-dns"}}
}
func proxyEntryProfile(t *testing.T, root map[string]any, cert string) string {
	t.Helper()
	b, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString(b)}
	if cert != "" {
		files["cert.pem"] = base64.StdEncoding.EncodeToString([]byte(cert))
	}
	b, err = json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func proxyEntry(t *testing.T, mode string) map[string]any {
	t.Helper()
	cert := ""
	if mode == "hysteria2" {
		cert = entryCertificate(t)
	}
	text, err := CompileProxyEntry(proxyEntryProfile(t, proxyEntryGraph(mode), cert), mode)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal([]byte(text), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestProxyEntryPreservesCredentialsAndOwnCertificateWithoutStaging(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "hysteria2"} {
		t.Run(mode, func(t *testing.T) {
			root := proxyEntryGraph(mode)
			certificate := ""
			if mode == "hysteria2" {
				certificate = entryCertificate(t)
			}
			profile := proxyEntryProfile(t, root, certificate)
			before, _ := json.Marshal(root)
			output, err := CompileProxyEntry(profile, mode)
			if err != nil {
				t.Fatal(err)
			}
			var entry map[string]any
			json.Unmarshal([]byte(output), &entry)
			expected := root["outbounds"].([]any)[0].(map[string]any)
			if entry["type"] != mode || entry["tag"] != "routervpn-hop-entry" || entry["password"] != expected["password"] || entry["server"] != expected["server"] || entry["server_port"] != expected["server_port"] {
				t.Fatal("native entry identity or credential changed")
			}
			if mode == "hysteria2" {
				tls := entry["tls"].(map[string]any)
				if tls["certificate_path"] != nil || tls["server_name"] != "entry.example" || tls["certificate"].([]any)[0] != certificate || !reflect.DeepEqual(entry["obfs"], expected["obfs"]) {
					t.Fatal("entry trust or obfuscation changed")
				}
			}
			after, _ := json.Marshal(root)
			if string(before) != string(after) || proxyEntryProfile(t, root, certificate) != profile {
				t.Fatal("source node mutated")
			}
			repeated, err := CompileProxyEntry(profile, mode)
			if err != nil || repeated != output {
				t.Fatal("entry compilation is not deterministic")
			}
		})
	}
}
func TestProxyEntryRejectsUnownedPolicyAndCredentialLoss(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong-label", func(r map[string]any) { r["outbounds"].([]any)[0].(map[string]any)["type"] = "socks" }},
		{"second-proxy", func(r map[string]any) { r["outbounds"] = append(r["outbounds"].([]any), r["outbounds"].([]any)[0]) }},
		{"helper", func(r map[string]any) {
			r["outbounds"] = append(r["outbounds"].([]any), map[string]any{"type": "socks", "tag": "helper"})
		}},
		{"custom-route", func(r map[string]any) {
			r["route"].(map[string]any)["rules"] = []any{map[string]any{"network": "tcp", "action": "route", "outbound": "direct"}}
		}},
		{"route-set", func(r map[string]any) { r["route"].(map[string]any)["rule_set"] = []any{} }},
		{"second-endpoint", func(r map[string]any) { r["endpoints"] = []any{map[string]any{"type": "wireguard"}} }},
		{"service", func(r map[string]any) { r["services"] = []any{map[string]any{"type": "helper"}} }},
		{"opaque-state", func(r map[string]any) {
			r["experimental"] = map[string]any{"cache_file": map[string]any{"enabled": true}}
		}},
		{"missing-auth", func(r map[string]any) { delete(r["outbounds"].([]any)[0].(map[string]any), "password") }},
	}
	for _, key := range []string{"detour", "bind_interface", "domain_resolver", "routing_mark", "inet4_bind_address", "network_strategy"} {
		key := key
		cases = append(cases, struct {
			name   string
			mutate func(map[string]any)
		}{key, func(r map[string]any) { r["outbounds"].([]any)[0].(map[string]any)[key] = "foreign" }})
	}
	for _, key := range []string{"route_address", "route_exclude_address", "include_package", "exclude_uid"} {
		key := key
		cases = append(cases, struct {
			name   string
			mutate func(map[string]any)
		}{key, func(r map[string]any) { r["inbounds"].([]any)[0].(map[string]any)[key] = []any{} }})
	}
	for _, mode := range []string{"shadowsocks", "hysteria2"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				root := proxyEntryGraph(mode)
				cert := ""
				if mode == "hysteria2" {
					cert = entryCertificate(t)
				}
				tc.mutate(root)
				if _, err := CompileProxyEntry(proxyEntryProfile(t, root, cert), mode); err == nil {
					t.Fatal("unsafe entry was compiled")
				} else if strings.Contains(err.Error(), "entry-private-credential") {
					t.Fatal("credential leaked through error")
				}
			})
		}
	}
	for _, host := range []string{"entry.example", "127.0.0.1", "::1", "0.0.0.0", "::ffff:192.0.2.1", "fe80::1%eth0", "224.0.0.1"} {
		root := proxyEntryGraph("shadowsocks")
		root["outbounds"].([]any)[0].(map[string]any)["server"] = host
		if _, err := CompileProxyEntry(proxyEntryProfile(t, root, ""), "shadowsocks"); err == nil {
			t.Fatalf("unowned physical endpoint %s accepted", host)
		}
	}
	for _, network := range []any{"tcp", "udp", true, 42} {
		root := proxyEntryGraph("shadowsocks")
		root["outbounds"].([]any)[0].(map[string]any)["network"] = network
		if _, err := CompileProxyEntry(proxyEntryProfile(t, root, ""), "shadowsocks"); err == nil {
			t.Fatal("one-way entry accepted")
		}
	}
	root := proxyEntryGraph("shadowsocks")
	root["outbounds"].([]any)[0].(map[string]any)["method"] = "none"
	if _, err := CompileProxyEntry(proxyEntryProfile(t, root, ""), "shadowsocks"); err == nil {
		t.Fatal("plaintext entry accepted")
	}
}
func TestProxyEntryCertificateCannotComeFromExitOrHost(t *testing.T) {
	certificate := entryCertificate(t)
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		cert   string
	}{
		{"missing", func(r map[string]any) {}, ""},
		{"absolute", func(tls map[string]any) { tls["certificate_path"] = "/etc/ssl/certs.pem" }, certificate},
		{"parent", func(tls map[string]any) { tls["certificate_path"] = "../exit/cert.pem" }, certificate},
		{"two-authorities", func(tls map[string]any) { tls["certificate"] = []any{certificate} }, certificate},
		{"insecure", func(tls map[string]any) { tls["insecure"] = true }, certificate},
		{"malformed", func(tls map[string]any) {}, "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"},
		{"extra-key", func(tls map[string]any) {}, "not a certificate\n" + certificate},
		{"nested-host-path", func(tls map[string]any) { tls["ech"] = map[string]any{"config_path": "foreign"} }, certificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := proxyEntryGraph("hysteria2")
			tc.change(root["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any))
			if _, err := CompileProxyEntry(proxyEntryProfile(t, root, tc.cert), "hysteria2"); err == nil {
				t.Fatal("wrong trust source accepted")
			}
		})
	}
	for _, raw := range []string{`{}`, `{"sing-box.json":"%%"}`, `{"sing-box.json":"e30=","sing-box.json":"e30="}`, `{"sing-box.json":"e30=","xray.json":"e30="}`, strings.Repeat(" ", 8<<20) + "{}"} {
		if _, err := CompileProxyEntry(raw, "hysteria2"); err == nil {
			t.Fatal("unbounded or ambiguous profile accepted")
		}
	}
}
func TestProxyEntriesUseSameRetainedExecutionController(t *testing.T) {
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	for _, mode := range []string{"shadowsocks", "hysteria2"} {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run(mode+"/"+execution, func(t *testing.T) {
				config, metadata := fixture(t, execution)
				var graph map[string]any
				json.Unmarshal([]byte(config), &graph)
				delete(graph, "endpoints")
				entry := proxyEntry(t, mode)
				entry["tag"] = "entry-wg"
				graph["outbounds"] = append(graph["outbounds"].([]any), entry)
				var meta Metadata
				json.Unmarshal([]byte(metadata), &meta)
				meta.EntryMode = mode
				raw, _ := json.Marshal(graph)
				private, _ := json.Marshal(meta)
				controller, err := New(string(raw), string(private))
				if err != nil {
					t.Fatal(err)
				}
				engine := makeEngine(t)
				if err = controller.Run(context.Background(), engine); err != nil {
					t.Fatal(err)
				}
				if !controller.Healthy() {
					t.Fatal("entry lost retained engine identity")
				}
				if err = controller.Close(); err != nil {
					t.Fatal(err)
				}
				if engine.lease != nil || engine.secretLeak || len(engine.errors) != 0 {
					t.Fatal("proxy entry changed node proof, credentials or cleanup")
				}
				var output map[string]any
				json.Unmarshal([]byte(controller.Config()), &output)
				for _, item := range output["outbounds"].([]any) {
					value := item.(map[string]any)
					if value["tag"] == "entry-wg" && !reflect.DeepEqual(value, entry) {
						t.Fatal("selector changed the native entry")
					}
				}
				// A forged graph cannot put a proxy under the native packet endpoint manager.
				graph["endpoints"] = []any{entry}
				graph["outbounds"] = graph["outbounds"].([]any)[:1]
				raw, _ = json.Marshal(graph)
				if _, err = New(string(raw), string(private)); err == nil {
					t.Fatal("proxy entry mislabeled as packet endpoint")
				}
			})
		}
	}
}
