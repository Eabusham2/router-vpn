package nativecomposite

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
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

func encoded(value any) string { raw, _ := json.Marshal(value); return string(raw) }
func parsed(t *testing.T, source string) map[string]any {
	t.Helper()
	value, err := object([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func fixture(t *testing.T, mode, node, layer, dnsType string) (string, string, string) {
	t.Helper()
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node.test"}, DNSNames: []string{"node.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	helperPort := 1090
	helperName := "xray.json"
	user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
	if mode == "max" {
		user["encryption"] = "mlkem768x25519plus.native.0rtt.public-authentication-fixture"
	}
	helper := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": helperPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}},
		"outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "192.0.2.1", "port": 10443, "users": []any{user}}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "node.test", "fingerprint": "chrome", "password": "public-key-fixture", "shortId": "0123456789abcdef"}}}},
	}
	if mode == "ss-v2ray" {
		helperPort = 1092
		helperName = "sslocal.json"
		helper = map[string]any{"server": "192.0.2.1", "server_port": 10443, "password": secret, "method": "2022-blake3-aes-256-gcm", "local_address": "127.0.0.1", "local_port": helperPort, "mode": "tcp_only", "plugin": "v2ray-plugin", "plugin_opts": "tls;host=node.test;path=/shadowsocks"}
	}
	dnsTag := "proxy" // Exact generated split/MAX inherited alias.
	if mode == "ss-v2ray" {
		dnsTag = "tcp-stack"
	}
	graph := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "interface_name": "router-vpn-" + mode, "auto_route": true, "strict_route": true, "mtu": 1320, "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}}},
		"outbounds": []any{map[string]any{"type": "socks", "tag": "tcp-stack", "server": "127.0.0.1", "server_port": helperPort, "version": "5"}, map[string]any{"type": "hysteria2", "tag": "udp-stack", "server": "192.0.2.1", "server_port": 8443, "password": "ephemeral-hysteria-fixture", "obfs": map[string]any{"type": "salamander", "password": "fixture-mask"}, "tls": map[string]any{"enabled": true, "server_name": "node.test", "certificate_path": "cert.pem"}}, map[string]any{"type": "direct", "tag": "direct"}},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": dnsType, "tag": "selected", "server": "10.77.0.1", "detour": dnsTag}}, "final": "selected"},
		"route":     map[string]any{"rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"network": "tcp", "action": "route", "outbound": "tcp-stack"}, map[string]any{"network": "udp", "action": "route", "outbound": "udp-stack"}}, "auto_detect_interface": true, "final": "tcp-stack"},
	}
	files := map[string]string{
		"sing-box.json": base64.StdEncoding.EncodeToString([]byte(encoded(graph))),
		helperName:      base64.StdEncoding.EncodeToString([]byte(encoded(helper))),
		"cert.pem":      base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
	if mode != "ss-v2ray" {
		files["stack.json"] = base64.StdEncoding.EncodeToString([]byte(encoded(map[string]any{"name": "Dual Transport", "transport": "both", "post_quantum": mode == "max", "shared_layers": []string{"single TUN interface"}, "tcp_stack": []string{"VLESS", "REALITY", "XTLS Vision"}, "udp_stack": []string{"Hysteria2", "QUIC", "TLS 1.3"}})))
	}
	policy := map[string]any{"node_id": node, "node_kind": "router-vpn", "router_api": "http://10.77.0.1:8787", "start_layer": layer}
	start := ""
	if layer != "" {
		aes := map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.1", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": secret}}}
		start = encoded(map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString([]byte(encoded(aes)))})
	}
	return encoded(files), encoded(policy), start
}
func planFor(t *testing.T, mode, node, layer string) map[string]any {
	t.Helper()
	source, metadata, start := fixture(t, mode, node, layer, "udp")
	compiled, err := Compile(mode, source, metadata, start)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(compiled, mode, node, layer)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestGeneratedCompositePreservesBothAuthenticatedLanes(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, dns := range []string{"udp", "tcp", "tls", "https", "h3", "quic"} {
				t.Run(mode+"/"+layer+"/"+dns, func(t *testing.T) {
					node := strings.Repeat("a", 64)
					source, metadata, start := fixture(t, mode, node, layer, dns)
					compiled, err := Compile(mode, source, metadata, start)
					if err != nil {
						t.Fatal(err)
					}
					plan, err := Plan(compiled, mode, node, layer)
					if err != nil {
						t.Fatal(err)
					}
					graph := parsed(t, compiled)
					outs := graph["outbounds"].([]any)
					owner := outs[0].(map[string]any)
					if owner["type"] != Type || owner["tcp"] == owner["udp"] || owner["node_id"] != node {
						t.Fatal("complete graph did not retain both lane identities")
					}
					if graph["route"].(map[string]any)["final"] != "proxy" || len(graph["route"].(map[string]any)["rules"].([]any)) != 1 {
						t.Fatal("fixed dispatcher did not own the entire routed graph")
					}
					resolver := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
					if resolver["type"] != dns || resolver["server"] != "10.77.0.1" || resolver["detour"] != "proxy" {
						t.Fatal("captured selected DNS lost its runtime owner")
					}
					udp := plan["udp"].(map[string]any)
					if udp["password"] != "ephemeral-hysteria-fixture" || udp["obfs"].(map[string]any)["password"] != "fixture-mask" || !certificates(udp["tls"].(map[string]any)["certificate"]) {
						t.Fatal("Hysteria2 authentication, obfuscation or trust changed")
					}
					tcp := plan["tcp"].(map[string]any)
					if mode == "ss-v2ray" {
						if tcp["plugin_opts"] != "tls;host=node.test;path=/shadowsocks" || tcp["password"] != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) {
							t.Fatal("SIP003 cryptographic policy changed")
						}
					} else if !strings.Contains(text(tcp["config_json"]), "11111111-1111-4111-8111-111111111111") || mode == "max" && !strings.Contains(text(tcp["config_json"]), "mlkem768x25519plus") {
						t.Fatal("Xray identity or required PQ changed")
					}
					if layer != "" && (tcp["detour"] != StartTag || udp["detour"] != StartTag || udp["server"] != "10.77.0.1") {
						t.Fatal("Start Layer did not enclose both lanes")
					}
				})
			}
		}
	}
}

func TestCompositeGraphRejectsDowngradeAndForeignOwnership(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				node := strings.Repeat("b", 64)
				plan := planFor(t, mode, node, layer)
				owner, children, err := Relabel(plan, mode, node, layer, "entry", "entry-composite-", "")
				if err != nil {
					t.Fatal(err)
				}
				root, other, err := Relabel(plan, mode, node, layer, "exit", "exit-composite-", "entry")
				if err != nil {
					t.Fatal(err)
				}
				graph := map[string]any{"outbounds": append(append([]any{owner, root}, children...), other...)}
				before := encoded(plan)
				for _, side := range []struct{ root, prefix, via string }{{"entry", "entry-composite-", ""}, {"exit", "exit-composite-", "entry"}} {
					extracted, err := Extract(graph, mode, node, layer, side.root, side.prefix, side.via)
					if err != nil || !reflect.DeepEqual(extracted, plan) {
						t.Fatal("paired detour roundtrip changed a captured lane", err)
					}
				}
				if encoded(plan) != before {
					t.Fatal("caller plan changed")
				}
				for _, via := range []string{"exit", "exit-composite-tcp", "exit-composite-udp", "exit-composite-start", "bad tag"} {
					if _, _, err := Relabel(plan, mode, node, layer, "exit", "exit-composite-", via); err == nil {
						t.Fatal("cycle or unowned tag accepted", via)
					}
				}
				cases := map[string]func(map[string]any){
					"missing UDP":      func(p map[string]any) { delete(p, "udp") },
					"weaker UDP":       func(p map[string]any) { p["udp"].(map[string]any)["type"] = "direct" },
					"foreign UDP node": func(p map[string]any) { p["udp"].(map[string]any)["server"] = "192.0.2.2" },
					"insecure TLS":     func(p map[string]any) { p["udp"].(map[string]any)["tls"].(map[string]any)["insecure"] = true },
					"file trust": func(p map[string]any) {
						p["udp"].(map[string]any)["tls"].(map[string]any)["certificate_path"] = "/unowned/trust.pem"
					},
					"invalid credential UTF8": func(p map[string]any) { p["udp"].(map[string]any)["password"] = string([]byte{0xff}) },
					"foreign detour":          func(p map[string]any) { p["udp"].(map[string]any)["detour"] = "unowned" },
					"TLS preamble": func(p map[string]any) {
						v := p["udp"].(map[string]any)["tls"].(map[string]any)
						v["certificate"] = "unowned bytes\n" + text(v["certificate"])
					},
					"UDP owner reused": func(p map[string]any) { p["udp"].(map[string]any)["tag"] = TCPTag },
					"label mismatch":   func(p map[string]any) { p["mode"] = "shadowsocks" },
					"node mismatch":    func(p map[string]any) { p["node_id"] = strings.Repeat("c", 64) },
					"runtime selector": func(p map[string]any) { p["type"] = "selector" },
				}
				for name, mutate := range cases {
					t.Run(name, func(t *testing.T) {
						copy, err := copyMap(plan)
						if err != nil {
							t.Fatal(err)
						}
						mutate(copy)
						if ValidatePlan(copy, mode, node, layer) == nil {
							t.Fatal("weakened or unowned plan accepted")
						}
					})
				}
				copy := parsed(t, encoded(graph))
				copy["outbounds"].([]any)[1].(map[string]any)["udp"] = "exit-composite-tcp"
				if _, err := Extract(copy, mode, node, layer, "exit", "exit-composite-", "entry"); err == nil {
					t.Fatal("whole graph adopted its TCP lane as UDP")
				}
				copy = parsed(t, encoded(graph))
				copy["outbounds"] = append(copy["outbounds"].([]any), map[string]any{"type": "direct", "tag": "exit-composite-foreign"})
				if _, err := Extract(copy, mode, node, layer, "exit", "exit-composite-", "entry"); err == nil {
					t.Fatal("foreign child escaped ownership check")
				}
			})
		}
	}
}

func TestCompositeProfilesAreBoundedExactAndSelfContained(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		source, metadata, start := fixture(t, mode, strings.Repeat("d", 64), "", "udp")
		for name, mutate := range map[string]func(map[string]any){
			"hidden helper":       func(p map[string]any) { p["run.sh"] = base64.StdEncoding.EncodeToString([]byte("do not execute")) },
			"missing trust":       func(p map[string]any) { delete(p, "cert.pem") },
			"noncanonical base64": func(p map[string]any) { p["cert.pem"] = text(p["cert.pem"]) + "\n" },
			"parent asset":        func(p map[string]any) { p["../cert.pem"] = p["cert.pem"] },
			"bad manifest": func(p map[string]any) {
				p["stack.json"] = base64.StdEncoding.EncodeToString([]byte(`{"transport":"tcp"}`))
			},
		} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				p := parsed(t, source)
				mutate(p)
				if _, err := Compile(mode, encoded(p), metadata, start); err == nil {
					t.Fatal("unowned profile accepted")
				}
			})
		}
		for _, wrong := range []string{`{"node_id":"wrong","node_kind":"router-vpn","router_api":"http://10.77.0.1:8787","start_layer":""}`, strings.TrimSuffix(metadata, "}") + `,"start_layer":""}`} {
			if _, err := Compile(mode, source, wrong, start); err == nil {
				t.Fatal("wrong or ambiguous captured metadata accepted")
			}
		}
		p := parsed(t, source)
		raw, err := base64.StdEncoding.DecodeString(text(p["sing-box.json"]))
		if err != nil {
			t.Fatal(err)
		}
		graph := parsed(t, string(raw))
		graph["route"].(map[string]any)["rules"] = append(graph["route"].(map[string]any)["rules"].([]any), map[string]any{"ip_is_private": true, "outbound": "direct"})
		p["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(encoded(graph)))
		if _, err := Compile(mode, encoded(p), metadata, start); err == nil {
			t.Fatal("compiler discarded an imported route exception")
		}
	}
}
