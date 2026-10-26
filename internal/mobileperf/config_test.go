package mobileperf

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativecomposite"
)

func perfFixture() map[string]any {
	return map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "mtu": 1380, "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.1", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": "preserve-secret"}},
		"route":     map[string]any{"final": "proxy", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}},
		"dns":       map[string]any{"final": "selected", "servers": []any{map[string]any{"type": "tls", "tag": "selected", "server": "192.0.2.53", "detour": "proxy"}}},
	}
}
func node() map[string]any {
	return map[string]any{"id": "exit", "node_kind": "router-vpn", "node_proof_id": strings.Repeat("a", 64), "router_api": "http://10.77.0.1:8787", "socks_host": "10.77.0.1", "daita_host": "10.77.0.1", "daita_port": 45999, "daita_rate_kbps": 192}
}
func jsonText(v any) string { b, _ := json.Marshal(v); return string(b) }
func compilePerf(root map[string]any, entry, exit map[string]any) (map[string]any, error) {
	s, err := Apply(jsonText(root), jsonText(map[string]any{"entry": entry, "exit": exit}))
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = json.Unmarshal([]byte(s), &result)
	return result, err
}
func TestDisabledPerformanceIsByteIdentical(t *testing.T) {
	raw := jsonText(perfFixture())
	out, err := Apply(raw, jsonText(map[string]any{"entry": node(), "exit": node()}))
	if err != nil || out != raw {
		t.Fatal("disabled changes source", err)
	}
}
func TestCoverAndJumboRetainActualDataplane(t *testing.T) {
	original := perfFixture()
	profile := node()
	profile["daita_enabled"] = true
	profile["jumbo_tun"] = true
	out, err := compilePerf(original, profile, profile)
	if err != nil {
		t.Fatal(err)
	}
	if out["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(9000) {
		t.Fatal("Jumbo not applied")
	}
	for _, key := range []string{"route", "dns", "outbounds"} {
		if jsonText(out[key]) != jsonText(original[key]) {
			t.Fatal("performance replaced", key)
		}
	}
	services := out["services"].([]any)
	if len(services) != 1 {
		t.Fatal("multiple cover workers")
	}
	service := services[0].(map[string]any)
	if service["type"] != CoverType || service["packet_tag"] != "proxy" || service["proof_tag"] != "proxy" || service["sink"] != "10.77.0.1" {
		t.Fatal("unowned padding path")
	}
	again, err := compilePerf(out, profile, profile)
	if err != nil || jsonText(out) != jsonText(again) {
		t.Fatal("performance not idempotent", err)
	}
}
func TestCoverPerHopAndSplitTransportOwnership(t *testing.T) {
	root := perfFixture()
	root["endpoints"] = []any{map[string]any{"type": "routervpn-amneziawg", "tag": "entry-wg"}}
	root["outbounds"].([]any)[0].(map[string]any)["detour"] = "entry-wg"
	entry, exit := node(), node()
	entry["id"] = "entry"
	entry["node_proof_id"] = strings.Repeat("b", 64)
	entry["daita_enabled"] = true
	exit["daita_enabled"] = true
	out, err := compilePerf(root, entry, exit)
	if err != nil {
		t.Fatal(err)
	}
	services := out["services"].([]any)
	if len(services) != 2 || services[1].(map[string]any)["packet_tag"] != "entry-wg" {
		t.Fatal("entry cover sent through wrong hop")
	}
	root = perfFixture()
	root["outbounds"] = []any{map[string]any{"type": "routervpn-xray", "tag": "tcp-stack"}, map[string]any{"type": "hysteria2", "tag": "udp-stack"}}
	root["route"] = map[string]any{"final": "tcp-stack", "rules": []any{map[string]any{"action": "route", "network": "udp", "outbound": "udp-stack"}}}
	out, err = compilePerf(root, exit, exit)
	if err != nil {
		t.Fatal(err)
	}
	service := out["services"].([]any)[0].(map[string]any)
	if service["proof_tag"] != "tcp-stack" || service["packet_tag"] != "udp-stack" {
		t.Fatal("split cover lost TCP/UDP ownership")
	}
}

func compositeCoverFixture(t *testing.T, mode, layer, rootTag, prefix, via string) map[string]any {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node.test"}, DNSNames: []string{"node.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	secret := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
	if mode == "max" {
		user["encryption"] = "mlkem768x25519plus.native.0rtt.public-authentication-fixture"
	}
	helper := map[string]any{"inbounds": []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": 1090, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "192.0.2.1", "port": 10443, "users": []any{user}}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "node.test", "fingerprint": "chrome", "password": "public-key-fixture", "shortId": "0123456789abcdef"}}}}}
	helperName, port := "xray.json", 1090
	if mode == "ss-v2ray" {
		helperName, port = "sslocal.json", 1092
		helper = map[string]any{"server": "192.0.2.1", "server_port": 10443, "password": secret, "method": "2022-blake3-aes-256-gcm", "local_address": "127.0.0.1", "local_port": port, "mode": "tcp_only", "plugin": "v2ray-plugin", "plugin_opts": "tls;host=node.test;path=/shadowsocks"}
	}
	graph := perfFixture()
	graph["outbounds"] = []any{map[string]any{"type": "socks", "tag": "tcp-stack", "server": "127.0.0.1", "server_port": port, "version": "5"}, map[string]any{"type": "hysteria2", "tag": "udp-stack", "server": "192.0.2.1", "server_port": 8443, "password": "fixture-password", "obfs": map[string]any{"type": "salamander", "password": "fixture-mask"}, "tls": map[string]any{"enabled": true, "server_name": "node.test", "certificate_path": "cert.pem"}}}
	graph["route"] = map[string]any{"final": "tcp-stack", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"network": "tcp", "action": "route", "outbound": "tcp-stack"}, map[string]any{"network": "udp", "action": "route", "outbound": "udp-stack"}}}
	graph["dns"] = map[string]any{"final": "selected", "servers": []any{map[string]any{"type": "udp", "tag": "selected", "server": "10.77.0.1", "detour": "tcp-stack"}}}
	assets := map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString([]byte(jsonText(graph))), helperName: base64.StdEncoding.EncodeToString([]byte(jsonText(helper))), "cert.pem": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	if mode != "ss-v2ray" {
		assets["stack.json"] = base64.StdEncoding.EncodeToString([]byte(jsonText(map[string]any{"name": "Dual Transport", "transport": "both", "post_quantum": mode == "max", "shared_layers": []string{"single TUN interface"}, "tcp_stack": []string{"VLESS", "REALITY", "XTLS Vision"}, "udp_stack": []string{"Hysteria2", "QUIC", "TLS 1.3"}})))
	}
	nodeID := strings.Repeat("a", 64)
	compiled, err := nativecomposite.Compile(mode, jsonText(assets), jsonText(map[string]any{"node_id": nodeID, "node_kind": "router-vpn", "router_api": "http://10.77.0.1:8787", "start_layer": ""}), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := nativecomposite.Plan(compiled, mode, nodeID, "")
	if err != nil {
		t.Fatal(err)
	}
	if layer != "" {
		outer := map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.1", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": secret}
		plan, err = nativecomposite.WithStartLayer(plan, mode, nodeID, layer, "http://10.77.0.1:8787", outer)
		if err != nil {
			t.Fatal(err)
		}
	}
	owner, children, err := nativecomposite.Relabel(plan, mode, nodeID, layer, rootTag, prefix, via)
	if err != nil {
		t.Fatal(err)
	}
	result := perfFixture()
	result["outbounds"] = append([]any{owner}, children...)
	if rootTag != "proxy" {
		result["outbounds"] = append(result["outbounds"].([]any), map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.2", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": secret, "detour": rootTag})
	}
	if via != "" {
		result["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": via}}
	}
	return result
}

func TestCompositeCoverRequiresBothCapturedEncryptedLanes(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, placement := range []struct{ role, tag, prefix, via string }{{"single", "proxy", "routervpn-composite-", ""}, {"entry", "routervpn-hop-entry", "routervpn-entry-composite-", ""}, {"exit", "proxy", "routervpn-exit-composite-", "routervpn-hop-entry"}} {
				t.Run(mode+"/"+layer+"/"+placement.role, func(t *testing.T) {
					original := compositeCoverFixture(t, mode, layer, placement.tag, placement.prefix, placement.via)
					entry, exit := node(), node()
					if placement.role == "entry" {
						entry["daita_enabled"] = true
					} else {
						exit["daita_enabled"] = true
					}
					if placement.role == "single" {
						entry = exit
					}
					out, err := compilePerf(original, entry, exit)
					if err != nil {
						t.Fatal(err)
					}
					service := out["services"].([]any)[0].(map[string]any)
					if service["packet_tag"] != placement.tag || service["proof_tag"] != placement.tag {
						t.Fatal("cover bypassed captured TCP/UDP dispatcher")
					}
					for _, key := range []string{"outbounds", "endpoints", "inbounds", "dns", "route"} {
						if jsonText(out[key]) != jsonText(original[key]) {
							t.Fatal("cover changed captured", key)
						}
					}
					for _, fault := range []string{"tcp-plain", "udp-plain", "udp-alias", "owner-node", "lane-node", "cycle", "bypass", "missing", "foreign-owner"} {
						var bad map[string]any
						_ = json.Unmarshal([]byte(jsonText(original)), &bad)
						outputs := bad["outbounds"].([]any)
						byTag := map[string]map[string]any{}
						for _, raw := range outputs {
							value := raw.(map[string]any)
							byTag[value["tag"].(string)] = value
						}
						tcp, udp, owner := byTag[placement.prefix+"tcp"], byTag[placement.prefix+"udp"], byTag[placement.tag]
						switch fault {
						case "tcp-plain":
							tcp["type"] = "direct"
						case "udp-plain":
							udp["type"] = "direct"
						case "udp-alias":
							owner["udp"] = owner["tcp"]
						case "owner-node":
							owner["node_id"] = strings.Repeat("b", 64)
						case "lane-node":
							udp["server"] = "192.0.2.99"
						case "cycle":
							tcp["detour"] = placement.tag
						case "bypass":
							udp["detour"] = "direct"
						case "missing":
							udp["tag"] = "missing-owned-udp"
						case "foreign-owner":
							owner["tcp"] = "routervpn-foreign-tcp"
							owner["udp"] = "routervpn-foreign-udp"
						}
						if _, err = compilePerf(bad, entry, exit); err == nil {
							t.Fatal("cover blessed", fault)
						}
					}
				})
			}
		}
	}
}
func TestPerformanceCannotIgnorePolicyOrCreateRawJumbo(t *testing.T) {
	for _, name := range []string{"bad-bool", "public-sink", "high-rate", "wrong-port", "missing-proof", "external-node", "plaintext", "foreign-service", "fixed-conflict", "raw-jumbo", "entry-jumbo"} {
		t.Run(name, func(t *testing.T) {
			root := perfFixture()
			profile := node()
			profile["daita_enabled"] = true
			entry := profile
			switch name {
			case "bad-bool":
				profile["daita_enabled"] = "true"
			case "public-sink":
				profile["daita_host"] = "1.1.1.1"
			case "high-rate":
				profile["daita_rate_kbps"] = 10000
			case "wrong-port":
				profile["daita_port"] = 22
			case "missing-proof":
				delete(profile, "node_proof_id")
			case "external-node":
				profile["node_kind"] = "external"
			case "plaintext":
				root["outbounds"].([]any)[0].(map[string]any)["type"] = "direct"
			case "foreign-service":
				root["services"] = []any{map[string]any{"type": "unowned", "tag": "routervpn-cover-exit"}}
			case "fixed-conflict":
				profile["jumbo_tun"] = true
				profile["mtu_policy"] = "manual"
				profile["manual_mtu"] = 1400
			case "raw-jumbo":
				profile["jumbo_tun"] = true
				root["outbounds"] = []any{}
				root["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": "proxy"}}
			case "entry-jumbo":
				root["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": "entry-wg"}}
				entry = node()
				entry["jumbo_tun"] = true
			}
			if _, err := compilePerf(root, entry, profile); err == nil {
				t.Fatal("invalid performance configuration accepted")
			}
		})
	}
	if _, err := Apply(jsonText(perfFixture()), `{"entry":{},"entry":{},"exit":{}}`); err == nil {
		t.Fatal("duplicate profile accepted")
	}
}

func TestImportedPaddingCannotOverrideDisabledPreferences(t *testing.T) {
	profile := node()
	profile["daita_enabled"] = true
	compiled, err := compilePerf(perfFixture(), profile, profile)
	if err != nil {
		t.Fatal(err)
	}
	profile["daita_enabled"] = false
	if _, err = compilePerf(compiled, profile, profile); err == nil {
		t.Fatal("disabled preference activated an imported cover worker")
	}
	profile["jumbo_tun"] = true
	if _, err = compilePerf(compiled, profile, profile); err == nil {
		t.Fatal("Jumbo reactivated old cover settings")
	}
}

func TestPQCoverUsesEncryptedPeerWithoutChangingKeysOrDNS(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		t.Run(mode, func(t *testing.T) {
			graph := perfFixture()
			graph["outbounds"] = []any{}
			endpoint := map[string]any{"type": "routervpn-pq", "mode": mode, "tag": "proxy", "mtu": 1420, "private_key": "captured-wg-key", "pq": map[string]any{"secret": "captured-pq-key", "endpoint": "192.0.2.1:51822"}}
			graph["endpoints"] = []any{endpoint}
			profile := node()
			profile["daita_enabled"] = true
			out, err := compilePerf(graph, profile, profile)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"endpoints", "dns", "route", "inbounds"} {
				if jsonText(out[key]) != jsonText(graph[key]) {
					t.Fatal("padding changed", key)
				}
			}
			if len(out["services"].([]any)) != 1 {
				t.Fatal("missing owned cover service")
			}
			profile["jumbo_tun"] = true
			if _, err = compilePerf(graph, profile, profile); err == nil {
				t.Fatal("PQ bypassed encrypted packet MTU ceiling")
			}
			profile["jumbo_tun"] = false
			endpoint["mode"] = "unknown"
			if _, err = compilePerf(graph, profile, profile); err == nil {
				t.Fatal("unimplemented PQ mode marked encrypted")
			}
		})
	}
}

func naiveCoverFixture(t *testing.T, mode, placement, layer, address string) (map[string]any, map[string]any, map[string]any, string) {
	t.Helper()
	root := perfFixture()
	entry, exit := node(), node()
	entry["node_proof_id"], entry["id"] = strings.Repeat("b", 64), "entry"
	tag, via := "proxy", ""
	if placement == "entry" {
		tag = "entry-wg"
		entry["daita_enabled"] = true
	} else {
		exit["daita_enabled"] = true
		if placement == "single" {
			entry = exit
		} else {
			via = "entry-wg"
			root["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": via}}
		}
	}
	value := map[string]any{
		"type": "naive", "tag": tag, "server": "192.0.2.4", "server_port": float64(13443),
		"username": placement + "-user", "password": placement + "-private-secret", "quic": mode == "naive-h3",
		"udp_over_tcp": map[string]any{"enabled": true, "version": float64(2)},
		"tls":          map[string]any{"enabled": true, "server_name": placement + ".example.test"},
	}
	if err := multihoprelay.ValidateNaiveTransport(value, mode); err != nil {
		t.Fatal(err)
	}
	outputs := []any{value}
	if layer != "" {
		start := &multihoprelay.StartLayer{Mode: layer, API: "http://10.77.0.1:8787", Transport: map[string]any{
			"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.4", "server_port": float64(8388),
			"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))),
		}}
		inner, outer, err := multihoprelay.WrapStartLayer(value, mode, start, "captured-aes", via)
		if err != nil {
			t.Fatal(err)
		}
		if address != "" {
			// Android's captured Start Layer can address the remote node's
			// loopback service. Validation must keep this actual destination.
			inner["server"] = address
		}
		outputs = []any{inner, outer}
	} else if via != "" {
		value["detour"] = via
	}
	if placement == "entry" {
		final := root["outbounds"].([]any)[0].(map[string]any)
		final["detour"] = tag
		outputs = append(outputs, final)
	}
	root["outbounds"] = outputs
	return root, entry, exit, tag
}

func TestNaiveCoverRetainsAuthenticatedNativeTCPAndUDP(t *testing.T) {
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		for _, placement := range []string{"single", "entry", "exit"} {
			for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				addresses := []string{""}
				if layer != "" {
					addresses = append(addresses, "127.0.0.1", "::1")
				}
				for _, address := range addresses {
					t.Run(mode+"/"+placement+"/"+layer+"/"+address, func(t *testing.T) {
						root, entry, exit, tag := naiveCoverFixture(t, mode, placement, layer, address)
						before := jsonText(root)
						out, err := compilePerf(root, entry, exit)
						if err != nil {
							t.Fatal(err)
						}
						if jsonText(root) != before {
							t.Fatal("cover validation changed the caller's graph")
						}
						for _, field := range []string{"outbounds", "endpoints", "inbounds", "dns", "route"} {
							if jsonText(out[field]) != jsonText(root[field]) {
								t.Fatal("Naive cover changed captured", field)
							}
						}
						services := out["services"].([]any)
						if len(services) != 1 {
							t.Fatal("Naive cover created another network owner")
						}
						service := services[0].(map[string]any)
						owner := exit
						if placement == "entry" {
							owner = entry
						}
						if service["packet_tag"] != tag || service["proof_tag"] != tag || service["node_id"] != owner["node_proof_id"] {
							t.Fatal("Naive cover bypassed the selected authenticated TCP/UDP owner")
						}
						again, err := compilePerf(out, entry, exit)
						if err != nil || jsonText(again) != jsonText(out) {
							t.Fatal("Naive cover was not idempotent", err)
						}
					})
				}
			}
		}
	}
}

func TestNaiveCoverRejectsDowngradesAndDetourCycles(t *testing.T) {
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		for _, fault := range []string{"HTTP", "QUIC-type", "secret", "TLS", "trust-path", "invalid-cert", "UDP-disabled", "UDP-version", "UDP-extra", "hostname", "plain-loopback", "missing-detour", "empty-detour", "typed-detour", "self-cycle", "encrypted-cycle", "plain-underlay", "plain-after-encrypted", "unowned-options"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				root, entry, exit, _ := naiveCoverFixture(t, mode, "single", "aes-256-gcm", "127.0.0.1")
				outputs := root["outbounds"].([]any)
				value, lower := outputs[0].(map[string]any), outputs[1].(map[string]any)
				switch fault {
				case "HTTP":
					value["type"] = "http"
				case "QUIC-type":
					value["quic"] = "true"
				case "secret":
					value["password"] = ""
				case "TLS":
					value["tls"].(map[string]any)["insecure"] = true
				case "trust-path":
					value["tls"].(map[string]any)["certificate_path"] = "other.pem"
				case "invalid-cert":
					value["tls"].(map[string]any)["certificate"] = []any{"not a certificate"}
				case "UDP-disabled":
					value["udp_over_tcp"].(map[string]any)["enabled"] = false
				case "UDP-version":
					value["udp_over_tcp"].(map[string]any)["version"] = float64(1)
				case "UDP-extra":
					value["udp_over_tcp"].(map[string]any)["detour"] = "direct"
				case "hostname":
					value["server"] = "localhost"
				case "plain-loopback":
					delete(value, "detour")
				case "missing-detour":
					value["detour"] = "absent"
				case "empty-detour":
					value["detour"] = ""
				case "typed-detour":
					value["detour"] = true
				case "self-cycle":
					value["detour"] = value["tag"]
				case "encrypted-cycle":
					lower["detour"] = value["tag"]
				case "plain-underlay":
					lower["type"] = "direct"
				case "plain-after-encrypted":
					lower["detour"] = "unowned"
					root["outbounds"] = append(outputs, map[string]any{"type": "direct", "tag": "unowned"})
				case "unowned-options":
					value["bind_interface"] = "lo"
				}
				before := jsonText(root)
				if _, err := compilePerf(root, entry, exit); err == nil {
					t.Fatal("padding accepted unproved Naive transport")
				}
				if jsonText(root) != before {
					t.Fatal("rejection repaired or replaced the caller's transport")
				}
			})
		}
	}
}

func TestNaiveCoverTraversesTheCompleteCapturedCompositeEntry(t *testing.T) {
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		for _, composite := range []string{"ss-v2ray", "split", "max"} {
			t.Run(mode+"/"+composite, func(t *testing.T) {
				root := compositeCoverFixture(t, composite, "", "entry-wg", "routervpn-entry-composite-", "")
				naive, _, _, _ := naiveCoverFixture(t, mode, "exit", "", "")
				outputs := root["outbounds"].([]any)
				for i, raw := range outputs {
					if raw.(map[string]any)["tag"] == "proxy" {
						outputs[i] = naive["outbounds"].([]any)[0]
					}
				}
				entry, exit := node(), node()
				exit["node_proof_id"], exit["daita_enabled"] = strings.Repeat("b", 64), true
				out, err := compilePerf(root, entry, exit)
				if err != nil || jsonText(out["outbounds"]) != jsonText(root["outbounds"]) {
					t.Fatal("Naive cover lost complete predecessor lanes", err)
				}
				for _, raw := range outputs {
					value := raw.(map[string]any)
					if value["tag"] == "routervpn-entry-composite-udp" {
						value["type"] = "direct"
					}
				}
				if _, err := compilePerf(root, entry, exit); err == nil {
					t.Fatal("Naive TCP proof blessed a plaintext composite UDP lane")
				}
			})
		}
	}
}

func TestNaiveCoverCapturedBootstrapUsesTheSameLowerOwner(t *testing.T) {
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, fault := range []string{"none", "missing", "duplicate", "wrong-lower", "physical-bypass", "child-bypass", "self-recursion", "tree-recursion", "missing-host-bootstrap", "system-resolver", "query-dial-option", "query-strategy"} {
				t.Run(mode+"/"+layer+"/"+fault, func(t *testing.T) {
					root, entry, exit, _ := naiveCoverFixture(t, mode, "exit", layer, "")
					transport := root["outbounds"].([]any)[0].(map[string]any)
					lower := transport["detour"]
					query := map[string]any{"server": "captured-bootstrap", "strategy": "ipv4_only", "disable_cache": true}
					transport["domain_resolver"] = query
					bootstrap := map[string]any{"type": "https", "tag": "captured-bootstrap", "server": "selected-resolver.example", "server_port": float64(4443), "path": "/selected-query", "tls": map[string]any{"enabled": true, "server_name": "selected-certificate.example"}, "detour": lower, "domain_resolver": map[string]any{"server": "captured-literal"}}
					leaf := map[string]any{"type": "udp", "tag": "captured-literal", "server": "10.77.0.53", "detour": lower}
					servers := []any{map[string]any{"type": "udp", "tag": "selected", "server": "10.88.0.53", "detour": "proxy"}, bootstrap, leaf}
					root["dns"] = map[string]any{"servers": servers, "final": "selected"}
					switch fault {
					case "missing":
						query["server"] = "absent"
					case "duplicate":
						root["dns"].(map[string]any)["servers"] = append(servers, bootstrap)
					case "wrong-lower":
						bootstrap["detour"] = "proxy"
					case "physical-bypass":
						delete(bootstrap, "detour")
					case "child-bypass":
						delete(leaf, "detour")
					case "self-recursion":
						bootstrap["domain_resolver"] = query
					case "tree-recursion":
						leaf["domain_resolver"] = query
					case "missing-host-bootstrap":
						delete(bootstrap, "domain_resolver")
					case "system-resolver":
						leaf["type"] = "local"
					case "query-dial-option":
						query["detour"] = "direct"
					case "query-strategy":
						query["strategy"] = "ordinary-network"
					}
					before := jsonText(root)
					compiled, err := compilePerf(root, entry, exit)
					if fault != "none" {
						if err == nil {
							t.Fatal("unowned or recursive captured DNS granted cover", fault)
						}
					} else {
						if err != nil || jsonText(compiled["dns"]) != jsonText(root["dns"]) || jsonText(compiled["outbounds"]) != jsonText(root["outbounds"]) {
							t.Fatal("captured resolver, TLS, path or UDP transport was replaced", err)
						}
						again, err := compilePerf(compiled, entry, exit)
						if err != nil || jsonText(again) != jsonText(compiled) {
							t.Fatal("captured DNS is not reusable for retained multihop", err)
						}
					}
					if jsonText(root) != before {
						t.Fatal("performance validation rewrote captured policy")
					}
				})
			}
		}
	}
}
