package mobiletor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func externalTorPredecessorFixture(t *testing.T, protocol string) (map[string]any, map[string]any) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	peer := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	profile := map[string]any{"id": "ordinary-entry", "node_kind": "external", "dns_mode": "custom", "dns_protocol": "tcp", "dns_host": "9.9.9.9", "dns_port": 5353,
		"home_lan_access": false, "ipv6_mode": "off", "mtu_policy": "auto", "effective_mtu": 9000}
	external := map[string]any{"protocol": protocol, "expected_public_ip": "203.0.113.88"}
	profile["external"] = external
	out := map[string]any{"tag": mobilemultihop.ExternalFinalTag, "server": "198.51.100.20", "server_port": 8443}
	endpoints, outbounds := []any{}, []any{}
	switch protocol {
	case "wireguard":
		delete(out, "server")
		delete(out, "server_port")
		addresses, routes := []string{"10.93.0.2/32", "fd93::2/128"}, []string{"0.0.0.0/0", "::/0"}
		out["type"], out["private_key"], out["address"], out["mtu"] = "wireguard", key, addresses, 1380
		out["peers"] = []any{map[string]any{"address": "198.51.100.20", "port": 8443, "public_key": peer, "pre_shared_key": key, "allowed_ips": routes}}
		external["wireguard"] = map[string]any{"private_key": key, "addresses": addresses, "peer_public_key": peer, "preshared_key": key, "endpoint": "198.51.100.20:8443", "allowed_ips": routes, "mtu": 1380}
		endpoints = append(endpoints, out)
	case "socks5":
		out["type"], out["version"], out["username"], out["password"] = "socks", "5", "captured-user", "captured-secret"
		external["socks5"] = map[string]any{"host": "198.51.100.20", "port": 8443, "username": "captured-user", "password": "captured-secret"}
	case "http-connect", "https-connect":
		out["type"], out["username"], out["password"] = "http", "captured-user", "captured-secret"
		settings := map[string]any{"host": "198.51.100.20", "port": 8443, "username": "captured-user", "password": "captured-secret"}
		if protocol == "https-connect" {
			out["tls"] = map[string]any{"enabled": true, "server_name": "selected.example"}
			settings["tls_server_name"] = "selected.example"
		}
		external[strings.ReplaceAll(protocol, "-", "_")] = settings
	case "shadowsocks":
		out["type"], out["method"], out["password"] = "shadowsocks", "2022-blake3-aes-256-gcm", key
		external["shadowsocks"] = map[string]any{"server": "198.51.100.20", "port": 8443, "method": out["method"], "password": key}
	case "hysteria2":
		out["type"], out["password"], out["tls"] = "hysteria2", "captured-secret", map[string]any{"enabled": true, "server_name": "selected.example"}
		external["hysteria2"] = map[string]any{"server": "198.51.100.20", "port": 8443, "password": "captured-secret", "tls_server_name": "selected.example"}
	default:
		t.Fatal("unknown test protocol")
	}
	if protocol != "wireguard" {
		outbounds = append(outbounds, out)
	}
	graph := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "interface_name": "router-vpn", "address": []string{"172.29.91.1/30", "fd29:91::1/126"}, "auto_route": true, "strict_route": true, "stack": "system", "mtu": 1280}},
		"outbounds": outbounds, "endpoints": endpoints, "route": map[string]any{"final": mobilemultihop.ExternalFinalTag, "auto_detect_interface": true, "rules": []any{}}}
	// Decode through the actual profile parser so every fixture mutation uses
	// the same numeric and array representation as a native captured request.
	profile, _ = profileObject(torHostEncode(t, profile), 4<<20)
	graph, _ = profileObject(torHostEncode(t, graph), 4<<20)
	return profile, graph
}

func TestExternalPredecessorCapturePreservesTransportAndSelectedPolicy(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		for _, dns := range []string{"tcp", "dot", "doh"} {
			t.Run(protocol+"/"+dns, func(t *testing.T) {
				profile, graph := externalTorPredecessorFixture(t, protocol)
				profile["dns_protocol"] = dns
				if dns != "tcp" {
					profile["dns_server_name"] = "selected-dns.example"
				}
				if dns == "doh" {
					profile["dns_path"] = "/chosen-query"
				}
				source, config := torHostEncode(t, profile), torHostEncode(t, graph)
				owner, err := NewExternalPredecessorProof(source, config)
				if err != nil {
					t.Fatal(err)
				}
				if owner.Kind() != ExternalPredecessorProofKind || owner.ID() != "ordinary-entry" || owner.Protocol() != protocol || owner.ExpectedPublicIP() != "203.0.113.88" ||
					owner.Profile() != source || owner.SourceConfig() != config || owner.Fingerprint() == "" || source != torHostEncode(t, profile) || config != torHostEncode(t, graph) || owner.mtu.policy != "auto" {
					t.Fatal("ordinary entry lost immutable source, type or policy")
				}
				compiled, _ := profileObject(owner.Config(), 4<<20)
				server := compiled["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if server["server"] != "9.9.9.9" || server["server_port"] != json.Number("5353") || server["detour"] != mobilemultihop.ExternalFinalTag {
					t.Fatal("ordinary lower changed selected DNS", server)
				}
				if compiled["dns"].(map[string]any)["strategy"] != "ipv4_only" || len(compiled["inbounds"].([]any)) != 1 {
					t.Fatal("captured native policy changed IPv6 or single-TUN ownership")
				}
				for _, family := range []string{"endpoints", "outbounds"} {
					if !reflect.DeepEqual(compiled[family], graph[family]) {
						t.Fatal("ordinary transport credentials changed", family)
					}
				}
				reencoded, _ := json.MarshalIndent(profile, "", "  ")
				copy, err := NewExternalPredecessorProof(string(reencoded), config)
				if err != nil || copy.Fingerprint() != owner.Fingerprint() {
					t.Fatal("formatting changed canonical identity", err)
				}
				if _, err := NewPredecessorProof(source); err == nil {
					t.Fatal("ordinary provider impersonated private Router /health proof")
				}
			})
		}
	}
}

func TestExternalPredecessorRejectsUnownedTransportIdentityAndHomeDNS(t *testing.T) {
	for _, mutation := range []string{"router-kind", "router-proof", "router-api", "router-token", "wrong-id", "private-ip", "empty-ip", "missing-profile", "tor-protocol", "mixed-protocol", "unknown-external", "wrong-password", "wrong-endpoint", "foreign-route", "extra-listener", "ambient-dns", "home-empty", "home-spoof", "fixed-invalid", "jumbo-conflict"} {
		t.Run(mutation, func(t *testing.T) {
			profile, graph := externalTorPredecessorFixture(t, "socks5")
			ext := profile["external"].(map[string]any)
			out := graph["outbounds"].([]any)[0].(map[string]any)
			switch mutation {
			case "router-kind":
				profile["node_kind"] = "router-vpn"
			case "router-proof":
				profile["node_proof_id"] = strings.Repeat("a", 64)
			case "router-api":
				profile["router_api"] = "http://10.77.0.1:8787"
			case "router-token":
				profile["api_token"] = "private-entry-secret"
			case "wrong-id":
				profile["id"] = "wrong id"
			case "private-ip":
				ext["expected_public_ip"] = "10.0.0.1"
			case "empty-ip":
				delete(ext, "expected_public_ip")
			case "missing-profile":
				delete(profile, "external")
			case "tor-protocol":
				ext["protocol"] = "tor-bridge"
			case "mixed-protocol":
				ext["wireguard"] = map[string]any{"private_key": "foreign-secret"}
			case "unknown-external":
				ext["unknown_transport"] = true
			case "wrong-password":
				out["password"] = "foreign-secret"
			case "wrong-endpoint":
				out["server"] = "203.0.113.20"
			case "foreign-route":
				graph["route"].(map[string]any)["final"] = "direct"
			case "extra-listener":
				graph["inbounds"] = append(graph["inbounds"].([]any), map[string]any{"type": "mixed", "tag": "foreign", "listen": "0.0.0.0", "listen_port": 9000})
			case "ambient-dns":
				graph["dns"] = map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "default"}}}
			case "home-empty":
				profile["dns_mode"], profile["dns_host"] = "home", ""
			case "home-spoof":
				profile["dns_mode"], profile["dns_host"], profile["adguard_ipv4"] = "home", "10.77.0.1", "10.77.0.1"
			case "fixed-invalid":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1000
			case "jumbo-conflict":
				profile["mtu_policy"], profile["manual_mtu"], profile["jumbo_tun"] = "fixed", 1400, true
			}
			owner, err := NewExternalPredecessorProof(torHostEncode(t, profile), torHostEncode(t, graph))
			if owner != nil || err == nil || strings.Contains(err.Error(), "private-entry-secret") || strings.Contains(err.Error(), "foreign-secret") {
				t.Fatal("invalid ordinary predecessor escaped", owner, err)
			}
		})
	}
	profile, graph := externalTorPredecessorFixture(t, "socks5")
	source, config := torHostEncode(t, profile), torHostEncode(t, graph)
	for _, broken := range []string{source + " {}", strings.Replace(source, `"id":"ordinary-entry"`, `"id":"ordinary-entry","id":"foreign"`, 1)} {
		if _, err := NewExternalPredecessorProof(broken, config); err == nil {
			t.Fatal("ambiguous source profile was accepted")
		}
	}
}

func TestExternalPredecessorIdentityRetainsCredentialsDNSMTUAndNativeSource(t *testing.T) {
	profile, graph := externalTorPredecessorFixture(t, "socks5")
	owner, err := NewExternalPredecessorProof(torHostEncode(t, profile), torHostEncode(t, graph))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"credentials", "public-ip", "dns", "mtu", "native-log"} {
		t.Run(mutation, func(t *testing.T) {
			profile, graph := externalTorPredecessorFixture(t, "socks5")
			switch mutation {
			case "credentials":
				profile["external"].(map[string]any)["socks5"].(map[string]any)["password"] = "replacement-secret"
				graph["outbounds"].([]any)[0].(map[string]any)["password"] = "replacement-secret"
			case "public-ip":
				profile["external"].(map[string]any)["expected_public_ip"] = "203.0.113.89"
			case "dns":
				profile["dns_host"] = "149.112.112.112"
			case "mtu":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1360
			case "native-log":
				graph["log"] = map[string]any{"level": "warn"}
			}
			changed, err := NewExternalPredecessorProof(torHostEncode(t, profile), torHostEncode(t, graph))
			if err != nil || changed.Fingerprint() == owner.Fingerprint() {
				t.Fatal("source replacement retained old proof identity", err)
			}
		})
	}
}

func TestExternalPredecessorCapturesExplicitDNSBootstrap(t *testing.T) {
	for _, mode := range []string{"exact", "missing", "foreign-route", "unused-literal", "null", "unknown-query"} {
		t.Run(mode, func(t *testing.T) {
			profile, graph := externalTorPredecessorFixture(t, "socks5")
			profile["dns_host"] = "selected-dns.example"
			bootstrap := map[string]any{
				"server": map[string]any{"type": "tcp", "tag": "external-dns-bootstrap", "server": "9.9.9.9", "server_port": 5353, "detour": mobilemultihop.ExternalFinalTag},
				"query":  map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "timeout": "2300ms", "disable_cache": true},
			}
			profile["dns_bootstrap"] = bootstrap
			switch mode {
			case "missing":
				delete(profile, "dns_bootstrap")
			case "foreign-route":
				bootstrap["server"].(map[string]any)["detour"] = "direct"
			case "unused-literal":
				profile["dns_host"] = "149.112.112.112"
			case "null":
				profile["dns_bootstrap"] = nil
			case "unknown-query":
				bootstrap["query"].(map[string]any)["default_resolver"] = "system"
			}
			owner, err := NewExternalPredecessorProof(torHostEncode(t, profile), torHostEncode(t, graph))
			if mode != "exact" {
				if err == nil || owner != nil {
					t.Fatal("invalid or discarded DNS bootstrap acquired an owner")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			compiled, _ := profileObject(owner.Config(), 4<<20)
			servers := compiled["dns"].(map[string]any)["servers"].([]any)
			if len(servers) != 2 || servers[0].(map[string]any)["server"] != "selected-dns.example" ||
				torHostEncode(t, servers[0].(map[string]any)["domain_resolver"]) != torHostEncode(t, bootstrap["query"]) ||
				torHostEncode(t, servers[1]) != torHostEncode(t, bootstrap["server"]) {
				t.Fatal("native predecessor changed its exact routed bootstrap or query options")
			}
		})
	}
}

func TestExternalPredecessorProofUsesOnlyCapturedLowerAndDistinctAuthority(t *testing.T) {
	profile, graph := externalTorPredecessorFixture(t, "socks5")
	owner, err := NewExternalPredecessorProof(torHostEncode(t, profile), torHostEncode(t, graph))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		if network != "tcp" || address != "1.1.1.1:443" || ctx.Err() != nil {
			t.Fatal("external proof escaped captured lower")
		}
		return nil, errors.New("isolated lower deliberately unavailable")
	}
	if owner.Prove(context.Background(), dial) == nil || calls != 1 {
		t.Fatal("external proof fabricated a successful address")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if owner.Prove(ctx, dial) == nil || calls != 1 {
		t.Fatal("retired external proof opened replacement work")
	}
	var missing *ExternalPredecessorProof
	var router *PredecessorProof
	var desktop *DesktopPredecessor
	if missing.Kind() != "" || missing.Fingerprint() != "" || router.Kind() != "" || desktop.IsRouter() || missing.Prove(context.Background(), dial) == nil {
		t.Fatal("absent proof acquired authority")
	}
	captured, _ := desktopEntryFixture(t, "wg", "", nil)
	if !captured.IsRouter() || captured.Proof().Kind() != RouterPredecessorProofKind || owner.Kind() == captured.Proof().Kind() {
		t.Fatal("entry proof kinds collapsed")
	}
	copy := *captured
	copy.kind = ExternalPredecessorProofKind
	if copy.IsRouter() {
		t.Fatal("external kind borrowed Router protection authority")
	}
	copy = *captured
	copy.proof = nil
	if copy.IsRouter() || (&DesktopPredecessor{proof: captured.Proof()}).IsRouter() {
		t.Fatal("unvalidated proof pointer acquired Router authority")
	}
}
