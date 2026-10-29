package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/nativeopenvpn"
)

func expectedNodeEgress(mode, layer string) []PhysicalEgress {
	host, port, networks := "192.0.2.44", 443, []string{"tcp"}
	if mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" || IsPQMode(mode) {
		host, port, networks = "192.0.2.1", 51820, []string{"udp"}
	} else if mode == "shadowsocks" || CompositeMode(mode) {
		networks = []string{"tcp", "udp"}
	} else if mode == "hysteria2" || mode == "naive-h3" || strings.HasPrefix(mode, "max-quic-") {
		networks = []string{"udp"}
	}
	if layer == "" {
		if IsPQMode(mode) {
			return []PhysicalEgress{{host, port, "udp"}, {host, 51822, "udp"}}
		}
		if CompositeMode(mode) {
			return []PhysicalEgress{{host, 8443, "udp"}, {host, 10443, "tcp"}}
		}
		if strings.HasPrefix(mode, "max-quic-") {
			port = 8443
		}
	} else {
		host, port = "192.0.2.44", 443
		if MAXMode(mode) {
			port = 8388
		}
		if layer == "aes-256-gcm+xor-whitening" {
			port = 8389
		}
	}
	result := []PhysicalEgress{}
	for _, network := range networks {
		result = append(result, PhysicalEgress{host, port, network})
	}
	return result
}

func compiledEgressFixture(t *testing.T, mode, layer string) (map[string]any, map[string]any) {
	t.Helper()
	files, profile, start := nodeProfileFixture(t, mode, layer)
	node, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal(err)
	}
	return profile, startObject(t, node.Config())
}

func TestNodePhysicalEgressAllModesAndStartLayers(t *testing.T) {
	count := 0
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				profile, graph := compiledEgressFixture(t, mode, layer)
				source, config := startJSON(t, profile), startJSON(t, graph)
				got, err := NodePhysicalEgress(mode, source, config)
				want := expectedNodeEgress(mode, layer)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("complete physical closure: got %#v, want %#v, error %v", got, want, err)
				}
				for _, tuple := range got {
					if tuple.Host == "10.77.0.1" || tuple.Host == "192.168.50.133" || tuple.Host == "127.0.0.1" {
						t.Fatal("private API, DNS or detoured transport became a physical exception")
					}
				}
				again, err := NodePhysicalEgress(mode, source, config)
				if err != nil || !reflect.DeepEqual(again, got) || source != startJSON(t, profile) || config != startJSON(t, graph) {
					t.Fatal("projection changed captured inputs or ordering")
				}
				// An address-only selected-profile field is not the graph's
				// physical path. Start Layers already exercise different values.
				profile["endpoint"] = "203.0.113.200"
				if changed, err := NodePhysicalEgress(mode, startJSON(t, profile), config); err != nil || !reflect.DeepEqual(changed, got) {
					t.Fatal("profile endpoint substituted the compiled physical closure", err)
				}
				count++
			})
		}
	}
	if count != 57 {
		t.Fatal("not all 19 modes and three Start Layers were exercised", count)
	}
	got, _ := json.Marshal(PhysicalEgress{"192.0.2.10", 8443, "udp"})
	want, _ := json.Marshal(nativeopenvpn.LayerEgress{Host: "192.0.2.10", Port: 8443, Network: "udp"})
	if string(got) != string(want) || string(got) != `{"host":"192.0.2.10","port":8443,"network":"udp"}` {
		t.Fatal("captured native egress wire fields diverged", string(got), string(want))
	}
}

func TestCapturedNodePhysicalEgressRetainsEveryModeAndLayer(t *testing.T) {
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				files, profile, start := nodeProfileFixture(t, mode, layer)
				node, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
				if err != nil {
					t.Fatal(err)
				}
				before := node.Config()
				got, err := node.PhysicalEgress()
				want := expectedNodeEgress(mode, layer)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("captured physical projection changed protocol, port or Start Layer", got, want, err)
				}
				got[0].Port = 1
				again, err := node.PhysicalEgress()
				if err != nil || !reflect.DeepEqual(again, want) || node.Config() != before {
					t.Fatal("one caller modified the retained source or another projection", err)
				}
				// The captured graph remains authority even if an unrelated
				// selected-profile object changes after native preparation.
				profile["endpoint"] = "203.0.113.200"
				profile["start_layer"] = "off"
				again, err = node.PhysicalEgress()
				if err != nil || !reflect.DeepEqual(again, want) {
					t.Fatal("current selection replaced captured physical tuples", err)
				}
			})
		}
	}
	for _, node := range []*NodeProfile{nil, {}, {mode: "wg", config: "{}", profile: map[string]any{}}} {
		if tuples, err := node.PhysicalEgress(); err == nil || tuples != nil {
			t.Fatal("unproved node acquired physical tuples", tuples, err)
		}
	}
}

func TestNodePhysicalEgressRejectsIncompleteOrSubstitutedGraphs(t *testing.T) {
	for _, mode := range predecessorFamilies {
		for _, defect := range []string{"wrong-mode", "missing-final", "direct-final", "competing-route", "extra-tun", "unowned-node", "missing-auth", "bad-kind"} {
			t.Run(mode+"/"+defect, func(t *testing.T) {
				profile, graph := compiledEgressFixture(t, mode, "")
				selected := mode
				switch defect {
				case "wrong-mode":
					selected = "tor-bridge"
				case "missing-final":
					graph["route"].(map[string]any)["final"] = "missing"
				case "direct-final":
					graph["route"].(map[string]any)["final"] = "physical"
					graph["outbounds"] = append(anyRows(graph["outbounds"]), map[string]any{"type": "direct", "tag": "physical"})
				case "competing-route":
					graph["route"].(map[string]any)["rules"] = []any{map[string]any{"outbound": "direct"}}
				case "extra-tun":
					graph["inbounds"] = append(graph["inbounds"].([]any), graph["inbounds"].([]any)[0])
				case "unowned-node":
					graph["outbounds"] = append(anyRows(graph["outbounds"]), map[string]any{"type": "hysteria2", "tag": "unowned"})
				case "missing-auth":
					delete(profile, "api_token")
				case "bad-kind":
					profile["node_kind"] = "external"
				}
				if got, err := NodePhysicalEgress(selected, startJSON(t, profile), startJSON(t, graph)); err == nil || got != nil {
					t.Fatal("invalid ownership produced firewall exceptions", got)
				}
			})
		}
	}
	for _, mode := range []string{"wg-pq", "reality-xhttp", "ss-v2ray", "max-tls-awg", "naive-h3"} {
		profile, graph := compiledEgressFixture(t, mode, "aes-256-gcm")
		for _, raw := range append(anyRows(graph["endpoints"]), anyRows(graph["outbounds"])...) {
			delete(raw.(map[string]any), "detour")
		}
		if got, err := NodePhysicalEgress(mode, startJSON(t, profile), startJSON(t, graph)); err == nil || got != nil {
			t.Fatal("missing Start Layer/detour exposed its inner service", mode, got)
		}
	}
}

func anyRows(value any) []any { result, _ := value.([]any); return result }

func TestNodePhysicalEgressRejectsUnsafeOuterLiteralsAndPorts(t *testing.T) {
	profile, valid := compiledEgressFixture(t, "hysteria2", "")
	for _, host := range []string{"outer.example", "0.0.0.0", "::", "127.0.0.1", "::1", "::ffff:192.0.2.44", "fe80::1", "fe80::1%3", "224.0.0.1", "ff02::1", "255.255.255.255", "0.1.2.3", "192.0.2.044", "2001:DB8::44"} {
		graph := predecessorCopy(valid)
		graph["outbounds"].([]any)[0].(map[string]any)["server"] = host
		if got, err := NodePhysicalEgress("hysteria2", startJSON(t, profile), startJSON(t, graph)); err == nil || got != nil {
			t.Fatal("unsafe outer literal admitted", host, got)
		}
	}
	for _, port := range []any{nil, "443", float64(0), float64(65536), 443.5, true} {
		graph := predecessorCopy(valid)
		graph["outbounds"].([]any)[0].(map[string]any)["server_port"] = port
		if got, err := NodePhysicalEgress("hysteria2", startJSON(t, profile), startJSON(t, graph)); err == nil || got != nil {
			t.Fatal("non-exact or all-port exception admitted", port, got)
		}
	}
	for _, host := range []string{"192.0.2.44", "2001:db8::44"} {
		graph := predecessorCopy(valid)
		graph["outbounds"].([]any)[0].(map[string]any)["server"] = host
		got, err := NodePhysicalEgress("hysteria2", startJSON(t, profile), startJSON(t, graph))
		if err != nil || !reflect.DeepEqual(got, []PhysicalEgress{{host, 443, "udp"}}) {
			t.Fatal("valid exact address family rejected", got, err)
		}
	}
}

func TestNodePhysicalEgressDNSRequiresAnActualBootstrapDependency(t *testing.T) {
	files, profile, start := nodeProfileFixture(t, "hysteria2", "")
	profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "custom", "https", "resolver.example"
	profile["dns_port"], profile["dns_server_name"], profile["dns_path"] = float64(4443), "resolver.example", "/captured-query"
	bootstrap := map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "9.9.9.9", "server_port": 53, "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only"}}
	node, err := NewNodeProfile("hysteria2", files, startJSON(t, profile), start, startJSON(t, bootstrap))
	if err != nil {
		t.Fatal(err)
	}
	base := startObject(t, node.Config())
	want := []PhysicalEgress{{"192.0.2.44", 443, "udp"}}
	if got, err := NodePhysicalEgress("hysteria2", startJSON(t, profile), node.Config()); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("encrypted DNS bootstrap became a physical exception", got, err)
	}
	for _, transport := range []struct {
		kind, network string
		port          int
	}{{"udp", "udp", 53}, {"tcp", "tcp", 53}, {"tls", "tcp", 853}, {"https", "tcp", 443}, {"h3", "udp", 443}, {"quic", "udp", 853}} {
		graph := predecessorCopy(base)
		server := graph["dns"].(map[string]any)["servers"].([]any)[1].(map[string]any)
		server["type"] = transport.kind
		delete(server, "server_port")
		delete(server, "detour")
		if transport.kind != "udp" && transport.kind != "tcp" {
			server["tls"] = map[string]any{"enabled": true, "server_name": "bootstrap.example"}
		}
		if err := ValidateNodePredecessor("hysteria2", startJSON(t, profile), startJSON(t, graph)); err != nil {
			t.Fatal("explicit captured bootstrap fixture is invalid", err)
		}
		got, err := NodePhysicalEgress("hysteria2", startJSON(t, profile), startJSON(t, graph))
		expected := append(append([]PhysicalEgress{}, want...), PhysicalEgress{"9.9.9.9", transport.port, transport.network})
		if err != nil || !reflect.DeepEqual(got, expected) {
			t.Fatal("required physical bootstrap transport was lost or widened", transport.kind, got, err)
		}
		// Once the hostname dependency is gone, declaring the same physical
		// resolver must not leave a firewall exception behind.
		selected := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
		selected["server"] = "1.1.1.1"
		delete(selected, "domain_resolver")
		if got, err := NodePhysicalEgress("hysteria2", startJSON(t, profile), startJSON(t, graph)); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("unused declared resolver gained an exception", got, err)
		}
	}
	home, graph := compiledEgressFixture(t, "naive-h2", "")
	if got, err := NodePhysicalEgress("naive-h2", startJSON(t, home), startJSON(t, graph)); err != nil || !reflect.DeepEqual(got, []PhysicalEgress{{"192.0.2.44", 443, "tcp"}}) {
		t.Fatal("literal Naive placeholder resolver leaked Home DNS onto the physical path", got, err)
	}
	delete(graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any), "detour")
	if got, err := NodePhysicalEgress("naive-h2", startJSON(t, home), startJSON(t, graph)); err == nil || got != nil {
		t.Fatal("selected Home DNS acquired direct physical permission", got)
	}
}
