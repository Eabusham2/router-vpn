package mobilemultihop

import (
	"errors"
	"reflect"
	"testing"
)

func TestExternalCompletePhysicalProjectionMatchesCapturedProtocol(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			policy, want := directEgressFixture(t, protocol)
			actual, err := policy.PhysicalEgress()
			if protocol == "socks5" {
				if !errors.Is(err, ErrDynamicPhysicalEgress) || actual != nil {
					t.Fatal("negotiated physical SOCKS relay acquired a fabricated fixed port", actual, err)
				}
				return
			}
			if protocol == "shadowsocks" {
				want = append(want, PhysicalEgress{"203.0.113.20", 443, "udp"})
			}
			if err != nil || !reflect.DeepEqual(actual, want) {
				t.Fatal("complete captured graph lost its physical socket set", actual, want, err)
			}
			policy.config += " "
			if actual, err := policy.PhysicalEgress(); err == nil || actual != nil {
				t.Fatal("changed compiled source borrowed another physical capture")
			}
		})
	}
	if actual, err := (*ExternalPolicy)(nil).PhysicalEgress(); err == nil || actual != nil {
		t.Fatal("nil compiled policy acquired physical authority")
	}
}

func TestExternalCompletePhysicalProjectionKeepsNegotiatedRelayInsidePredecessor(t *testing.T) {
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				source, entry := externalPredecessorFixture(t, mode, layer, false)
				graph, capture := externalTestFixture(t, "socks5", "")
				capture["entry"], capture["entry_tag"], capture["predecessor_config"] = entry, externalEntryTag, source
				capture["profile"].(map[string]any)["multihop_entry_mode"] = mode
				policy, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
				if err != nil {
					t.Fatal(err)
				}
				actual, err := policy.PhysicalEgress()
				if err != nil {
					t.Fatal("negotiated inner relay escaped the captured predecessor", err)
				}
				expected, err := NodePhysicalEgress(mode, startJSON(t, entry), source)
				if err != nil || !reflect.DeepEqual(actual, expected) {
					t.Fatal("provider or selected DNS acquired a physical bypass", actual, expected, err)
				}
			})
		}
	}
}

func TestExternalCompletePhysicalProjectionRejectsSubstitutedSelector(t *testing.T) {
	source, capture := externalExecutionFixture(t, "auto")
	prepared, err := PrepareExternalExecutionCapture(source, capture, "")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewExternalPolicy(source, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.PhysicalEgress(); err != nil {
		t.Fatal("valid captured execution selector lost its physical path", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"other default":            func(node map[string]any) { node["default"] = "direct" },
		"extra candidate":          func(node map[string]any) { node["outbounds"] = []any{LocalTag, ServerTag, "direct"} },
		"substituted candidate":    func(node map[string]any) { node["outbounds"] = []any{LocalTag, "direct"} },
		"retained connections":     func(node map[string]any) { node["interrupt_exist_connections"] = false },
		"extra selector authority": func(node map[string]any) { node["fallback"] = "direct" },
	} {
		t.Run(name, func(t *testing.T) {
			graph := externalTestRead(t, policy.Config())
			mutate(externalTestFind(t, graph, ExternalFinalTag))
			// Exercise the private projection separately from the metadata digest
			// rejection, so an altered selector cannot quietly broaden egress.
			if got, err := compiledPhysicalEgress(externalTestJSON(t, graph), []string{"tcp", "udp"}); err == nil || got != nil {
				t.Fatal("substituted execution selector acquired physical authority", got, err)
			}
		})
	}
}

func TestExternalCompletePhysicalProjectionRejectsUnownedPrivateOpenVPNRemote(t *testing.T) {
	source, capture := externalOpenVPNExecutionFixture(t, "local", "aes-256-gcm")
	policy, err := NewExternalPolicy(source, capture)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := policy.PhysicalEgress(); err != nil || len(got) == 0 {
		t.Fatal("valid layered OpenVPN graph lost its physical predecessor", got, err)
	}
	for name, mutate := range map[string]func(map[string]any, map[string]any){
		"missing fixed layer": func(_ map[string]any, node map[string]any) { delete(node, "detour") },
		"ordinary detour":     func(graph, node map[string]any) { node["detour"] = "entry-wg" },
		"loopback inner remote": func(_ map[string]any, node map[string]any) {
			node["servers"].([]any)[0].(map[string]any)["server"] = "127.0.0.1"
		},
		"zero inner port": func(_ map[string]any, node map[string]any) {
			node["servers"].([]any)[0].(map[string]any)["server_port"] = float64(0)
		},
		"unbounded inner transport": func(_ map[string]any, node map[string]any) {
			node["servers"].([]any)[0].(map[string]any)["network"] = "ip"
		},
		"extra remote authority": func(_ map[string]any, node map[string]any) {
			node["servers"].([]any)[0].(map[string]any)["fallback"] = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			graph := externalTestRead(t, policy.Config())
			mutate(graph, externalTestFind(t, graph, ExternalFinalTag))
			if got, err := compiledPhysicalEgress(externalTestJSON(t, graph), []string{"tcp", "udp"}); err == nil || got != nil {
				t.Fatal("unowned private OpenVPN remote acquired physical authority", got, err)
			}
		})
	}
}

func directEgressFixture(t *testing.T, protocol string) (*ExternalPolicy, []PhysicalEgress) {
	t.Helper()
	base := protocol
	if protocol == "amneziawg" || protocol == "openvpn" {
		base = "wireguard"
	}
	graph, capture := externalTestFixture(t, base, "")
	profile := capture["profile"].(map[string]any)
	profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", "tcp", "9.9.9.9", float64(5353)
	want := []PhysicalEgress{{"203.0.113.20", 443, "tcp"}}
	switch protocol {
	case "wireguard", "hysteria2":
		want[0].Network = "udp"
	case "amneziawg":
		externalAmneziaReplace(t, graph, capture, false, "strong")
		want = []PhysicalEgress{{"192.0.2.1", 51820, "udp"}}
	case "openvpn":
		externalOpenVPNReplace(t, graph, capture, false, "udp")
		want = []PhysicalEgress{{"2001:db8::24", 443, "udp"}, {"203.0.113.24", 1194, "udp"}}
	}
	policy, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	return policy, want
}

func TestExternalPhysicalEgressCapturesOnlyActualProtocolSockets(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			policy, want := directEgressFixture(t, protocol)
			got, err := policy.DirectPhysicalEgress([]string{"tcp"})
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("wrong physical owner: got %v, want %v, error %v", got, want, err)
			}
			got, err = policy.DirectPhysicalEgress([]string{"tcp", "udp"})
			if protocol == "socks5" || protocol == "http-connect" || protocol == "https-connect" {
				if err == nil || got != nil {
					t.Fatal("invented a fixed UDP relay for a TCP/dynamic transport", got)
				}
				return
			}
			if protocol == "shadowsocks" {
				want = append(want, PhysicalEgress{"203.0.113.20", 443, "udp"})
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("lost packet transport: got %v, want %v, error %v", got, want, err)
			}
		})
	}
}

func TestExternalPhysicalEgressRetainsCapturedStartLayerAndEveryOpenVPNRemote(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, protocol := range externalExecutionProtocols {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				source, capture := externalDirectLayerFixture(t, protocol, layer)
				selected := externalTestRead(t, capture)
				profile := selected["profile"].(map[string]any)
				profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "custom", "tcp", "9.9.9.9"
				policy, err := NewExternalPolicy(source, externalTestJSON(t, selected))
				if err != nil {
					t.Fatal(err)
				}
				port := 8388
				if layer == "aes-256-gcm+xor-whitening" {
					port = 8389
				}
				network := "tcp"
				if protocol == "hysteria2" {
					network = "udp"
				}
				got, err := policy.DirectPhysicalEgress([]string{"tcp"})
				if err != nil || !reflect.DeepEqual(got, []PhysicalEgress{{"203.0.113.20", port, network}}) {
					t.Fatal("exposed private inner or lost outer layer", got, err)
				}
			})
		}
		t.Run("openvpn-mapped/"+layer, func(t *testing.T) {
			source, capture := externalOpenVPNLayerMapFixture(t, layer)
			graph, selected := externalTestRead(t, source), externalTestRead(t, capture)
			delete(externalTestFind(t, graph, ExternalFinalTag), "detour")
			graph["endpoints"] = []any{externalTestFind(t, graph, ExternalFinalTag)}
			graph["outbounds"] = []any{}
			delete(selected, "entry")
			delete(selected, "entry_tag")
			profile := selected["profile"].(map[string]any)
			profile["multihop_enabled"] = false
			profile["multihop_execution"] = "local"
			profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "custom", "tcp", "9.9.9.9"
			policy, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, selected))
			if err != nil {
				t.Fatal(err)
			}
			port1, port2 := 8388, 8390
			if layer == "aes-256-gcm+xor-whitening" {
				port1, port2 = 8389, 8389
			}
			got, err := policy.DirectPhysicalEgress([]string{"tcp", "udp"})
			want := []PhysicalEgress{{"203.0.113.20", port1, "udp"}, {"203.0.113.21", port2, "tcp"}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("mapped remote physical closure changed", got, want, err)
			}
		})
	}
}

func TestExternalPhysicalEgressCannotBorrowAnotherPathOrUnboundedNetwork(t *testing.T) {
	policy, _ := directEgressFixture(t, "shadowsocks")
	for _, networks := range [][]string{nil, {}, {""}, {"ip"}, {"tcp", "tcp"}, {"udp", "udp"}, {"tcp", "udp", "tcp"}} {
		if got, err := policy.DirectPhysicalEgress(networks); err == nil || got != nil {
			t.Fatal("unbounded physical request", networks, got)
		}
	}
	if got, err := (*ExternalPolicy)(nil).DirectPhysicalEgress([]string{"tcp"}); err == nil || got != nil {
		t.Fatal("nil owner projected sockets")
	}
	graph, capture := externalTestFixture(t, "shadowsocks", "wireguard")
	policy, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := policy.DirectPhysicalEgress([]string{"tcp"}); err == nil || got != nil {
		t.Fatal("borrowed a different entry graph", got)
	}
}
