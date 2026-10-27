package mobilemultihop

import (
	"reflect"
	"testing"
)

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
