package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestExternalProxyJumboRetainsVirtualCapacityAndTransportMTUs(t *testing.T) {
	for _, protocol := range externalTestProtocols[1:] {
		for _, entry := range []string{"", "wireguard", "socks5", "hysteria2"} {
			for _, mode := range []string{"auto", "default", "fixed", "manual"} {
				t.Run(protocol+"/"+entry+"/"+mode, func(t *testing.T) {
					graph, capture := externalTestFixture(t, protocol, entry)
					profile := capture["profile"].(map[string]any)
					profile["jumbo_tun"], profile["mtu_policy"], profile["manual_mtu"] = true, mode, float64(9000)
					input, selected := externalTestJSON(t, graph), externalTestJSON(t, capture)
					policy, err := NewExternalPolicy(input, selected)
					if err != nil {
						t.Fatal(err)
					}
					compiled, metadata := externalTestRead(t, policy.Config()), externalTestRead(t, policy.Metadata())
					if compiled["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(9000) || metadata["configured_mtu"] != float64(9000) {
						t.Fatal("selected proxy Jumbo was silently discarded")
					}
					want := mode
					if mode == "manual" {
						want = "fixed"
					}
					if metadata["mtu_policy"] != want || metadata["auto_mtu"] == "measured" {
						t.Fatal("virtual capacity became a measured path MTU", metadata)
					}
					for _, family := range []string{"outbounds", "endpoints"} {
						if !reflect.DeepEqual(compiled[family], graph[family]) {
							t.Fatal("Jumbo changed captured packet/proxy transport", family)
						}
					}
					if input != externalTestJSON(t, graph) || selected != externalTestJSON(t, capture) {
						t.Fatal("Jumbo compilation mutated caller source")
					}
				})
			}
		}
	}
}

func TestExternalProxyEntryJumboSurvivesAnotherProxyExit(t *testing.T) {
	for _, entry := range externalTestProtocols[1:] {
		graph, capture := externalTestFixture(t, "https-connect", entry)
		capture["entry"].(map[string]any)["jumbo_tun"] = true
		policy, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
		if err != nil {
			t.Fatal(entry, err)
		}
		compiled := externalTestRead(t, policy.Config())
		if compiled["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(9000) {
			t.Fatal("captured proxy entry Jumbo was discarded", entry)
		}
	}
}

func TestExternalJumboRejectsPacketExpansionAndConflictingSelections(t *testing.T) {
	for _, fault := range []string{"flag-string", "flag-number", "flag-null", "entry-flag-string", "fixed-exit", "fixed-proxy-entry", "packet-entry", "wireguard-exit", "amnezia-exit", "openvpn-tcp-exit", "openvpn-udp-exit", "inherited-packet-exit"} {
		t.Run(fault, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "https-connect", "socks5")
			profile, entry := capture["profile"].(map[string]any), capture["entry"].(map[string]any)
			profile["jumbo_tun"] = true
			switch fault {
			case "flag-string":
				profile["jumbo_tun"] = "true"
			case "flag-number":
				profile["jumbo_tun"] = 1
			case "flag-null":
				profile["jumbo_tun"] = nil
			case "entry-flag-string":
				entry["jumbo_tun"] = "false"
			case "fixed-exit":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1400
			case "fixed-proxy-entry":
				entry["mtu_policy"], entry["manual_mtu"] = "fixed", 1400
			case "packet-entry":
				graph, capture = externalTestFixture(t, "https-connect", "wireguard")
				capture["entry"].(map[string]any)["jumbo_tun"] = true
			case "wireguard-exit", "amnezia-exit", "openvpn-tcp-exit", "openvpn-udp-exit", "inherited-packet-exit":
				graph, capture = externalTestFixture(t, "wireguard", "socks5")
				if fault == "amnezia-exit" {
					externalAmneziaReplace(t, graph, capture, false, "strong")
				}
				if fault == "openvpn-tcp-exit" {
					externalOpenVPNReplace(t, graph, capture, false, "tcp")
				}
				if fault == "openvpn-udp-exit" {
					externalOpenVPNReplace(t, graph, capture, false, "udp")
				}
				if fault == "inherited-packet-exit" {
					capture["entry"].(map[string]any)["jumbo_tun"] = true
				} else {
					capture["profile"].(map[string]any)["jumbo_tun"] = true
				}
			}
			if policy, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil || policy != nil {
				t.Fatal("unsafe or malformed Jumbo became a runnable graph", fault)
			}
		})
	}
}
