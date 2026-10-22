package mobilemultihop

import "testing"

func TestExternalIdleTransportValidationDoesNotInventDNSOrRuntimeReadiness(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			base := protocol
			if base == "amneziawg" || base == "openvpn" {
				base = "wireguard"
			}
			graph, capture := externalTestFixture(t, base, "")
			if protocol == "amneziawg" {
				externalAmneziaReplace(t, graph, capture, false, "strong")
			}
			if protocol == "openvpn" {
				externalOpenVPNReplace(t, graph, capture, false, "tcp")
			}
			profile := capture["profile"].(map[string]any)
			profile["dns_mode"] = "home"
			source, frozen := externalTestJSON(t, graph), externalTestJSON(t, capture)
			if err := ValidateExternalTransport(source, frozen); err != nil {
				t.Fatal(err)
			}
			if source != externalTestJSON(t, graph) || frozen != externalTestJSON(t, capture) {
				t.Fatal("draft validation changed private saved transport or policy")
			}
			if _, err := NewExternalPolicy(source, frozen); err == nil {
				t.Fatal("an idle Home draft became a runnable direct connection")
			}
			profile["id"] = "replacement"
			if err := ValidateExternalTransport(source, externalTestJSON(t, capture)); err == nil {
				t.Fatal("transport validation borrowed another node's credentials")
			}
		})
	}
}

func TestExternalIdleTransportValidationKeepsNativeRejectionCoverage(t *testing.T) {
	for _, fault := range []string{"credential", "unowned-entry", "node", "protocol", "public-exit", "mtu", "lan", "graph", "selection"} {
		t.Run(fault, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "shadowsocks", "")
			profile := capture["profile"].(map[string]any)
			profile["dns_mode"] = "home"
			switch fault {
			case "credential":
				profile["external"].(map[string]any)["shadowsocks"].(map[string]any)["password"] = "replaced secret"
			case "unowned-entry":
				capture["entry_tag"] = "entry"
			case "node":
				profile["node_kind"] = "router-vpn"
			case "protocol":
				capture["protocol"] = "socks5"
			case "public-exit":
				capture["expected_public_ip"] = "192.168.50.1"
			case "mtu":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", 0
			case "lan":
				profile["home_lan_access"] = "false"
			case "graph":
				graph["route"].(map[string]any)["final"] = "foreign"
			case "selection":
				capture["schema"] = 2
			}
			if err := ValidateExternalTransport(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
				t.Fatal("invalid idle transport accepted")
			}
		})
	}
}
