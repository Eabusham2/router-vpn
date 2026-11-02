//go:build linux && routervpn_controller_privileged

package main

// Each name keeps a separate installed result while sharing the same complete
// host lifecycle assertions. Only these explicitly enumerated WG/plain cases
// can select the independent WireGuard peer; unknown graphs stay rejected.
var linuxHostTUNWireGuardCases = []string{
	"wg-public-connect", "wg-home-lan", "wg-wrong-key", "wg-resolver-failure", "wg-wrong-node",
	"wg-active-network-change", "wg-cancelled-proof", "wg-restore-sealed", "wg-always",
	"wg-cover-connect", "wg-cover-restore",
}

func linuxHostTUNWireGuardCase(scenario string) bool {
	for _, value := range linuxHostTUNWireGuardCases {
		if value == scenario {
			return true
		}
	}
	return linuxHostTUNWireGuardLayerCase(scenario)
}

func linuxHostTUNAction(scenario string) string {
	if linuxHostTUNSIP003Case(scenario) {
		return linuxHostTUNSIP003Action(scenario)
	}
	if linuxHostTUNWireGuardCase(scenario) {
		return linuxHostTUNWireGuardAction(scenario)
	}
	if linuxHostTUNHysteria2Case(scenario) {
		return linuxHostTUNHysteria2Action(scenario)
	}
	if linuxHostTUNAmneziaCase(scenario) {
		return linuxHostTUNAmneziaAction(scenario)
	}
	return scenario
}

func linuxHostTUNMode(scenario string) string {
	if linuxHostTUNSIP003Case(scenario) {
		return "ss-v2ray"
	}
	if linuxHostTUNWireGuardCase(scenario) {
		return "wg"
	}
	if linuxHostTUNHysteria2Case(scenario) {
		return "hysteria2"
	}
	if linuxHostTUNAmneziaCase(scenario) {
		return linuxHostTUNAmneziaMode(scenario)
	}
	return "shadowsocks"
}

func linuxHostTUNEncryptedTCP(peer *linuxHostTUNPeer, before, after linuxHostTUNPeerReply) bool {
	if peer.mode == "ss-v2ray" {
		return after.ProtocolTCP > before.ProtocolTCP && after.ProtocolRawTCP >= before.ProtocolRawTCP && after.ProtocolRawTCP > 0 && after.ProtocolTLSHTTP > 0 && after.ProtocolWebSocket > 0 && after.ProtocolMux > before.ProtocolMux && after.RawTCP >= before.RawTCP && after.RawTCP > 0 && (peer.layer == "" || after.PlainTCP > 0)
	}
	if linuxHostTUNFinalProtocolCounters(peer) {
		return after.ProtocolTCP > before.ProtocolTCP && after.ProtocolRawUDP > before.ProtocolRawUDP &&
			before.RawTCP == 0 && after.RawTCP == 0 && after.RawUDP > before.RawUDP
	}
	if after.PlainTCP <= before.PlainTCP {
		return false
	}
	if peer.mode == "wg" || linuxHostTUNIsAmnezia(peer.mode) {
		return before.RawTCP == 0 && after.RawTCP == 0 && after.RawUDP > before.RawUDP
	}
	return after.RawTCP > before.RawTCP
}
