//go:build linux && routervpn_controller_privileged

package main

import "strings"

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
	return false
}

func linuxHostTUNAction(scenario string) string {
	if linuxHostTUNWireGuardCase(scenario) {
		return strings.TrimPrefix(scenario, "wg-")
	}
	return scenario
}

func linuxHostTUNMode(scenario string) string {
	if linuxHostTUNWireGuardCase(scenario) {
		return "wg"
	}
	return "shadowsocks"
}

func linuxHostTUNEncryptedTCP(peer *linuxHostTUNPeer, before, after linuxHostTUNPeerReply) bool {
	if after.PlainTCP <= before.PlainTCP {
		return false
	}
	if peer.mode == "wg" {
		return before.RawTCP == 0 && after.RawTCP == 0 && after.RawUDP > before.RawUDP
	}
	return after.RawTCP > before.RawTCP
}
