//go:build linux && routervpn_controller_privileged

package main

import (
	"strings"

	"router-vpn/internal/common"
)

// The complete installed host owns each source, selected policy and physical
// UDP grant. The separate peer retains the original cryptographic client while
// the inner WireGuard bind admits only the explicitly captured AES relay.
var linuxHostTUNWireGuardLayerCases = []string{
	"wg-aes-public-connect",
	"wg-aes-home-lan",
	"wg-aes-wrong-key",
	"wg-aes-wrong-psk",
	"wg-aes-wrong-layer-key",
	"wg-aes-resolver-failure",
	"wg-aes-wrong-node",
	"wg-aes-active-network-change",
	"wg-aes-cancelled-proof",
	"wg-aes-restore-sealed",
	"wg-aes-always",
	"wg-aes-cover-connect",
	"wg-aes-cover-restore",
	"wg-aes-mtu-rollback",
	"wg-aes-mtu-commit",
	"wg-whitening-public-connect",
	"wg-whitening-home-lan",
	"wg-whitening-wrong-key",
	"wg-whitening-wrong-psk",
	"wg-whitening-wrong-layer-key",
	"wg-whitening-resolver-failure",
	"wg-whitening-wrong-node",
	"wg-whitening-active-network-change",
	"wg-whitening-cancelled-proof",
	"wg-whitening-restore-sealed",
	"wg-whitening-always",
	"wg-whitening-cover-connect",
	"wg-whitening-cover-restore",
	"wg-whitening-mtu-rollback",
	"wg-whitening-mtu-commit",
	"wg-whitening-wrong-whitening",
}

func linuxHostTUNWireGuardLayerCase(scenario string) bool {
	for _, value := range linuxHostTUNWireGuardLayerCases {
		if value == scenario {
			return true
		}
	}
	return false
}

func linuxHostTUNWireGuardLayer(scenario string) string {
	if !linuxHostTUNWireGuardLayerCase(scenario) {
		return ""
	}
	if strings.HasPrefix(scenario, "wg-aes-") {
		return common.StartLayerAES256GCM
	}
	return common.StartLayerAES256GCMXOR
}

func linuxHostTUNWireGuardAction(scenario string) string {
	if linuxHostTUNWireGuardLayerCase(scenario) {
		if strings.HasPrefix(scenario, "wg-aes-") {
			return strings.TrimPrefix(scenario, "wg-aes-")
		}
		return strings.TrimPrefix(scenario, "wg-whitening-")
	}
	return strings.TrimPrefix(scenario, "wg-")
}

func linuxHostTUNFinalProtocolCounters(peer *linuxHostTUNPeer) bool {
	return peer.mode == "hysteria2" || peer.mode == "wg" && peer.layer != ""
}
