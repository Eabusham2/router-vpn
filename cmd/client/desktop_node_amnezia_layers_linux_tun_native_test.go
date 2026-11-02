//go:build linux && routervpn_controller_privileged

package main

import (
	"strings"

	"router-vpn/internal/common"
)

// Each case retains the exact AWG native parameters and cryptographic peer;
// AES/whitening is a separate captured outer UDP owner, never a WG substitute.
var linuxHostTUNAmneziaLayerCases = []string{
	"awg2-fast-aes-public-connect",
	"awg2-fast-aes-home-lan",
	"awg2-fast-aes-wrong-key",
	"awg2-fast-aes-wrong-psk",
	"awg2-fast-aes-wrong-layer-key",
	"awg2-fast-aes-wrong-header",
	"awg2-fast-aes-wrong-padding",
	"awg2-fast-aes-resolver-failure",
	"awg2-fast-aes-wrong-node",
	"awg2-fast-aes-active-network-change",
	"awg2-fast-aes-cancelled-proof",
	"awg2-fast-aes-restore-sealed",
	"awg2-fast-aes-always",
	"awg2-fast-aes-cover-connect",
	"awg2-fast-aes-cover-restore",
	"awg2-fast-aes-mtu-rollback",
	"awg2-fast-aes-mtu-commit",
	"awg2-fast-whitening-public-connect",
	"awg2-fast-whitening-home-lan",
	"awg2-fast-whitening-wrong-key",
	"awg2-fast-whitening-wrong-psk",
	"awg2-fast-whitening-wrong-layer-key",
	"awg2-fast-whitening-wrong-header",
	"awg2-fast-whitening-wrong-padding",
	"awg2-fast-whitening-resolver-failure",
	"awg2-fast-whitening-wrong-node",
	"awg2-fast-whitening-active-network-change",
	"awg2-fast-whitening-cancelled-proof",
	"awg2-fast-whitening-restore-sealed",
	"awg2-fast-whitening-always",
	"awg2-fast-whitening-cover-connect",
	"awg2-fast-whitening-cover-restore",
	"awg2-fast-whitening-mtu-rollback",
	"awg2-fast-whitening-mtu-commit",
	"awg2-strong-aes-public-connect",
	"awg2-strong-aes-home-lan",
	"awg2-strong-aes-wrong-key",
	"awg2-strong-aes-wrong-psk",
	"awg2-strong-aes-wrong-layer-key",
	"awg2-strong-aes-wrong-header",
	"awg2-strong-aes-wrong-padding",
	"awg2-strong-aes-resolver-failure",
	"awg2-strong-aes-wrong-node",
	"awg2-strong-aes-active-network-change",
	"awg2-strong-aes-cancelled-proof",
	"awg2-strong-aes-restore-sealed",
	"awg2-strong-aes-always",
	"awg2-strong-aes-cover-connect",
	"awg2-strong-aes-cover-restore",
	"awg2-strong-aes-mtu-rollback",
	"awg2-strong-aes-mtu-commit",
	"awg2-strong-whitening-public-connect",
	"awg2-strong-whitening-home-lan",
	"awg2-strong-whitening-wrong-key",
	"awg2-strong-whitening-wrong-psk",
	"awg2-strong-whitening-wrong-layer-key",
	"awg2-strong-whitening-wrong-header",
	"awg2-strong-whitening-wrong-padding",
	"awg2-strong-whitening-resolver-failure",
	"awg2-strong-whitening-wrong-node",
	"awg2-strong-whitening-active-network-change",
	"awg2-strong-whitening-cancelled-proof",
	"awg2-strong-whitening-restore-sealed",
	"awg2-strong-whitening-always",
	"awg2-strong-whitening-cover-connect",
	"awg2-strong-whitening-cover-restore",
	"awg2-strong-whitening-mtu-rollback",
	"awg2-strong-whitening-mtu-commit",
	"awg2-fast-whitening-wrong-whitening",
	"awg2-strong-whitening-wrong-whitening",
}

func linuxHostTUNAmneziaLayerCase(scenario string) bool {
	for _, value := range linuxHostTUNAmneziaLayerCases {
		if value == scenario {
			return true
		}
	}
	return false
}
func linuxHostTUNAmneziaLayer(scenario string) string {
	if !linuxHostTUNAmneziaLayerCase(scenario) {
		return ""
	}
	if strings.HasPrefix(scenario, linuxHostTUNAmneziaMode(scenario)+"-aes-") {
		return common.StartLayerAES256GCM
	}
	return common.StartLayerAES256GCMXOR
}
func linuxHostTUNAmneziaAction(scenario string) string {
	mode := linuxHostTUNAmneziaMode(scenario)
	if linuxHostTUNAmneziaLayerCase(scenario) {
		if strings.HasPrefix(scenario, mode+"-aes-") {
			return strings.TrimPrefix(scenario, mode+"-aes-")
		}
		return strings.TrimPrefix(scenario, mode+"-whitening-")
	}
	return strings.TrimPrefix(scenario, mode+"-")
}
