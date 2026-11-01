//go:build linux && routervpn_controller_privileged

package main

import (
	"router-vpn/internal/common"
	"strings"
)

// These exact cases retain the existing full installed public Connect,
// lifecycle and sealed restoration assertions with the independent final HY2
// peer behind an authenticated AES or AES-plus-whitening UDP-only route.
var linuxHostTUNHysteria2LayerCases = []string{
	"hy2-aes-public-connect",
	"hy2-aes-home-lan",
	"hy2-aes-wrong-key",
	"hy2-aes-wrong-layer-key",
	"hy2-aes-wrong-trust",
	"hy2-aes-wrong-salamander",
	"hy2-aes-resolver-failure",
	"hy2-aes-wrong-node",
	"hy2-aes-active-network-change",
	"hy2-aes-cancelled-proof",
	"hy2-aes-restore-sealed",
	"hy2-aes-always",
	"hy2-aes-cover-connect",
	"hy2-aes-cover-restore",
	"hy2-aes-mtu-rollback",
	"hy2-aes-mtu-commit",
	"hy2-whitening-public-connect",
	"hy2-whitening-home-lan",
	"hy2-whitening-wrong-key",
	"hy2-whitening-wrong-layer-key",
	"hy2-whitening-wrong-trust",
	"hy2-whitening-wrong-salamander",
	"hy2-whitening-resolver-failure",
	"hy2-whitening-wrong-node",
	"hy2-whitening-active-network-change",
	"hy2-whitening-cancelled-proof",
	"hy2-whitening-restore-sealed",
	"hy2-whitening-always",
	"hy2-whitening-cover-connect",
	"hy2-whitening-cover-restore",
	"hy2-whitening-mtu-rollback",
	"hy2-whitening-mtu-commit",
	"hy2-whitening-wrong-whitening",
}

func linuxHostTUNHysteria2LayerCase(scenario string) bool {
	for _, value := range linuxHostTUNHysteria2LayerCases {
		if value == scenario {
			return true
		}
	}
	return false
}

func linuxHostTUNHysteria2Layer(scenario string) string {
	if !linuxHostTUNHysteria2LayerCase(scenario) {
		return ""
	}
	if strings.HasPrefix(scenario, "hy2-aes-") {
		return common.StartLayerAES256GCM
	}
	return common.StartLayerAES256GCMXOR
}

func linuxHostTUNHysteria2Action(scenario string) string {
	if linuxHostTUNHysteria2LayerCase(scenario) {
		if strings.HasPrefix(scenario, "hy2-aes-") {
			return strings.TrimPrefix(scenario, "hy2-aes-")
		}
		return strings.TrimPrefix(scenario, "hy2-whitening-")
	}
	return strings.TrimPrefix(scenario, "hy2-")
}
