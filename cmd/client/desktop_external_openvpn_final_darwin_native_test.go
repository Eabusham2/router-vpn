//go:build darwin && routervpn_controller_privileged

package main

import "strings"

var macOSExternalOpenVPNFinalCases = []string{
	"wg-entry-openvpn-tcp",
	"wg-entry-openvpn-tcp-always",
	"wg-entry-openvpn-udp",
	"wg-entry-openvpn-udp-always",
	"wg-entry-openvpn-tcp-fallback",
	"wg-entry-openvpn-tcp-fallback-always",
	"wg-entry-openvpn-mixed-fallback",
	"wg-entry-openvpn-mixed-fallback-always",
	"awg-entry-fast-openvpn-tcp",
	"awg-entry-fast-openvpn-tcp-always",
	"awg-entry-fast-openvpn-udp",
	"awg-entry-fast-openvpn-udp-always",
	"awg-entry-fast-openvpn-tcp-fallback",
	"awg-entry-fast-openvpn-tcp-fallback-always",
	"awg-entry-fast-openvpn-mixed-fallback",
	"awg-entry-fast-openvpn-mixed-fallback-always",
	"awg-entry-strong-openvpn-tcp",
	"awg-entry-strong-openvpn-tcp-always",
	"awg-entry-strong-openvpn-udp",
	"awg-entry-strong-openvpn-udp-always",
	"awg-entry-strong-openvpn-tcp-fallback",
	"awg-entry-strong-openvpn-tcp-fallback-always",
	"awg-entry-strong-openvpn-mixed-fallback",
	"awg-entry-strong-openvpn-mixed-fallback-always",
	"wg-entry-openvpn-tcp-wrong-control",
	"wg-entry-openvpn-udp-wrong-control",
	"wg-entry-openvpn-tcp-wrong-provider-trust",
	"wg-entry-openvpn-udp-wrong-password",
	"wg-entry-openvpn-tcp-wrong-username",
	"wg-entry-openvpn-udp-wrong-dns",
	"wg-entry-openvpn-tcp-wrong-trust",
	"wg-entry-openvpn-udp-wrong-exit",
	"wg-entry-openvpn-udp-wrong-exit-address",
	"wg-entry-openvpn-tcp-wrong-entry-key",
	"wg-entry-openvpn-udp-wrong-entry-psk",
	"wg-entry-openvpn-tcp-wrong-entry-public",
	"awg-entry-fast-openvpn-udp-wrong-entry-parameters",
	"awg-entry-strong-openvpn-tcp-wrong-entry-parameters",
	"awg-entry-strong-openvpn-udp-wrong-entry-psk",
}

func macOSExternalOpenVPNFinalScenario(scenario string) (entry, transport, fault string, found bool) {
	for _, candidate := range macOSExternalOpenVPNFinalCases {
		if scenario != candidate {
			continue
		}
		for _, entry := range []string{"wireguard", "fast", "strong"} {
			prefix := "wg-entry-openvpn-"
			if entry != "wireguard" {
				prefix = "awg-entry-" + entry + "-openvpn-"
			}
			if !strings.HasPrefix(scenario, prefix) {
				continue
			}
			rest := strings.TrimPrefix(scenario, prefix)
			for _, transport := range []string{"tcp-fallback", "mixed-fallback", "tcp", "udp"} {
				if rest != transport && !strings.HasPrefix(rest, transport+"-") {
					continue
				}
				suffix := strings.TrimPrefix(rest, transport)
				if suffix != "" && suffix != "-always" {
					fault = strings.TrimPrefix(suffix, "-")
				}
				return entry, transport, fault, true
			}
		}
	}
	return "", "", "", false
}
