//go:build darwin && routervpn_controller_privileged

package main

import "strings"

var macOSExternalAmneziaFinalCases = []string{
	"wg-entry-amneziawg-fast",
	"wg-entry-amneziawg-fast-always",
	"wg-entry-amneziawg-strong",
	"wg-entry-amneziawg-strong-always",
	"awg-entry-fast-amneziawg-fast",
	"awg-entry-fast-amneziawg-fast-always",
	"awg-entry-fast-amneziawg-strong",
	"awg-entry-fast-amneziawg-strong-always",
	"awg-entry-strong-amneziawg-fast",
	"awg-entry-strong-amneziawg-fast-always",
	"awg-entry-strong-amneziawg-strong",
	"awg-entry-strong-amneziawg-strong-always",
	"wg-entry-amneziawg-fast-wrong-exit-key",
	"wg-entry-amneziawg-fast-wrong-exit-peer-key",
	"wg-entry-amneziawg-fast-wrong-exit-psk",
	"wg-entry-amneziawg-fast-wrong-exit-parameters",
	"wg-entry-amneziawg-fast-wrong-exit-padding",
	"wg-entry-amneziawg-fast-wrong-exit-address",
	"wg-entry-amneziawg-fast-wrong-dns",
	"wg-entry-amneziawg-fast-wrong-trust",
	"wg-entry-amneziawg-fast-wrong-exit",
	"wg-entry-amneziawg-strong-wrong-exit-key",
	"wg-entry-amneziawg-strong-wrong-exit-peer-key",
	"wg-entry-amneziawg-strong-wrong-exit-psk",
	"wg-entry-amneziawg-strong-wrong-exit-parameters",
	"wg-entry-amneziawg-strong-wrong-exit-padding",
	"wg-entry-amneziawg-strong-wrong-exit-address",
	"wg-entry-amneziawg-strong-wrong-dns",
	"wg-entry-amneziawg-strong-wrong-trust",
	"wg-entry-amneziawg-strong-wrong-exit",
	"awg-entry-fast-amneziawg-strong-wrong-entry-parameters",
	"awg-entry-strong-amneziawg-fast-wrong-entry-parameters",
	"awg-entry-strong-amneziawg-strong-wrong-entry-psk",
	"wg-entry-amneziawg-strong-wrong-entry-key",
	"wg-entry-amneziawg-strong-wrong-entry-psk",
	"wg-entry-amneziawg-strong-wrong-entry-public",
}

func macOSExternalAmneziaFinalScenario(scenario string) (entry, final, fault string, found bool) {
	for _, candidate := range macOSExternalAmneziaFinalCases {
		if scenario != candidate {
			continue
		}
		for _, entry := range []string{"wireguard", "fast", "strong"} {
			for _, final := range []string{"fast", "strong"} {
				prefix := "wg-entry-amneziawg-" + final
				if entry != "wireguard" {
					prefix = "awg-entry-" + entry + "-amneziawg-" + final
				}
				if scenario != prefix && !strings.HasPrefix(scenario, prefix+"-") {
					continue
				}
				suffix := strings.TrimPrefix(scenario, prefix)
				if suffix != "" && suffix != "-always" {
					fault = strings.TrimPrefix(suffix, "-")
				}
				return entry, final, fault, true
			}
		}
	}
	return "", "", "", false
}
