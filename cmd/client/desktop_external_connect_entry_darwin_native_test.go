//go:build darwin && routervpn_controller_privileged

package main

import "strings"

// Exact native acceptance names, not public protocol or preset aliases.
var macOSExternalConnectEntryCases = []string{
	"wg-entry-http",
	"wg-entry-http-always",
	"wg-entry-https",
	"wg-entry-https-always",
	"awg-entry-http-fast",
	"awg-entry-http-fast-always",
	"awg-entry-http-strong",
	"awg-entry-http-strong-always",
	"awg-entry-https-fast",
	"awg-entry-https-fast-always",
	"awg-entry-https-strong",
	"awg-entry-https-strong-always",
	"wg-entry-http-wrong-entry-key",
	"wg-entry-http-wrong-exit-username",
	"wg-entry-http-wrong-exit-key",
	"wg-entry-http-wrong-dns",
	"wg-entry-http-wrong-exit",
	"wg-entry-https-wrong-entry-public",
	"wg-entry-https-wrong-exit-server-name",
	"wg-entry-https-wrong-exit-key",
	"wg-entry-https-wrong-trust",
	"awg-entry-http-fast-wrong-entry-parameters",
	"awg-entry-https-strong-wrong-entry-parameters",
	"awg-entry-https-strong-wrong-exit-key",
}

func macOSExternalConnectEntryScenario(scenario string) (protocol, variant, fault string, found bool) {
	for _, candidate := range macOSExternalConnectEntryCases {
		if candidate != scenario {
			continue
		}
		protocol, variant = "http-connect", "wireguard"
		if strings.Contains(scenario, "-https") {
			protocol = "https-connect"
		}
		if strings.HasPrefix(scenario, "awg-entry-") {
			variant = "strong"
			if strings.Contains(scenario, "-fast") {
				variant = "fast"
			}
		}
		if index := strings.Index(scenario, "-wrong-"); index >= 0 {
			fault = scenario[index+1:]
		}
		return protocol, variant, fault, true
	}
	return "", "", "", false
}
