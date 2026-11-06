package mobilemultihop

import (
	"errors"
	"net/netip"
)

// CONNECT carries streams only. This first captured composition permits an
// unlayered SS2022 final and its explicitly selected literal TCP resolver.
// It never substitutes TCP for a saved UDP policy or invents packet carriage.
func importedCONNECTCapture(graph, final map[string]any, entryLayer, mode string, profile map[string]any) error {
	bad := errors.New("CONNECT entry requires Local SS2022 with both Start Layers Off and captured Home or custom literal TCP DNS")
	off := func(s string) bool { return s == "" || s == "off" }
	if mode != "shadowsocks" || final["type"] != "shadowsocks" || !importedSS2022Method(predecessorText(final, "method")) || !off(entryLayer) || !off(predecessorText(profile, "start_layer")) || predecessorText(final, "detour") != "" {
		return bad
	}
	// This capture has no separately proven Router UoT service authority.
	if _, present := final["udp_over_tcp"]; present {
		return bad
	}
	dnsMode := predecessorText(profile, "dns_mode")
	if dnsMode != "" && dnsMode != "home" && dnsMode != "custom" {
		return bad
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return bad
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) != 1 {
		return bad
	}
	server, ok := servers[0].(map[string]any)
	if !ok || server["type"] != "tcp" || server["detour"] != "proxy" || dns["final"] != server["tag"] {
		return bad
	}
	ip, err := netip.ParseAddr(predecessorText(server, "server"))
	if err != nil || ip.Zone() != "" || ip.Is4In6() {
		return bad
	}
	final["network"] = "tcp"
	return nil
}
