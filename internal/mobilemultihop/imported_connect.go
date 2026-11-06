package mobilemultihop

import (
	"errors"
	"net/netip"
	"router-vpn/internal/nativecomposite"
)

// CONNECT carries streams only. Datagram carriage requires the final node's
// exact configured SS UoT-v2 authority; this is not a live receiver proof.
// Without that authority the original TCP-only composition remains unchanged.
func importedCONNECTCapture(graph, final map[string]any, entryLayer, mode string, profile map[string]any, files string) (bool, error) {
	bad := errors.New("CONNECT requires an Off entry and captured SS final: TCP-only without service authority, or explicit UoT-v2 authority for UDP and final Start Layers")
	off := func(s string) bool { return s == "" || s == "off" }
	assets, err := nodeProfileAssets(files)
	if err != nil {
		return false, err
	}
	defer func() {
		for _, data := range assets {
			clear(data)
		}
	}()
	_, authorized := assets[nativecomposite.SSServiceAsset]
	if authorized {
		if err := ValidateCapturedSSService(files, predecessorText(profile, "node_proof_id")); err != nil {
			return false, err
		}
	}
	layer := predecessorText(profile, "start_layer")
	expectedType := "shadowsocks"
	if authorized && layer == "aes-256-gcm+xor-whitening" {
		expectedType = "routervpn-aes-xor"
	}
	if mode != "shadowsocks" || final["type"] != expectedType || !importedSS2022Method(predecessorText(final, "method")) || !off(entryLayer) || predecessorText(final, "detour") != "" {
		return false, bad
	}
	if !off(layer) && (!authorized || (layer != "aes-256-gcm" && layer != "aes-256-gcm+xor-whitening")) {
		return false, bad
	}
	// Inline options never supply authority. The separately captured declaration
	// is validated against the original six-field source before graph derivation.
	if _, present := final["udp_over_tcp"]; present {
		return false, bad
	}
	dnsMode := predecessorText(profile, "dns_mode")
	if dnsMode != "" && dnsMode != "home" && dnsMode != "custom" {
		return false, bad
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return false, bad
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) != 1 {
		return false, bad
	}
	server, ok := servers[0].(map[string]any)
	if !ok || (server["type"] != "tcp" && (!authorized || server["type"] != "udp")) || server["detour"] != "proxy" || dns["final"] != server["tag"] {
		return false, bad
	}
	ip, err := netip.ParseAddr(predecessorText(server, "server"))
	if err != nil || ip.Zone() != "" || ip.Is4In6() {
		return false, bad
	}
	if authorized {
		final["udp_over_tcp"] = map[string]any{"enabled": true, "version": float64(2)}
	} else {
		final["network"] = "tcp"
	}
	return authorized, nil
}
