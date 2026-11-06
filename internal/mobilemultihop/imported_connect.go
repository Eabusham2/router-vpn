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
	if err := importedCONNECTDNS(graph, authorized); err != nil {
		return false, err
	}
	if authorized {
		final["udp_over_tcp"] = map[string]any{"enabled": true, "version": float64(2)}
	} else {
		final["network"] = "tcp"
	}
	return authorized, nil
}

// NewNodeProfile owns policy selection and bootstrap capture. This checks only
// that its complete DNS closure can use this CONNECT carrier, without choosing
// or rewriting a resolver, TLS identity, path, port, or query option.
func importedCONNECTDNS(graph map[string]any, udp bool) error {
	bad := errors.New("CONNECT DNS requires the captured final route and compatible selected/bootstrap transports")
	dns, ok := graph["dns"].(map[string]any)
	if !ok || dns["final"] != ExternalDNSTag {
		return bad
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) < 1 || len(servers) > 2 {
		return bad
	}
	primary, ok := servers[0].(map[string]any)
	if !ok || primary["tag"] != ExternalDNSTag {
		return bad
	}
	transport := make(map[string]any, len(primary))
	for key, value := range primary {
		if key != "domain_resolver" {
			transport[key] = value
		}
	}
	if err := externalDNSTransport(transport, "proxy", false, udp); err != nil {
		return err
	}
	_, literalErr := netip.ParseAddr(predecessorText(primary, "server"))
	if literalErr == nil {
		if len(servers) != 1 {
			return bad
		}
		if _, present := primary["domain_resolver"]; present {
			return bad
		}
		return nil
	}
	if len(servers) != 2 {
		return bad
	}
	bootstrap, ok := servers[1].(map[string]any)
	if !ok || bootstrap["tag"] != "external-dns-bootstrap" {
		return bad
	}
	if err := externalDNSTransport(bootstrap, "proxy", true, udp); err != nil {
		return err
	}
	query, ok := primary["domain_resolver"].(map[string]any)
	if !ok {
		return bad
	}
	return externalDNSQuery(query, "external-dns-bootstrap")
}
