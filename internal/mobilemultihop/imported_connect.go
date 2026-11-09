package mobilemultihop

import (
	"errors"
	"net/netip"
	"router-vpn/internal/nativecomposite"
)

// CONNECT carries streams only. The independently validated REALITY final has
// its own VLESS datagram carrier. SS instead requires the final node's exact
// configured UoT-v2 authority; without it the existing TCP-only path remains.
// None of these configured capabilities proves a live receiver or selected DNS.
func importedCONNECTCapture(graph, final map[string]any, entryLayer, mode string, profile map[string]any, files string) (string, error) {
	bad := errors.New("CONNECT requires its captured independent entry layer and a paired REALITY/Vision or SS2022 final with its own transport authority")
	off := func(s string) bool { return s == "" || s == "off" }
	// NewExternalPolicy has validated and retained this entry's independently
	// provisioned wrapper. It does not supply the final's UoT or layer authority.
	if !off(entryLayer) && entryLayer != "aes-256-gcm" && entryLayer != "aes-256-gcm+xor-whitening" {
		return "", bad
	}
	if importedVisionFinal(mode) {
		// NewNodeProfile and the exact Xray/layer validators run before this
		// branch and before an outer CONNECT detour is attached. Derive this
		// capability only from their real native VLESS final, never from an SS
		// service claim, inline UoT option or a caller-supplied metadata label.
		if final["type"] != "routervpn-xray" || final["mode"] != mode {
			return "", bad
		}
		for _, key := range []string{"udp_over_tcp", "network"} {
			if _, present := final[key]; present {
				return "", bad
			}
		}
		if err := importedCONNECTDNS(graph, true); err != nil {
			return "", err
		}
		return "vless-stream", nil
	}
	assets, err := nodeProfileAssets(files)
	if err != nil {
		return "", err
	}
	defer func() {
		for _, data := range assets {
			clear(data)
		}
	}()
	_, authorized := assets[nativecomposite.SSServiceAsset]
	if authorized {
		if err := ValidateCapturedSSService(files, predecessorText(profile, "node_proof_id")); err != nil {
			return "", err
		}
	}
	layer := predecessorText(profile, "start_layer")
	expectedType := "shadowsocks"
	if authorized && layer == "aes-256-gcm+xor-whitening" {
		expectedType = "routervpn-aes-xor"
	}
	if mode != "shadowsocks" || final["type"] != expectedType || !importedSS2022Method(predecessorText(final, "method")) || predecessorText(final, "detour") != "" {
		return "", bad
	}
	if !off(layer) && (!authorized || (layer != "aes-256-gcm" && layer != "aes-256-gcm+xor-whitening")) {
		return "", bad
	}
	// Inline options never supply authority. The separately captured declaration
	// is validated against the original six-field source before graph derivation.
	if _, present := final["udp_over_tcp"]; present {
		return "", bad
	}
	if err := importedCONNECTDNS(graph, authorized); err != nil {
		return "", err
	}
	if authorized {
		final["udp_over_tcp"] = map[string]any{"enabled": true, "version": float64(2)}
		return "uot-v2", nil
	}
	final["network"] = "tcp"
	return "tcp-only", nil
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
