package multihoprelay

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativeopenvpn"
)

// ExternalMode identifies native external execution families. Packet families
// additionally require an independently provisioned public server-peer capture.
func ExternalMode(mode string) bool {
	switch mode {
	case "wireguard", "amneziawg", "openvpn", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect":
		return true
	}
	return false
}

// ExternalSelection compiles the exact saved external block into the same
// private relay representation used by native clients and operator pairing.
// It never resolves names, adds credentials, defaults DNS, or opens a socket.
// The optional layer must be the same object saved inside external.start_layer;
// callers also verify its mode against the containing profile's selection.
func ExternalSelection(id, protocol string, external map[string]any, layer *StartLayer) (Exit, error) {
	bad := errors.New("external relay requires a complete captured authenticated proxy and response endpoint")
	if !ident.MatchString(id) || !ExternalMode(protocol) || external["protocol"] != protocol {
		return Exit{}, bad
	}
	if raw, exists := external["start_layer"]; exists {
		if layer == nil || raw == nil {
			return Exit{}, bad
		}
		encoded, err := json.Marshal(raw)
		if err != nil || len(encoded) > 16384 {
			return Exit{}, bad
		}
		var saved StartLayer
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&saved) != nil {
			return Exit{}, bad
		}
		left, err1 := json.Marshal(saved)
		right, err2 := json.Marshal(layer)
		if err1 != nil || err2 != nil || !bytes.Equal(left, right) {
			return Exit{}, bad
		}
	} else if layer != nil {
		return Exit{}, bad
	}
	transport, err := ExternalTransport(protocol, external)
	if err != nil {
		return Exit{}, err
	}
	expected, ok := external["expected_public_ip"].(string)
	if !ok {
		return Exit{}, bad
	}
	exit := Exit{ID: id, Mode: protocol, Transport: transport, StartLayer: layer, External: &ExternalExit{ExpectedPublicIP: expected}}
	if raw, mapped := external["openvpn_response_probes"]; mapped {
		if protocol != "openvpn" {
			return Exit{}, bad
		}
		if _, legacy := external["response_probe"]; legacy {
			return Exit{}, bad
		}
		encoded, err := json.Marshal(raw)
		var probes nativeopenvpn.ResponseProbes
		if err != nil || json.Unmarshal(encoded, &probes) != nil || probes.Validate(transport) != nil {
			return Exit{}, bad
		}
		exit.External.OpenVPNResponseProbes = probes
		if rawLayers, present := external["openvpn_start_layers"]; present {
			encoded, err := json.Marshal(rawLayers)
			var layers nativeopenvpn.StartLayers
			if err != nil || layer != nil || json.Unmarshal(encoded, &layers) != nil || layers.Validate(transport, probes, layers.Mode()) != nil { return Exit{}, bad }
			exit.External.OpenVPNStartLayers = layers
		}
	} else {
		rawProbe, ok := external["response_probe"].(map[string]any)
		if !ok {
			return Exit{}, bad
		}
		for key := range rawProbe {
			if key != "url" && key != "server_name" {
				return Exit{}, bad
			}
		}
		probeURL, urlOK := rawProbe["url"].(string)
		probeName := ""
		if value, exists := rawProbe["server_name"]; exists {
			var nameOK bool
			probeName, nameOK = value.(string)
			if !nameOK {
				return Exit{}, bad
			}
		}
		if !urlOK {
			return Exit{}, bad
		}
		exit.External.ResponseProbe = ResponseProbe{URL: probeURL, ServerName: probeName}
	}
	if ExternalPacketMode(protocol) {
		pair, err := externalPacketSelection(protocol, external, transport)
		if err != nil {
			return Exit{}, err
		}
		exit.External.Packet = pair
	}
	if protocol == "openvpn" {
		pair, err := externalOpenVPNSelection(external)
		if err != nil {
			return Exit{}, err
		}
		exit.External.OpenVPN = pair
	}
	validated, err := externalTransport(exit)
	if err != nil {
		return Exit{}, err
	}
	exit.Transport = validated
	// Freeze all private material; callers cannot mutate the source after proof.
	encoded, err := json.Marshal(exit)
	var frozen Exit
	if err != nil || json.Unmarshal(encoded, &frozen) != nil {
		return Exit{}, bad
	}
	return frozen, nil
}

// ExternalTransport validates the saved native proxy independently of Compare's
// HTTPS response endpoint. This is also used to validate a Local-only imported
// Start Layer without inventing a comparison proof or requiring proxy credentials
// that the selected Local protocol does not use.
func ExternalTransport(protocol string, external map[string]any) (map[string]any, error) {
	bad := errors.New("external native proxy configuration is invalid")
	if !ExternalMode(protocol) || external["protocol"] != protocol {
		return nil, bad
	}
	if ExternalPacketMode(protocol) {
		return externalPacketTransport(protocol, external)
	}
	if protocol == "openvpn" {
		return externalOpenVPNTransport(external)
	}
	block := protocol
	if protocol == "http-connect" {
		block = "http_connect"
	}
	if protocol == "https-connect" {
		block = "https_connect"
	}
	allowed := map[string]bool{"protocol": true, "expected_public_ip": true, "response_probe": true, block: true, "start_layer": true}
	for key := range external {
		if !allowed[key] {
			return nil, bad
		}
	}
	profile, ok := external[block].(map[string]any)
	if !ok {
		return nil, bad
	}
	keys := map[string]bool{"password": true, "port": true}
	hostKey := "server"
	transportType := protocol
	switch protocol {
	case "shadowsocks":
		keys["server"], keys["method"] = true, true
	case "hysteria2":
		keys["server"], keys["tls_server_name"] = true, true
	case "socks5":
		hostKey, transportType = "host", "socks"
		keys["host"], keys["username"] = true, true
	case "http-connect", "https-connect":
		hostKey, transportType = "host", "http"
		keys["host"], keys["username"] = true, true
		keys["tls_server_name"] = true
	}
	for key := range profile {
		if !keys[key] {
			return nil, bad
		}
	}
	transport := map[string]any{"type": transportType, "tag": "exit", "server": profile[hostKey], "server_port": profile["port"], "password": profile["password"]}
	switch protocol {
	case "shadowsocks":
		transport["method"] = profile["method"]
	case "socks5":
		transport["username"], transport["version"] = profile["username"], "5"
	case "http-connect", "https-connect":
		transport["username"] = profile["username"]
		if protocol == "http-connect" {
			if value, exists := profile["tls_server_name"]; exists && value != "" {
				return nil, bad
			}
		}
	}
	if protocol == "https-connect" || protocol == "hysteria2" {
		transport["tls"] = map[string]any{"enabled": true, "server_name": profile["tls_server_name"]}
	}

	if protocol == "socks5" || protocol == "http-connect" || protocol == "https-connect" {
		for _, key := range []string{"username", "password"} {
			if _, exists := profile[key]; !exists {
				transport[key] = ""
			}
			value, ok := transport[key].(string)
			if !ok || !utf8.ValidString(value) || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
				return nil, bad
			}
		}
	} else if !externalCredential(transport["password"], 4096) {
		return nil, bad
	}
	if !externalPublicIP(stringValue(transport["server"])) {
		return nil, bad
	}
	if protocol == "hysteria2" || protocol == "https-connect" {
		if !externalTLS(transport["tls"]) {
			return nil, bad
		}
	}
	return validateTransport(Exit{Mode: protocol, Transport: transport, External: &ExternalExit{}})
}

func externalCredential(value any, max int) bool {
	s, ok := value.(string)
	return ok && s != "" && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

func externalTLSName(value any) bool {
	s, ok := value.(string)
	if !ok || !utf8.ValidString(s) || len(s) > 253 || s != strings.TrimSpace(s) || strings.HasSuffix(s, ".") {
		return false
	}
	if applexray.ValidNodeHostname(s) {
		return true
	}
	ip, err := netip.ParseAddr(s)
	return err == nil && ip.Zone() == "" && !ip.Is4In6() && ip.IsGlobalUnicast()
}

func externalTLS(value any) bool {
	tls, ok := value.(map[string]any)
	if !ok || tls["enabled"] != true || !externalTLSName(tls["server_name"]) {
		return false
	}
	for key, value := range tls {
		if key == "insecure" {
			if value != false {
				return false
			}
			continue
		}
		if key != "enabled" && key != "server_name" {
			return false
		}
	}
	return true
}

// validateExternalProxyTransport is also used before Start Layer wrapping,
// where the temporary Exit does not carry the external public identity.
func validateExternalProxyCredentials(p map[string]any) error {
	bad := errors.New("proxy credentials require either an exact bounded UTF-8 pair or no authentication")
	userRaw, userPresent := p["username"]
	passwordRaw, passwordPresent := p["password"]
	username, userOK := userRaw.(string)
	password, passwordOK := passwordRaw.(string)
	if userPresent != passwordPresent || userPresent && (!userOK || !passwordOK) || (username == "") != (password == "") {
		return bad
	}
	if username != "" && (!externalCredential(username, 255) || !externalCredential(password, 4096)) {
		return bad
	}
	return nil
}

func validateExternalProxyTransport(p map[string]any, mode string) error {
	bad := errors.New("relay proxy requires exact native transport, paired credentials and verified TLS when selected")
	if !literalServer(p["server"]) || !validPort(p["server_port"]) || validateExternalProxyCredentials(p) != nil {
		return bad
	}
	username, password := stringValue(p["username"]), stringValue(p["password"])
	switch mode {
	case "socks5":
		if p["type"] != "socks" || p["version"] != "5" || (password != "" && !externalCredential(password, 255)) {
			return bad
		}
	case "http-connect":
		if p["type"] != "http" || p["tls"] != nil || strings.Contains(username, ":") {
			return bad
		}
	case "https-connect":
		if p["type"] != "http" || !externalTLS(p["tls"]) || strings.Contains(username, ":") {
			return bad
		}
	default:
		return bad
	}
	return nil
}

func externalTransport(exit Exit) (map[string]any, error) {
	bad := errors.New("external relay requires its exact native transport and public proof address")
	if exit.External == nil || exit.NodeID != "" || !ExternalMode(exit.Mode) || !externalPublicIP(exit.External.ExpectedPublicIP) {
		return nil, bad
	}
	if ExternalPacketMode(exit.Mode) {
		if exit.External.OpenVPN != nil {
			return nil, bad
		}
		return validateExternalPacket(exit)
	}
	if exit.Mode == "openvpn" {
		return validateExternalOpenVPN(exit)
	}
	if exit.External.Packet != nil || exit.External.OpenVPN != nil {
		return nil, bad
	}
	// Reject invalid bytes before JSON copying can replace them with U+FFFD.
	if !externalCredential(exit.Transport["password"], 4096) {
		return nil, bad
	}
	if exit.Mode == "socks5" || exit.Mode == "http-connect" || exit.Mode == "https-connect" {
		if !externalCredential(exit.Transport["username"], 255) {
			return nil, bad
		}
	}
	transport, err := validateTransport(exit)
	if err != nil {
		return nil, bad
	}
	host, _ := transport["server"].(string)
	if !externalPublicIP(host) || exit.External.ResponseProbe.Validate(host) != nil {
		return nil, bad
	}
	allowed := map[string]bool{"type": true, "tag": true, "server": true, "server_port": true, "password": true}
	switch exit.Mode {
	case "shadowsocks":
		allowed["method"] = true
	case "hysteria2":
		allowed["tls"] = true
		if !externalTLS(transport["tls"]) {
			return nil, bad
		}
	case "socks5":
		allowed["username"], allowed["version"] = true, true
	case "http-connect":
		allowed["username"] = true
	case "https-connect":
		allowed["username"], allowed["tls"] = true, true
	}
	for key := range transport {
		if !allowed[key] {
			return nil, bad
		}
	}
	if exit.StartLayer != nil {
		if _, _, err := WrapStartLayer(transport, exit.Mode, exit.StartLayer, ExitStartLayerTag, ""); err != nil {
			return nil, err
		}
	}
	return transport, nil
}
