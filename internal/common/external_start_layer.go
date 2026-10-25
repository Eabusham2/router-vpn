package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

func externalExecutionProtocol(protocol string) bool {
	switch protocol {
	case "wireguard", "amneziawg", "openvpn", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect":
		return true
	}
	return false
}

// The common profile schema remains independent of native engine packages:
// standalone Tor packages also embed it. Runtime adoption separately compiles
// this provision with the selected native transport and verifies every detour.
func (layer *ExternalStartLayer) UnmarshalJSON(raw []byte) error {
	bad := errors.New("external Start Layer requires exact mode, private target and transport fields")
	fields, err := externalLayerJSONObject(raw)
	if err != nil || len(fields) != 3 {
		return bad
	}
	var decoded ExternalStartLayer
	if json.Unmarshal(fields["mode"], &decoded.Mode) != nil || bytes.Equal(fields["mode"], []byte("null")) || json.Unmarshal(fields["api"], &decoded.API) != nil || bytes.Equal(fields["api"], []byte("null")) {
		return bad
	}
	transport, err := externalLayerJSONObject(fields["transport"])
	if err != nil || len(transport) != 6 {
		return bad
	}
	if json.Unmarshal(fields["transport"], &decoded.Transport) != nil {
		return bad
	}
	*layer = decoded
	return nil
}

func externalLayerJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	return externalProfileJSONObject(raw, 16384)
}

func externalProfileJSONObject(raw []byte, limit int) (map[string]json.RawMessage, error) {
	bad := errors.New("external Start Layer object is invalid or contains duplicate fields")
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return nil, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, bad
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, bad
		}
		if _, exists := fields[key]; exists {
			return nil, bad
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, bad
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, bad
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, bad
	}
	return fields, nil
}

// A selected external layer is a private, provisioned transport. Never replace
// it with a Router default, manufacture an endpoint, or silently strip it while
// normalizing an imported profile. This validates the stored schema; the native
// compiler then binds the provision to the actual graph before starting it.
func validateExternalStartLayer(profile *RouterProfile) error {
	if profile.External == nil {
		return errors.New("external Start Layer requires its private node configuration")
	}
	if profile.External.OpenVPNStartLayers != nil {
		return validateExternalOpenVPNStartLayers(profile)
	}
	layer := profile.External.StartLayer
	if profile.StartLayer == StartLayerOff {
		if layer != nil {
			return errors.New("external Start Layer provision does not match the selected Off mode")
		}
		return nil
	}
	if layer == nil || layer.Mode != profile.StartLayer || !externalExecutionProtocol(profile.External.Protocol) {
		return errors.New("external Start Layer requires matching imported mode, private target and transport credentials")
	}
	bad := errors.New("external Start Layer target, cipher or private credentials are invalid")
	api, err := url.Parse(layer.API)
	if err != nil || api == nil || api.Scheme != "http" && api.Scheme != "https" || api.User != nil || api.Opaque != "" || api.RawQuery != "" || api.ForceQuery || api.Fragment != "" || api.RawPath != "" || api.Path != "" && api.Path != "/" {
		return bad
	}
	address, err := netip.ParseAddr(api.Hostname())
	port, portErr := strconv.Atoi(api.Port())
	if err != nil || portErr != nil || port < 1 || port > 65535 || !address.IsPrivate() || address.Is4In6() || address.Zone() != "" {
		return bad
	}
	transport := layer.Transport
	if len(transport) != 6 {
		return bad
	}
	for key := range transport {
		switch key {
		case "type", "tag", "server", "server_port", "method", "password":
		default:
			return bad
		}
	}
	host := externalNodeEndpoint(profile.External)
	if profile.External.Protocol == "openvpn" { host, err = externalOpenVPNProofHost(profile.External); if err != nil { return bad } }
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Is4In6() || ip.Zone() != "" {
		return bad
	}
	if _, err := NormalizeExpectedPublicIP(host); err != nil {
		return bad
	}
	outerHost, ok := transport["server"].(string)
	outer, err := netip.ParseAddr(outerHost)
	if !ok || err != nil || outer != ip || transport["type"] != "shadowsocks" || transport["method"] != StartLayerAES256GCMTransport {
		return bad
	}
	if _, ok := transport["tag"].(string); !ok {
		return bad
	}
	rawPort, err := json.Marshal(transport["server_port"])
	var outerPort int
	if err != nil || json.Unmarshal(rawPort, &outerPort) != nil || outerPort < 1 || outerPort > 65535 {
		return bad
	}
	password, ok := transport["password"].(string)
	if !ok || len(password) == 0 || len(password) > 4096 || !utf8.ValidString(password) {
		return bad
	}
	for _, part := range strings.Split(password, ":") {
		key, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != part {
			return bad
		}
	}
	if profile.StartLayer == StartLayerAES256GCMXOR && outerPort != 8389 {
		return bad
	}
	return nil
}
