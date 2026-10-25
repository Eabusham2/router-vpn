package multihoprelay

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"router-vpn/internal/applexray"
	"router-vpn/internal/mobilepq"
	"router-vpn/internal/nativeopenvpn"
	"strconv"
	"strings"
)

const ExitStartLayerTag = "routervpn-exit-start-layer"

// StartLayer is operator-private paired configuration. Requests only name its
// mode; they never supply this transport, authentication or a remote script.
type StartLayer struct {
	Mode      string         `json:"mode"`
	API       string         `json:"api"`
	Transport map[string]any `json:"transport"`
}

// UnmarshalJSON preserves the complete private layer contract. Unknown or
// duplicate members must not disappear during typed import before the captured
// graph is validated. Pointer absence still means no selected layer.
func (layer *StartLayer) UnmarshalJSON(raw []byte) error {
	bad := errors.New("Start Layer requires its exact private mode, API and transport object")
	if len(raw) > 16384 {
		return bad
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 3 {
		return bad
	}
	if _, ok := object["mode"].(string); !ok {
		return bad
	}
	if _, ok := object["api"].(string); !ok {
		return bad
	}
	if transport, ok := object["transport"].(map[string]any); !ok || len(transport) == 0 {
		return bad
	}
	type startLayerJSON StartLayer
	var decoded startLayerJSON
	if json.Unmarshal(raw, &decoded) != nil {
		return bad
	}
	*layer = StartLayer(decoded)
	return nil
}

func LayerMode(layer *StartLayer) string {
	if layer == nil {
		return ""
	}
	return layer.Mode
}
func ValidLayerMode(mode string) bool {
	return mode == "aes-256-gcm" || mode == "aes-256-gcm+xor-whitening"
}

// WrapStartLayer returns fresh maps, preserving the exact validated native
// transport. Only its remote service address and explicitly owned detour change.
// On a phone the outer transport itself goes through the captured entry; on a
// private relay it owns the physical exit path. DNS always remains on the inner.
func WrapStartLayer(transport map[string]any, mode string, layer *StartLayer, tag, via string) (map[string]any, map[string]any, error) {
	return wrapStartLayer(transport, mode, layer, tag, via, false)
}

// WrapStartLayerForSelection proves the complete same-node outer layer before
// an explicit owner resolves that node. It opens nothing; runtime callers must
// use WrapStartLayer again after capturing a literal address.
func WrapStartLayerForSelection(transport map[string]any, mode string, layer *StartLayer, tag, via string) (map[string]any, map[string]any, error) {
	return wrapStartLayer(transport, mode, layer, tag, via, true)
}

func wrapStartLayer(transport map[string]any, mode string, layer *StartLayer, tag, via string, allowHostname bool) (map[string]any, map[string]any, error) {
	bad := errors.New("invalid captured exit Start Layer ownership")
	if layer == nil || !ValidLayerMode(layer.Mode) || !ident.MatchString(tag) || (via != "" && !ident.MatchString(via)) || tag == via {
		return nil, nil, bad
	}
	api, e := url.Parse(layer.API)
	if e != nil || api == nil || (api.Scheme != "http" && api.Scheme != "https") || api.User != nil || api.RawQuery != "" || api.Fragment != "" || api.RawPath != "" || (api.Path != "" && api.Path != "/") {
		return nil, nil, bad
	}
	address, e := netip.ParseAddr(api.Hostname())
	port, pe := strconv.Atoi(api.Port())
	if e != nil || pe != nil || port < 1 || port > 65535 || address.Is4In6() || address.Zone() != "" || !address.IsPrivate() || !literalServer(address.String()) {
		return nil, nil, bad
	}
	if mode == "socks5" || mode == "http-connect" || mode == "https-connect" {
		if err := validateExternalProxyCredentials(transport); err != nil {
			return nil, nil, err
		}
	}
	var inner map[string]any
	if mode == "openvpn" {
		// Validate original bytes before JSON copying, and retain the original
		// inline compiler's 256 KiB source / 512 KiB emitted endpoint bound.
		inner, e = nativeopenvpn.ValidateEndpoint(transport)
	} else {
		inner, e = copyMap(transport)
	}
	if e != nil || len(inner) == 0 {
		return nil, nil, bad
	}
	rawTag, ok := inner["tag"].(string)
	if !ok || !ident.MatchString(rawTag) || rawTag == tag {
		return nil, nil, bad
	}
	checked := inner
	if mode != "openvpn" {
		checked, e = copyMap(inner)
	}
	if e != nil {
		return nil, nil, bad
	}
	// Mobile packet endpoints explicitly say system=false. Validate that value
	// rather than silently discarding a second-OS-interface request.
	if value, exists := checked["system"]; exists && mode != "openvpn" {
		if value != false {
			return nil, nil, bad
		}
		delete(checked, "system")
	}
	if value, exists := checked["listen_port"]; exists {
		if value != float64(0) {
			return nil, nil, bad
		}
		delete(checked, "listen_port")
	}
	if mode == "openvpn" {
		// The entire original native endpoint was validated above.
	} else {
		_, e = validateTransportForSelection(Exit{Mode: mode, NodeID: stringValue(checked["node_id"]), DNS: address.String(), Transport: checked}, allowHostname)
	}
	if e != nil {
		return nil, nil, bad
	}
	var host string
	if mode == "openvpn" {
		host, e = nativeopenvpn.SameRemoteHost(inner)
		if e != nil {
			return nil, nil, bad
		}
	} else if PacketMode(mode) {
		host, _ = inner["peers"].([]any)[0].(map[string]any)["address"].(string)
	} else if applexray.SingleTransportMode(mode) {
		raw, _ := inner["config_json"].(string)
		prepare := applexray.Prepare
		if allowHostname {
			prepare = applexray.PrepareForSelection
		}
		plan, err := prepare(mode, []byte(raw))
		if err != nil {
			return nil, nil, bad
		}
		host = plan.ServerHost
	} else {
		host, _ = inner["server"].(string)
	}
	outer, e := copyMap(layer.Transport)
	if e != nil || len(outer) != 6 {
		return nil, nil, bad
	}
	for key := range outer {
		switch key {
		case "type", "tag", "server", "server_port", "method", "password":
		default:
			return nil, nil, bad
		}
	}
	if outer["type"] != "shadowsocks" || outer["method"] != "2022-blake3-aes-256-gcm" || !validPort(outer["server_port"]) {
		return nil, nil, bad
	}
	left, e1 := netip.ParseAddr(host)
	right, e2 := netip.ParseAddr(stringValue(outer["server"]))
	sameLiteral := e1 == nil && e2 == nil && left == right && literalServer(host) && literalServer(outer["server"])
	sameHostname := allowHostname && host == stringValue(outer["server"]) && applexray.ValidNodeHostname(host)
	if !sameLiteral && !sameHostname {
		return nil, nil, errors.New("exit Start Layer belongs to a different paired server")
	}
	password, ok := outer["password"].(string)
	if !ok || password == "" || len(password) > 4096 {
		return nil, nil, bad
	}
	for _, part := range strings.Split(password, ":") {
		key, e := base64.StdEncoding.Strict().DecodeString(part)
		if e != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != part {
			return nil, nil, bad
		}
	}
	if mode == "openvpn" {
		if remotes, exists := inner["servers"].([]any); exists {
			for _, raw := range remotes {
				raw.(map[string]any)["server"] = address.String()
			}
		} else {
			inner["server"] = address.String()
		}
	} else if PacketMode(mode) {
		inner["peers"].([]any)[0].(map[string]any)["address"] = address.String()
		if mobilepq.IsMode(mode) {
			pq := inner["pq"].(map[string]any)
			_, port, err := net.SplitHostPort(pq["endpoint"].(string))
			if err != nil {
				return nil, nil, bad
			}
			pq["endpoint"] = net.JoinHostPort(address.String(), port)
		}
	} else if applexray.SingleTransportMode(mode) {
		parsed, e := applexray.Object([]byte(inner["config_json"].(string)))
		if e != nil {
			return nil, nil, bad
		}
		parsed["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = address.String()
		encoded, e := json.Marshal(parsed)
		if e != nil {
			return nil, nil, bad
		}
		if _, e = applexray.Prepare(mode, encoded); e != nil {
			return nil, nil, bad
		}
		inner["config_json"] = string(encoded)
	} else {
		inner["server"] = address.String()
	}
	inner["detour"] = tag
	outer["tag"] = tag
	if via != "" {
		outer["detour"] = via
	}
	if layer.Mode == "aes-256-gcm+xor-whitening" {
		outer["type"] = "routervpn-aes-xor"
		outer["server_port"] = 8389
	}
	return inner, outer, nil
}
func stringValue(value any) string { text, _ := value.(string); return text }
