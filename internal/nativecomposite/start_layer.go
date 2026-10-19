package nativecomposite

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"

	"router-vpn/internal/applexray"
)

// WithStartLayer wraps an operator-private paired plan. It preserves both
// authenticated legs, changing only same-node service addresses and owned
// detours. The unwrapped transport and AES source remain caller-owned.
func WithStartLayer(plan map[string]any, mode, node, layer, api string, outer map[string]any) (map[string]any, error) {
	if ValidatePlan(plan, mode, node, "") != nil || layer == "" || !Layer(layer) {
		return nil, invalid
	}
	address, err := url.Parse(api)
	if err != nil || address == nil || (address.Scheme != "http" && address.Scheme != "https") || address.User != nil || address.RawQuery != "" || address.Fragment != "" || address.RawPath != "" || address.Path != "" && address.Path != "/" {
		return nil, invalid
	}
	private, err := netip.ParseAddr(address.Hostname())
	if err != nil || !literal(private.String()) || !private.IsPrivate() {
		return nil, invalid
	}
	if address.Port() != "" {
		port, err := strconv.Atoi(address.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, invalid
		}
	}
	result, err := copyMap(plan)
	if err != nil {
		return nil, err
	}
	start, err := copyMap(outer)
	if err != nil {
		return nil, err
	}
	if len(start) != 6 || !fields(start, "type", "tag", "server", "server_port", "method", "password") || start["type"] != "shadowsocks" || start["server"] != result["udp"].(map[string]any)["server"] {
		return nil, invalid
	}
	start["tag"] = StartTag
	if layer == "aes-256-gcm+xor-whitening" {
		start["type"] = "routervpn-aes-xor"
		start["server_port"] = float64(8389)
	}
	tcp := result["tcp"].(map[string]any)
	udp := result["udp"].(map[string]any)
	if mode == "ss-v2ray" {
		tcp["server"] = private.String()
	} else {
		raw, err := object([]byte(text(tcp["config_json"])))
		if err != nil {
			return nil, err
		}
		// ValidatePlan already proved this one exact VLESS endpoint shape.
		remote := raw["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
		remote["address"] = private.String()
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, invalid
		}
		if _, err = applexray.Prepare(mode, encoded); err != nil {
			return nil, invalid
		}
		tcp["config_json"] = string(encoded)
	}
	udp["server"] = private.String()
	tcp["detour"], udp["detour"] = StartTag, StartTag
	result["start"], result["start_layer"] = start, layer
	if err = ValidatePlan(result, mode, node, layer); err != nil {
		return nil, err
	}
	return result, nil
}
