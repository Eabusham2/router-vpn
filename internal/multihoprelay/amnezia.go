package multihoprelay

import (
	"encoding/json"
	"errors"
	"net/netip"
	"router-vpn/internal/awgpolicy"
)

// Validate the data-only server endpoint before it reaches the engine checker.
// In particular, no foreign listener, host path, bind or peer route may be hidden
// inside the new endpoint type. The pinned native engine validates again.
func validateAmnezia(endpoint, peer map[string]any) error {
	bad := errors.New("invalid or unowned server AmneziaWG endpoint")
	raw, err := json.Marshal(endpoint["amnezia"])
	if err != nil {
		return bad
	}
	var parameters map[string]string
	if json.Unmarshal(raw, &parameters) != nil {
		return bad
	}
	if _, err = awgpolicy.ParametersUAPI(parameters); err != nil {
		return bad
	}
	mtu, ok := endpoint["mtu"].(float64)
	if !ok || mtu < 1280 || mtu > 9000 || mtu != float64(int(mtu)) {
		return bad
	}
	allowed := map[string]bool{"address": true, "port": true, "public_key": true, "pre_shared_key": true, "allowed_ips": true, "persistent_keepalive_interval": true}
	for key := range peer {
		if !allowed[key] {
			return bad
		}
	}
	if psk, exists := peer["pre_shared_key"]; exists && !key32(psk) {
		return bad
	}
	if value, exists := peer["persistent_keepalive_interval"]; exists {
		n, ok := value.(float64)
		if !ok || n < 0 || n > 65535 || n != float64(int(n)) {
			return bad
		}
	}
	addresses, ok := endpoint["address"].([]any)
	if !ok || len(addresses) < 1 || len(addresses) > 2 {
		return bad
	}
	networks, ok := peer["allowed_ips"].([]any)
	if !ok || len(networks) < 1 || len(networks) > 2 {
		return bad
	}
	routes := map[string]bool{}
	for _, raw := range networks {
		value, ok := raw.(string)
		if !ok || (value != "0.0.0.0/0" && value != "::/0") || routes[value] {
			return bad
		}
		routes[value] = true
	}
	families := map[bool]bool{}
	for _, raw := range addresses {
		text, ok := raw.(string)
		if !ok {
			return bad
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.Addr().Is4In6() || !literalServer(prefix.Addr().String()) || families[prefix.Addr().Is4()] {
			return bad
		}
		families[prefix.Addr().Is4()] = true
		route := "::/0"
		if prefix.Addr().Is4() {
			route = "0.0.0.0/0"
		}
		if !routes[route] {
			return bad
		}
	}
	return nil
}
