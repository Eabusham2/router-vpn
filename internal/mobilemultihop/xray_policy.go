package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

// ApplyNativeXrayDevicePolicy adds only capture/reject rules to a previously
// compiler-validated single-TUN Xray graph. The final route must belong to its
// unique native encrypted Xray outbound. It retains both Split/MAX transports
// and all DNS/cipher settings; nothing is redirected through a direct bypass.
func ApplyNativeXrayDevicePolicy(config, profile string) (string, error) {
	bad := errors.New("native Xray device policy requires an owned encrypted graph")
	var node, graph map[string]any
	if exactJSON([]byte(profile), &node, 256<<10) != nil || node == nil || exactJSON([]byte(config), &graph, 4<<20) != nil || graph == nil {
		return "", bad
	}
	if kind, ok := node["node_kind"]; ok && kind != "router-vpn" && kind != "" {
		return "", bad
	}
	lan := true
	if value, exists := node["home_lan_access"]; exists {
		var ok bool
		lan, ok = value.(bool)
		if !ok {
			return "", bad
		}
	}
	ipv6 := "on"
	if value, exists := node["ipv6_mode"]; exists {
		var ok bool
		ipv6, ok = value.(string)
		if !ok {
			return "", bad
		}
		ipv6 = strings.ToLower(strings.TrimSpace(ipv6))
	}
	if ipv6 != "" && ipv6 != "on" && ipv6 != "auto" && ipv6 != "off" {
		return "", bad
	}
	route, ok := graph["route"].(map[string]any)
	if !ok {
		return "", bad
	}
	final, ok := route["final"].(string)
	if !ok || !exactID.MatchString(final) {
		return "", bad
	}
	if endpoints, exists := graph["endpoints"]; exists {
		list, ok := endpoints.([]any)
		if !ok || len(list) != 0 {
			return "", bad
		}
	}
	outbounds, ok := graph["outbounds"].([]any)
	if !ok {
		return "", bad
	}
	seen := map[string]bool{}
	native := 0
	for _, raw := range outbounds {
		out, ok := raw.(map[string]any)
		if !ok {
			return "", bad
		}
		tag, ok := out["tag"].(string)
		if !ok || !exactID.MatchString(tag) || seen[tag] {
			return "", bad
		}
		seen[tag] = true
		if out["type"] == "routervpn-xray" {
			native++
			if tag != final {
				return "", bad
			}
			mode, ok := out["mode"].(string)
			if !ok {
				return "", bad
			}
			switch mode {
			case "reality-vision", "reality-pq-vision", "reality-xhttp", "split", "max":
			default:
				return "", bad
			}
			if text, ok := out["config_json"].(string); !ok || text == "" {
				return "", bad
			}
		}
	}
	if native != 1 {
		return "", bad
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return "", bad
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return "", bad
	}
	tag, ok := tun["tag"].(string)
	if !ok || !exactID.MatchString(tag) {
		return "", bad
	}
	if !lan || ipv6 == "off" {
		for _, key := range []string{"route_exclude_address", "route_exclude_address_set", "route_address_set", "route_address"} {
			if raw, exists := tun[key]; exists {
				values, ok := raw.([]any)
				if !ok || len(values) > 0 {
					return "", bad
				}
			}
		}
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return "", bad
	}
	if ipv6 == "off" {
		addresses, ok := tun["address"].([]any)
		if !ok || len(addresses) == 0 {
			return "", bad
		}
		v6 := false
		for _, raw := range addresses {
			text, ok := raw.(string)
			if !ok {
				return "", bad
			}
			prefix, e := netip.ParsePrefix(text)
			if e != nil {
				return "", bad
			}
			if prefix.Addr().Is6() {
				v6 = true
			}
		}
		if !v6 {
			tun["address"] = append(addresses, "fd00:5256:504e:1::1/126")
		}
		if lan {
			rules, ok := route["rules"].([]any)
			if route["rules"] != nil && !ok {
				return "", bad
			}
			route["rules"] = append([]any{map[string]any{"inbound": []string{tag}, "ip_version": 6, "action": "reject"}}, rules...)
			// Capture IPv6 before rejecting it. Removing its routes would leak it onto
			// the underlying network instead of disabling it within the VPN.
			tun["route_address"] = []string{"0.0.0.0/0", "::/0"}
		}
		dns["strategy"] = "ipv4_only"
	}
	normalized, e := json.Marshal(graph)
	if e != nil {
		return "", bad
	}
	node["ipv6_mode"] = ipv6
	profiles, e := json.Marshal(map[string]any{"entry": node, "exit": node})
	if e != nil {
		return "", bad
	}
	return applyLANPolicyFinal(string(normalized), string(profiles), final)
}
