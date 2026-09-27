package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
)

// ApplyLANPolicy operates on a fresh, owned multihop graph. It captures both
// nodes' LAN policy, not only the currently displayed exit. Control/proof and
// native DNS dialers retain their owned paths; ordinary TUN traffic cannot use
// those internal dialers as a general private-LAN bypass.
func ApplyLANPolicy(config, profiles string) (string, error) {
	var pair struct {
		Entry map[string]any `json:"entry"`
		Exit  map[string]any `json:"exit"`
	}
	if exactJSON([]byte(profiles), &pair, 256*1024) != nil || pair.Entry == nil || pair.Exit == nil {
		return "", errors.New("two frozen node profiles are required for multihop LAN policy")
	}
	privateRanges := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}
	blocked := map[string]bool{}
	for _, profile := range []map[string]any{pair.Entry, pair.Exit} {
		allow := true
		if value, exists := profile["home_lan_access"]; exists {
			var valid bool
			allow, valid = value.(bool)
			if !valid {
				return "", errors.New("LAN access must be an explicit boolean")
			}
		}
		if allow {
			continue
		}
		var ranges []any
		if value, exists := profile["home_lan_cidrs"]; exists && value != nil {
			var valid bool
			ranges, valid = value.([]any)
			if !valid || len(ranges) > 32 {
				return "", errors.New("invalid frozen home LAN ranges")
			}
		}
		if len(ranges) == 0 {
			for _, prefix := range privateRanges {
				blocked[prefix.String()] = true
			}
			continue
		}
		for _, value := range ranges {
			text, valid := value.(string)
			if !valid {
				return "", errors.New("home LAN CIDRs must be strings")
			}
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
				return "", errors.New("home LAN must be a canonical private network")
			}
			contained := false
			for _, allowed := range privateRanges {
				if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
					contained = true
				}
			}
			if !contained {
				return "", errors.New("home LAN ranges cannot replace public, default or link-local routing")
			}
			blocked[prefix.String()] = true
		}
	}
	if len(blocked) == 0 {
		return config, nil
	}
	var root map[string]any
	if exactJSON([]byte(config), &root, 4*1024*1024) != nil || root == nil {
		return "", errors.New("invalid bounded multihop graph")
	}
	route, valid := root["route"].(map[string]any)
	if !valid || route["final"] != "proxy" {
		return "", errors.New("LAN policy requires the owned encrypted exit route")
	}
	inbound, valid := root["inbounds"].([]any)
	if !valid {
		return "", errors.New("multihop TUN is missing")
	}
	var tun map[string]any
	for _, raw := range inbound {
		value, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid multihop inbound")
		}
		if value["type"] == "tun" {
			if tun != nil {
				return "", errors.New("multiple TUN owners")
			}
			tun = value
		}
	}
	if tun == nil || tun["auto_route"] != true || tun["strict_route"] != true {
		return "", errors.New("LAN-Off requires full-device strict TUN routes")
	}
	tag, valid := tun["tag"].(string)
	if !valid || !exactID.MatchString(tag) {
		return "", errors.New("the TUN must have one valid ownership tag")
	}
	for _, key := range []string{"route_exclude_address", "route_exclude_address_set", "route_address_set"} {
		if value, exists := tun[key]; exists {
			if values, ok := value.([]any); !ok || len(values) != 0 {
				return "", errors.New("LAN-Off cannot preserve a bypass outside the owned TUN")
			}
		}
	}
	if value, exists := tun["route_address"]; exists {
		if list, ok := value.([]any); !ok || len(list) != 0 {
			return "", errors.New("LAN-Off must be compiled from the original full-device graph, not a saved split route")
		}
	}
	networks := make([]string, 0, len(blocked))
	for prefix := range blocked {
		networks = append(networks, prefix)
	}
	sort.Strings(networks)
	api, ok := pair.Exit["router_api"].(string)
	if !ok {
		return "", errors.New("selected exit control identity is missing")
	}
	endpoint, err := privateAPI(api)
	if err != nil {
		return "", err
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil {
		return "", errors.New("invalid selected control address")
	}
	address = address.Unmap()
	bits := 128
	if address.Is4() {
		bits = 32
	}
	host := netip.PrefixFrom(address, bits).String()
	port, _ := strconv.Atoi(endpoint.Port())
	rules, ok := route["rules"].([]any)
	if route["rules"] != nil && !ok {
		return "", errors.New("invalid owned route rules")
	}
	// Only this exact selected control socket is allowed to ordinary application
	// traffic. No SSH, admin subnet, general private SOCKS, or broad private range
	// is exempted. DNS queries use the already selected, exit-routed DNS policy.
	policy := []any{}
	if pair.Entry["ipv6_mode"] == "off" || pair.Exit["ipv6_mode"] == "off" {
		policy = append(policy, map[string]any{"inbound": []string{tag}, "ip_version": 6, "action": "reject"})
	}
	policy = append(policy, []any{
		map[string]any{"inbound": []string{tag}, "protocol": "dns", "action": "hijack-dns"},
		map[string]any{"inbound": []string{tag}, "network": "tcp", "ip_cidr": []string{host}, "port": port, "action": "route", "outbound": "proxy"},
		map[string]any{"inbound": []string{tag}, "ip_cidr": networks, "action": "reject"},
	}...)
	// Explicit included routes prevent a more-specific physical LAN route from
	// winning over the TUN default on either operating system. Keep BOTH defaults;
	// IPv6-Off is separately enforced by the existing graph's reject rule.
	captures := append([]string{"0.0.0.0/0", "::/0"}, networks...)
	captures = append(captures, host)
	tun["route_address"] = captures
	route["rules"] = append(policy, rules...)
	body, err := json.Marshal(root)
	if err != nil || len(body) > 4*1024*1024 {
		return "", errors.New("compiled LAN policy exceeds safety bound")
	}
	return string(body), nil
}
