package mobiletor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"router-vpn/internal/common"
)

const ProfileOutboundTag = "routervpn-tor-exit"
const profileDNS = "routervpn-tor-dns"
const bootstrapDNS = "routervpn-tor-bootstrap"

var profileIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var dnsHostname = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// CompileProfile materializes a frozen mobile Tor selection. A predecessor is
// an already compiled, single-TUN VPN graph, never a local proxy address supplied
// by the UI. Its encrypted final outbound owns Tor's TCP and packet underlay.
// The function opens no socket, stages no secret, and mutates no caller object.
func CompileProfile(profileJSON, sessionID, predecessorJSON string) (string, error) {
	if !profileIdentifier.MatchString(sessionID) {
		return "", errors.New("Tor requires the captured connection session identity")
	}
	profile, err := profileObject(profileJSON, 256*1024)
	if err != nil || profile["node_kind"] != "external" || !profileIdentifier.MatchString(profileString(profile, "id")) {
		return "", errors.New("Tor requires one frozen external node profile")
	}
	for _, key := range []string{"start_layer", "dns_mode", "dns_protocol", "dns_host", "dns_server_name", "dns_path", "ipv6_mode", "mtu_policy"} {
		if value, exists := profile[key]; exists {
			if _, ok := value.(string); !ok {
				return "", errors.New("Tor profile policy requires typed saved values")
			}
		}
	}
	for _, key := range []string{"node_proof_id", "router_api", "api_token"} {
		if value, exists := profile[key]; exists && value != "" && value != nil {
			return "", errors.New("Tor external profile contains another node's control credentials")
		}
	}
	if value := profileString(profile, "start_layer"); value != "" && value != "off" {
		return "", errors.New("Tor external profile cannot replace a captured predecessor Start Layer")
	}
	external, ok := profile["external"].(map[string]any)
	if !ok || external["expected_public_ip"] != nil && external["expected_public_ip"] != "" {
		return "", errors.New("Tor requires dynamic exit proof, with no fixed expected public IP")
	}
	for key := range external {
		if key != "protocol" && key != "expected_public_ip" && key != "tor_bridge" {
			return "", errors.New("Tor external profile contains a second protocol owner")
		}
	}
	bridges := []string{}
	switch external["protocol"] {
	case "tor":
		if external["tor_bridge"] != nil {
			return "", errors.New("Plain Tor cannot discard an imported bridge selection")
		}
	case "tor-bridge":
		block, ok := external["tor_bridge"].(map[string]any)
		if !ok {
			return "", errors.New("Tor bridge configuration is missing")
		}
		for key := range block {
			if key != "transport" && key != "bridges" && key != "socks_port" {
				return "", errors.New("Unknown Tor bridge configuration field")
			}
		}
		data, _ := json.Marshal(block)
		var configuration common.ExternalTorBridgeConfig
		if json.Unmarshal(data, &configuration) != nil || configuration.SocksPort != 0 {
			return "", errors.New("Mobile Tor owns its private SOCKS listener")
		}
		plan, err := NewPlan(configuration)
		if err != nil {
			return "", err
		}
		for _, bridge := range plan.Bridges {
			bridges = append(bridges, bridge.Line)
		}
	default:
		return "", errors.New("Selected external node is not Tor")
	}

	root, tun, predecessor, err := torPredecessor(predecessorJSON)
	if err != nil {
		return "", err
	}
	selected, err := torSelectedDNS(profile)
	if err != nil {
		return "", err
	}
	selected["tag"], selected["detour"] = profileDNS, ProfileOutboundTag
	bootstrap := make(map[string]any, len(selected))
	for key, value := range selected {
		bootstrap[key] = value
	}
	bootstrap["tag"] = bootstrapDNS
	delete(bootstrap, "detour")
	if predecessor != "" {
		bootstrap["detour"] = predecessor
	}
	// Direct Tor uses the user's exact resolver for bridge/broker bootstrap.
	// With a VPN predecessor, Tor bootstrap still uses that captured resolver,
	// through the predecessor. Neither path inherits system DNS or dns.final.
	dns, _ := root["dns"].(map[string]any)
	if dns == nil {
		dns = map[string]any{}
		root["dns"] = dns
	}
	servers, _ := dns["servers"].([]any)
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		if !ok || server["tag"] == profileDNS || server["tag"] == bootstrapDNS {
			return "", errors.New("Tor DNS tags collide with an existing resolver")
		}
	}
	dns["servers"] = append(servers, selected, bootstrap)
	dns["final"] = profileDNS
	// Existing DNS rules belong to the entry runtime; applying them to the Tor
	// exit would send application queries over a different path. Bootstrap and
	// predecessor dialers select their own explicit transport by tag.
	delete(dns, "rules")
	dns["independent_cache"] = true

	tor := map[string]any{"type": "routervpn-tor", "tag": ProfileOutboundTag, "session_id": sessionID, "bridges": bridges}
	if predecessor != "" {
		tor["detour"] = predecessor
	}
	if len(bridges) != 0 {
		tor["domain_resolver"] = map[string]any{"server": bootstrapDNS}
	}
	outbounds, _ := root["outbounds"].([]any)
	root["outbounds"] = append(outbounds, tor)
	route := root["route"].(map[string]any)
	route["final"] = ProfileOutboundTag
	if predecessor == "" {
		route["default_domain_resolver"] = map[string]any{"server": bootstrapDNS}
	}
	if err := applyTorDevicePolicy(root, tun, profile); err != nil {
		return "", err
	}
	data, err := json.Marshal(root)
	if err != nil || len(data) > 4*1024*1024 {
		return "", errors.New("Tor runtime configuration exceeds its native bound")
	}
	return string(data), nil
}

func torPredecessor(source string) (map[string]any, map[string]any, string, error) {
	if source == "" {
		tun := map[string]any{"type": "tun", "tag": "tun-in", "address": []any{"172.29.94.1/30", "fd29:94::1/126"}, "mtu": json.Number("1280"), "auto_route": true, "strict_route": true, "stack": "system"}
		return map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{tun}, "endpoints": []any{}, "outbounds": []any{}, "route": map[string]any{"auto_detect_interface": true, "rules": []any{}}}, tun, "", nil
	}
	failure := errors.New("Tor predecessor must be the complete captured encrypted graph with one strict VPN interface")
	root, err := profileObject(source, 4*1024*1024)
	if err != nil {
		return nil, nil, "", failure
	}
	route, ok := root["route"].(map[string]any)
	if !ok {
		return nil, nil, "", failure
	}
	final := profileString(route, "final")
	if !profileIdentifier.MatchString(final) || final == ProfileOutboundTag {
		return nil, nil, "", failure
	}
	seen := map[string]bool{}
	finalFound := false
	for _, key := range []string{"outbounds", "endpoints"} {
		rows, ok := root[key].([]any)
		if root[key] != nil && !ok {
			return nil, nil, "", failure
		}
		for _, raw := range rows {
			outbound, ok := raw.(map[string]any)
			tag := profileString(outbound, "tag")
			if !ok || !profileIdentifier.MatchString(tag) || seen[tag] || tag == ProfileOutboundTag || outbound["type"] == "routervpn-tor" {
				return nil, nil, "", failure
			}
			seen[tag] = true
			if tag == final {
				switch outbound["type"] {
				case "wireguard", "amneziawg", "routervpn-pq-wireguard", "shadowsocks", "hysteria2", "routervpn-xray", "routervpn-composite", "routervpn-max", "naive", "openvpn-client":
					finalFound = true
				default:
					return nil, nil, "", failure
				}
			}
		}
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) != 1 || !finalFound {
		return nil, nil, "", failure
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true || !profileIdentifier.MatchString(profileString(tun, "tag")) {
		return nil, nil, "", failure
	}
	for _, key := range []string{"route_exclude_address", "route_exclude_address_set", "route_address_set"} {
		if value, exists := tun[key]; exists {
			rows, ok := value.([]any)
			if !ok || len(rows) != 0 {
				return nil, nil, "", failure
			}
		}
	}
	rules, ok := route["rules"].([]any)
	if route["rules"] != nil && !ok {
		return nil, nil, "", failure
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, "", failure
		}
		switch rule["action"] {
		case "reject", "hijack-dns", "sniff":
		case "route", nil:
			if rule["outbound"] != final {
				return nil, nil, "", failure
			}
			rule["outbound"] = ProfileOutboundTag
		default:
			return nil, nil, "", failure
		}
	}
	return root, tun, final, nil
}

func torSelectedDNS(profile map[string]any) (map[string]any, error) {
	mode := profileString(profile, "dns_mode")
	if mode == "" || mode == "rescue" {
		return map[string]any{"type": "https", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": map[string]any{"enabled": true, "server_name": "cloudflare-dns.com"}}, nil
	}
	if mode == "home" {
		return nil, errors.New("A Tor circuit exit cannot reach private Home AdGuard; select the reachable resolver explicitly, or put that home node after Tor")
	}
	protocol := profileString(profile, "dns_protocol")
	switch mode {
	case "custom":
	case "dot", "doh", "doh3":
		protocol = mode
	case "fastest":
		return nil, errors.New("Saved Fastest UDP DNS does not run through a Tor TCP circuit; select TCP, DoT or DoH")
	default:
		return nil, errors.New("Unknown captured Tor DNS mode")
	}
	switch protocol {
	case "dot":
		protocol = "tls"
	case "doh":
		protocol = "https"
	}
	if protocol != "tcp" && protocol != "tls" && protocol != "https" {
		return nil, errors.New("Tor DNS requires the selected resolver's TCP, DoT or DoH endpoint")
	}
	address, err := netip.ParseAddr(profileString(profile, "dns_host"))
	if err != nil || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() {
		return nil, errors.New("Tor DNS requires a reachable literal resolver address; no system bootstrap or private resolver substitution is allowed")
	}
	port, err := profileInteger(profile, "dns_port", 0)
	if err != nil || port < 0 || port > 65535 {
		return nil, errors.New("Invalid captured Tor DNS port")
	}
	if port == 0 {
		port = 53
		if protocol == "tls" {
			port = 853
		}
		if protocol == "https" {
			port = 443
		}
	}
	server := map[string]any{"type": protocol, "server": address.Unmap().String(), "server_port": port}
	if protocol != "tcp" {
		hostname := profileString(profile, "dns_server_name")
		if !dnsHostname.MatchString(hostname) || strings.Contains(hostname, "..") {
			return nil, errors.New("Encrypted Tor DNS requires the captured certificate server name")
		}
		server["tls"] = map[string]any{"enabled": true, "server_name": hostname}
	}
	if protocol == "https" {
		path := profileString(profile, "dns_path")
		if path == "" {
			path = "/dns-query"
		}
		parsed, err := url.ParseRequestURI(path)
		if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || parsed.IsAbs() || parsed.Host != "" || strings.ContainsAny(path, "\x00\r\n") || len(path) > 2048 {
			return nil, errors.New("Invalid captured Tor DoH request path")
		}
		server["path"] = path
	}
	return server, nil
}

func applyTorDevicePolicy(root, tun, profile map[string]any) error {
	route := root["route"].(map[string]any)
	dns := root["dns"].(map[string]any)
	tag := tun["tag"]
	rules := []any{}
	switch profileString(profile, "ipv6_mode") {
	case "", "on", "auto":
	case "off":
		rules = append(rules, map[string]any{"inbound": []any{tag}, "ip_version": 6, "action": "reject"})
		dns["strategy"] = "ipv4_only"
	default:
		return errors.New("Invalid captured Tor IPv6 policy")
	}
	rules = append(rules, map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"network": "udp", "action": "reject"})
	allowLAN := true
	if raw, exists := profile["home_lan_access"]; exists {
		var ok bool
		allowLAN, ok = raw.(bool)
		if !ok {
			return errors.New("Tor LAN access requires an explicit boolean")
		}
	}
	if !allowLAN {
		prefixes := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}
		if raw, exists := profile["home_lan_cidrs"]; exists && raw != nil {
			values, ok := raw.([]any)
			if !ok || len(values) > 32 {
				return errors.New("Invalid captured Tor LAN ranges")
			}
			if len(values) != 0 {
				prefixes = nil
				for _, value := range values {
					text, ok := value.(string)
					prefix, err := netip.ParsePrefix(text)
					if !ok || err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || !prefix.Addr().IsPrivate() || prefix.Bits() == 0 {
						return errors.New("Tor LAN ranges must be canonical private networks")
					}
					last := prefix.Addr()
					if prefix.Addr().Is4() {
						a := prefix.Addr().As4()
						n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
						n |= ^uint32(0) >> prefix.Bits()
						last = netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
					}
					if !last.IsPrivate() || prefix.Addr().Is6() && prefix.Bits() < 7 {
						return errors.New("Tor LAN range extends beyond private addresses")
					}
					prefixes = append(prefixes, text)
				}
			}
		}
		sort.Strings(prefixes)
		rules = append(rules, map[string]any{"inbound": []any{tag}, "ip_cidr": prefixes, "action": "reject"})
		captures, _ := tun["route_address"].([]any)
		captures = append(captures, "0.0.0.0/0", "::/0")
		for _, prefix := range prefixes {
			captures = append(captures, prefix)
		}
		tun["route_address"] = captures
	}
	old, _ := route["rules"].([]any)
	route["rules"] = append(rules, old...)
	switch profileString(profile, "mtu_policy") {
	case "", "auto", "default":
		// A saved effective MTU is history. The current interface owner may
		// optimize it only with current-path measurements after connection.
	case "manual", "fixed":
		mtu, err := profileInteger(profile, "manual_mtu", 0)
		if err != nil || mtu < 1280 || mtu > 9000 {
			return errors.New("Native Tor interface MTU must be 1280..9000")
		}
		tun["mtu"] = mtu
	default:
		return errors.New("Invalid captured Tor interface MTU policy")
	}
	return nil
}

func profileString(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}

func profileInteger(object map[string]any, key string, fallback int) (int, error) {
	value, exists := object[key]
	if !exists {
		return fallback, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, errors.New("integer required")
	}
	return strconv.Atoi(string(number))
}

func profileObject(source string, maximum int) (map[string]any, error) {
	if len(source) == 0 || len(source) > maximum {
		return nil, errors.New("invalid bounded Tor JSON")
	}
	decoder := json.NewDecoder(strings.NewReader(source))
	decoder.UseNumber()
	value, err := profileValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("Tor profile must be an object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("Tor JSON contains trailing data")
	}
	return object, nil
}

func profileValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 48 {
		return nil, errors.New("Tor JSON exceeds nesting bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return nil, errors.New("invalid Tor JSON key")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate Tor JSON field %q", key)
			}
			value, err := profileValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid Tor JSON object")
		}
		return object, nil
	case '[':
		values := []any{}
		for decoder.More() {
			value, err := profileValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid Tor JSON array")
		}
		return values, nil
	default:
		return nil, errors.New("unexpected Tor JSON delimiter")
	}
}
