package mobiletor

import (
	"encoding/base64"
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
	return compileProfile(profileJSON, sessionID, predecessorJSON, "", false)
}

// CompileProfileWithPredecessor binds the exact captured Router node to its
// complete native graph. Home DNS belongs to that authenticated private entry;
// the Tor circuit still owns application traffic and its independent exit proof.
func CompileProfileWithPredecessor(profileJSON, sessionID, predecessorJSON, predecessorProfileJSON string) (string, error) {
	return compileProfile(profileJSON, sessionID, predecessorJSON, predecessorProfileJSON, true)
}

// ValidateProfile checks an idle saved node without claiming a runnable graph
// or replacing its unresolved Home default with a public resolver. Connection
// compilation and live proof remain mandatory after the entry is captured.
func ValidateProfile(profileJSON string) error {
	profile, _, err := capturedTorProfile(profileJSON)
	if err != nil {
		return err
	}
	if _, _, err = torSelectedDNS(profile, nil, true); err != nil {
		return err
	}
	root, tun, _, err := torPredecessor("")
	if err != nil {
		return err
	}
	root["dns"] = map[string]any{}
	if err = applyTorDevicePolicy(root, tun, profile); err != nil {
		return err
	}
	_, err = torProfileDigest(profile)
	return err
}

func capturedTorProfile(profileJSON string) (map[string]any, []string, error) {
	profile, err := profileObject(profileJSON, 256*1024)
	if err != nil || profile["node_kind"] != "external" || !profileIdentifier.MatchString(profileString(profile, "id")) {
		return nil, nil, errors.New("Tor requires one frozen external node profile")
	}
	if err := validateTorPaddingPolicy(profile); err != nil {
		return nil, nil, err
	}
	for _, key := range []string{"start_layer", "dns_mode", "dns_protocol", "dns_host", "dns_server_name", "dns_path", "ipv6_mode", "mtu_policy", "multihop_entry_id", "multihop_exit_id", "multihop_entry_mode", "multihop_exit_mode", "multihop_execution"} {
		if value, exists := profile[key]; exists {
			if _, ok := value.(string); !ok {
				return nil, nil, errors.New("Tor profile policy requires typed saved values")
			}
		}
	}
	for _, key := range []string{"node_proof_id", "router_api", "api_token"} {
		if value, exists := profile[key]; exists && value != "" && value != nil {
			return nil, nil, errors.New("Tor external profile contains another node's control credentials")
		}
	}
	if value := profileString(profile, "start_layer"); value != "" && value != "off" {
		return nil, nil, errors.New("Tor external profile cannot replace a captured predecessor Start Layer")
	}
	external, ok := profile["external"].(map[string]any)
	if !ok || external["expected_public_ip"] != nil && external["expected_public_ip"] != "" {
		return nil, nil, errors.New("Tor requires dynamic exit proof, with no fixed expected public IP")
	}
	for key := range external {
		if key != "protocol" && key != "expected_public_ip" && key != "tor_bridge" {
			return nil, nil, errors.New("Tor external profile contains a second protocol owner")
		}
	}
	bridges := []string{}
	switch external["protocol"] {
	case "tor":
		if external["tor_bridge"] != nil {
			return nil, nil, errors.New("Plain Tor cannot discard an imported bridge selection")
		}
	case "tor-bridge":
		block, ok := external["tor_bridge"].(map[string]any)
		if !ok {
			return nil, nil, errors.New("Tor bridge configuration is missing")
		}
		for key := range block {
			if key != "transport" && key != "bridges" && key != "socks_port" {
				return nil, nil, errors.New("Unknown Tor bridge configuration field")
			}
		}
		data, _ := json.Marshal(block)
		var configuration common.ExternalTorBridgeConfig
		if json.Unmarshal(data, &configuration) != nil || configuration.SocksPort != 0 {
			return nil, nil, errors.New("Mobile Tor owns its private SOCKS listener")
		}
		plan, err := NewPlan(configuration)
		if err != nil {
			return nil, nil, err
		}
		for _, bridge := range plan.Bridges {
			bridges = append(bridges, bridge.Line)
		}
	default:
		return nil, nil, errors.New("Selected external node is not Tor")
	}

	return profile, bridges, nil
}

func compileProfile(profileJSON, sessionID, predecessorJSON, predecessorProfileJSON string, captured bool) (string, error) {
	return compileProfileWithEntryProof(profileJSON, sessionID, predecessorJSON, predecessorProfileJSON, captured, nil)
}

func compileProfileWithEntryProof(profileJSON, sessionID, predecessorJSON, predecessorProfileJSON string, captured bool, supplied capturedTorEntryProof) (string, error) {
	if !profileIdentifier.MatchString(sessionID) {
		return "", errors.New("Tor requires the captured connection session identity")
	}
	profile, bridges, err := capturedTorProfile(profileJSON)
	if err != nil {
		return "", err
	}
	var entry map[string]any
	var entryProof capturedTorEntryProof
	if supplied != nil && (!captured || predecessorJSON == "" || predecessorProfileJSON == "" || !supplied.matchesCapturedSource(predecessorProfileJSON, predecessorJSON)) {
		return "", errors.New("Tor predecessor proof authority differs from its captured source")
	}
	if captured {
		throughEntry, exists := profile["multihop_enabled"]
		if exists && throughEntry != true && throughEntry != false {
			return "", errors.New("Tor requires an explicit captured multihop selection")
		}
		if (throughEntry == true) != (predecessorJSON != "") || (throughEntry == true) != (predecessorProfileJSON != "") {
			return "", errors.New("Tor entry graph does not match the captured node selection")
		}
	}
	if predecessorProfileJSON != "" {
		limit := 256 * 1024
		if supplied != nil && !supplied.privateRouter() {
			limit = 4 << 20
		}
		entry, err = profileObject(predecessorProfileJSON, limit)
		if err != nil {
			return "", err
		}
		entryProof = supplied
		if entryProof == nil {
			entryProof, err = NewPredecessorProof(predecessorProfileJSON)
			if err != nil {
				return "", err
			}
		}
		external := profile["external"].(map[string]any)
		if predecessorJSON == "" || profile["multihop_enabled"] != true ||
			profile["multihop_entry_id"] != entry["id"] || profile["multihop_entry_id"] != entryProof.capturedID() || profile["multihop_exit_id"] != profile["id"] ||
			profile["multihop_exit_mode"] != external["protocol"] || entry["id"] == profile["id"] ||
			!profileIdentifier.MatchString(profileString(profile, "multihop_entry_mode")) ||
			(profileString(profile, "multihop_execution") != "" && profileString(profile, "multihop_execution") != "local") {
			return "", errors.New("Tor predecessor belongs to a different captured entry, exit or execution selection")
		}
	}

	root, tun, predecessor, err := torPredecessorCaptured(predecessorJSON, entryProof != nil && !entryProof.privateRouter())
	if err != nil {
		return "", err
	}
	if entryProof != nil {
		exitMTU, err := capturedTorMTUPreferences(profile)
		if err != nil {
			return "", err
		}
		entryPolicy := entryProof.capturedMTU()
		if err := compatibleTorMTUPreferences(exitMTU, entryPolicy); err != nil {
			return "", err
		}
		_, _, entryMTU, err := torMTUInterface(root)
		if err != nil || entryPolicy.jumbo && entryMTU != 9000 || entryPolicy.fixed != 0 && entryMTU != entryPolicy.fixed {
			return "", errors.New("Tor predecessor interface differs from the captured entry MTU policy")
		}
		if entryMTU > 1500 && !entryPolicy.jumbo && entryPolicy.fixed == 0 {
			return "", errors.New("Tor predecessor large interface lacks a captured Jumbo or Fixed policy")
		}
	}
	if err := torFreezeNaiveDNS(root); err != nil {
		return "", err
	}
	selected, home, err := torSelectedDNS(profile, entry, false)
	if err != nil {
		return "", err
	}
	selected["tag"], selected["detour"] = profileDNS, ProfileOutboundTag
	if home {
		if predecessor == "" || entryProof == nil || !entryProof.privateRouter() {
			return "", errors.New("Home AdGuard requires its captured private Router VPN entry")
		}
		selected["detour"] = predecessor
	}
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

	profileDigest, err := torProfileDigest(profile)
	if err != nil {
		return "", err
	}
	tor := map[string]any{"type": "routervpn-tor", "tag": ProfileOutboundTag, "session_id": sessionID, "bridges": bridges, "profile_sha256": profileDigest}
	if predecessor != "" {
		tor["detour"] = predecessor
	}
	if entryProof != nil {
		tor["entry_sha256"] = entryProof.Fingerprint()
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

// Naive always constructs an explicit native resolver, even for a literal
// server. Freeze that selection before adding Tor's DNS transports: otherwise
// a formerly single-server graph becomes ambiguous, or resolves its own first
// connection through the Tor exit that still depends on it.
func torFreezeNaiveDNS(root map[string]any) error {
	var naives []map[string]any
	nodes := map[string]map[string]any{}
	for _, field := range []string{"outbounds", "endpoints"} {
		rows, _ := root[field].([]any)
		for _, raw := range rows {
			node := raw.(map[string]any) // torPredecessor already checked these rows.
			nodes[profileString(node, "tag")] = node
			if node["type"] == "naive" {
				naives = append(naives, node)
			}
		}
	}
	if len(naives) == 0 {
		return nil
	}
	failure := errors.New("Naive Tor entry requires its captured nonrecursive bootstrap DNS")
	dns, ok := root["dns"].(map[string]any)
	if !ok {
		return failure
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) == 0 {
		return failure
	}
	resolvers := map[string]map[string]any{}
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		tag := profileString(server, "tag")
		if !ok || !profileIdentifier.MatchString(tag) || resolvers[tag] != nil {
			return failure
		}
		resolvers[tag] = server
	}
	route := root["route"].(map[string]any)
	implicit := profileString(dns, "final")
	if implicit == "" && len(servers) == 1 {
		implicit = profileString(servers[0].(map[string]any), "tag")
	}
	for index, naive := range naives {
		selection := naive["domain_resolver"]
		if selection == nil {
			selection = route["default_domain_resolver"]
		}
		var query map[string]any
		if selection != nil {
			var err error
			query, err = torResolverSelection(selection)
			if err != nil {
				return failure
			}
		} else {
			// Capture the entry's selected resolver, not the new Tor policy or a
			// machine default. Only this new bootstrap copy uses the Naive
			// lower path; application DNS and its exact saved policy stay intact.
			source := resolvers[implicit]
			if source == nil {
				return failure
			}
			tag := "routervpn-tor-naive-bootstrap-" + strconv.Itoa(index)
			if resolvers[tag] != nil {
				return failure
			}
			bootstrap := make(map[string]any, len(source))
			for key, value := range source {
				bootstrap[key] = value
			}
			bootstrap["tag"] = tag
			delete(bootstrap, "detour")
			if detour, exists := naive["detour"]; exists {
				if text, ok := detour.(string); !ok || !profileIdentifier.MatchString(text) {
					return failure
				}
				bootstrap["detour"] = detour
			}
			resolvers[tag] = bootstrap
			servers = append(servers, bootstrap)
			query = map[string]any{"server": tag}
			strategy := naive["domain_strategy"]
			if strategy == nil {
				strategy = dns["strategy"]
			}
			if strategy != nil {
				if _, ok := strategy.(string); !ok {
					return failure
				}
				query["strategy"] = strategy
			}
		}
		if !torNaiveDNSPath(profileString(query, "server"), profileString(naive, "tag"), resolvers, nodes, route) {
			return failure
		}
		naive["domain_resolver"] = query
	}
	dns["servers"] = servers
	return nil
}

func torResolverSelection(value any) (map[string]any, error) {
	result := map[string]any{}
	switch value := value.(type) {
	case string:
		result["server"] = value
	case map[string]any:
		for key, content := range value {
			result[key] = content
		}
	default:
		return nil, errors.New("invalid captured DNS selection")
	}
	if !profileIdentifier.MatchString(profileString(result, "server")) {
		return nil, errors.New("missing captured DNS selection")
	}
	return result, nil
}

// The bootstrap transport must be numeric and remotely selected. Follow its
// actual named DNS/detour dependencies before any I/O, rejecting unresolved,
// dynamic or recursive paths instead of falling back to dns.final or the OS.
func torNaiveDNSPath(first, blocked string, resolvers, nodes map[string]map[string]any, route map[string]any) bool {
	active := map[string]bool{}
	checked := map[string]bool{}
	var visit func(string, bool) bool
	visit = func(tag string, dns bool) bool {
		if !profileIdentifier.MatchString(tag) || tag == ProfileOutboundTag {
			return false
		}
		key := "outbound:" + tag
		rows := nodes
		if dns {
			key, rows = "dns:"+tag, resolvers
		} else if tag == blocked {
			return false
		}
		value := rows[tag]
		if value == nil || active[key] || len(active) >= 128 {
			return false
		}
		if checked[key] {
			return true
		}
		active[key] = true
		defer delete(active, key)
		if dns {
			switch value["type"] {
			case "udp", "tcp", "tls", "https", "h3", "quic":
			default:
				return false
			}
			address, err := netip.ParseAddr(profileString(value, "server"))
			if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
				return false
			}
			if address.IsLoopback() && profileString(value, "detour") == "" {
				return false
			}
		} else {
			switch value["type"] {
			case "direct", "shadowsocks", "routervpn-aes-xor", "hysteria2", "wireguard", "routervpn-amneziawg", "routervpn-pq", "routervpn-xray", "openvpn-client":
			case "routervpn-composite":
				if !visit(profileString(value, "tcp"), false) || !visit(profileString(value, "udp"), false) {
					return false
				}
			default:
				return false
			}
		}
		if raw, exists := value["detour"]; exists {
			detour, ok := raw.(string)
			if !ok || !visit(detour, false) {
				return false
			}
		}
		selection := value["domain_resolver"]
		if !dns && selection == nil {
			if host := profileString(value, "server"); host != "" {
				if _, err := netip.ParseAddr(host); err != nil {
					selection = route["default_domain_resolver"]
					if selection == nil {
						return false
					}
				}
			}
		}
		if selection != nil {
			query, err := torResolverSelection(selection)
			if err != nil || !visit(profileString(query, "server"), true) {
				return false
			}
		}
		checked[key] = true
		return true
	}
	return visit(first, true)
}

func torPredecessor(source string) (map[string]any, map[string]any, string, error) {
	return torPredecessorCaptured(source, false)
}

func torPredecessorCaptured(source string, ordinaryExternal bool) (map[string]any, map[string]any, string, error) {
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
			if !ok || !profileIdentifier.MatchString(tag) || seen[tag] || tag == ProfileOutboundTag || outbound["type"] == "routervpn-tor" || outbound["type"] == ServerTorClientType {
				return nil, nil, "", failure
			}
			seen[tag] = true
			if tag == final {
				switch outbound["type"] {
				case "socks", "http":
					if !ordinaryExternal || key != "outbounds" {
						return nil, nil, "", failure
					}
					finalFound = true
				case "routervpn-aes-xor":
					if key != "outbounds" || !torAuthenticatedWhitening(outbound) {
						return nil, nil, "", failure
					}
					finalFound = true
				case "wireguard", "routervpn-amneziawg", "routervpn-pq", "shadowsocks", "hysteria2", "routervpn-xray", "routervpn-composite", "naive", "openvpn-client":
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

// A captured AES+XOR entry remains authenticated Shadowsocks 2022. Reject
// plaintext/XOR-only labels before native configuration or secret staging.
func torAuthenticatedWhitening(outbound map[string]any) bool {
	for key := range outbound {
		switch key {
		case "type", "tag", "server", "server_port", "method", "password", "detour":
		default:
			return false
		}
	}
	password := profileString(outbound, "password")
	material, err := base64.StdEncoding.Strict().DecodeString(password)
	validKey := err == nil && len(material) == 32 && base64.StdEncoding.EncodeToString(material) == password
	clear(material)
	if !validKey || outbound["method"] != "2022-blake3-aes-256-gcm" {
		return false
	}
	host := profileString(outbound, "server")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/@\r\n\x00 %") || strings.EqualFold(host, "localhost") {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return false
		}
	} else if !dnsHostname.MatchString(host) {
		return false
	}
	port, err := profileInteger(outbound, "server_port", 0)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	if raw, exists := outbound["detour"]; exists {
		tag, ok := raw.(string)
		if !ok || !profileIdentifier.MatchString(tag) || tag == outbound["tag"] {
			return false
		}
	}
	return true
}

func torSelectedDNS(profile, entry map[string]any, idle bool) (map[string]any, bool, error) {
	mode := profileString(profile, "dns_mode")
	if mode == "" {
		mode = "home"
	}
	if raw := profile["dns_bootstrap"]; raw != nil {
		return nil, false, errors.New("Tor DNS requires its exact literal resolver; an unrelated hostname bootstrap cannot be discarded")
	}
	if mode == "rescue" {
		return map[string]any{"type": "https", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": map[string]any{"enabled": true, "server_name": "cloudflare-dns.com"}}, false, nil
	}
	home := mode == "home"
	host := profileString(profile, "dns_host")
	protocol := profileString(profile, "dns_protocol")
	switch mode {
	case "home":
		if entry != nil && profileString(entry, "node_kind") != "router-vpn" {
			return nil, true, errors.New("Home AdGuard requires its authenticated private Router entry; an ordinary external provider cannot acquire that DNS authority")
		}
		if entry == nil && !idle {
			return nil, true, errors.New("Home AdGuard requires the exact paired Router VPN entry; choose that entry or explicitly select a reachable TCP, DoT or DoH resolver for direct Tor")
		}
		if entry != nil {
			addresses := []string{}
			for _, key := range []string{"adguard_ipv4", "adguard_ipv6"} {
				raw, exists := entry[key]
				if !exists {
					continue
				}
				text, ok := raw.(string)
				if !ok {
					return nil, true, errors.New("Home DNS entry requires typed captured AdGuard addresses")
				}
				if text == "" {
					continue
				}
				address, err := netip.ParseAddr(text)
				if err != nil || address.Zone() != "" || address.Is4In6() || !address.IsPrivate() ||
					(key == "adguard_ipv4" && !address.Is4()) || (key == "adguard_ipv6" && !address.Is6()) {
					return nil, true, errors.New("Home DNS must use the captured entry's private AdGuard address")
				}
				addresses = append(addresses, text)
			}
			if len(addresses) == 0 {
				return nil, true, errors.New("Home DNS entry has no saved private AdGuard address")
			}
			if host == "" {
				host = addresses[0]
			}
			matched := false
			for _, address := range addresses {
				if host == address {
					matched = true
				}
			}
			if !matched {
				return nil, true, errors.New("Home DNS belongs to a different node than the captured Tor entry")
			}
		}
		if protocol == "" {
			protocol = "udp"
		}
	case "custom":
	case "dot", "doh", "doh3":
		protocol = mode
	case "fastest":
		return nil, false, errors.New("Saved Fastest UDP DNS does not run through a Tor TCP circuit; select TCP, DoT or DoH")
	default:
		return nil, false, errors.New("Unknown captured Tor DNS mode")
	}
	switch protocol {
	case "dot":
		protocol = "tls"
	case "doh":
		protocol = "https"
	case "doh3":
		protocol = "h3"
	}
	if protocol != "tcp" && protocol != "tls" && protocol != "https" && !(home && (protocol == "udp" || protocol == "h3")) {
		return nil, home, errors.New("Tor DNS requires the selected resolver's TCP, DoT or DoH endpoint; private Home DNS uses its captured entry transport")
	}
	if host != "" || !home || !idle {
		address, err := netip.ParseAddr(host)
		if err != nil || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsPrivate() != home {
			return nil, home, errors.New("Tor DNS requires the exact reachable literal resolver; no system lookup or private/public resolver substitution is allowed")
		}
		host = address.String()
	}
	port, err := profileInteger(profile, "dns_port", 0)
	if err != nil || port < 0 || port > 65535 {
		return nil, home, errors.New("Invalid captured Tor DNS port")
	}
	if port == 0 {
		port = 53
		if protocol == "tls" {
			port = 853
		}
		if protocol == "https" || protocol == "h3" {
			port = 443
		}
	}
	server := map[string]any{"type": protocol, "server": host, "server_port": port}
	if protocol == "tls" || protocol == "https" || protocol == "h3" {
		hostname := profileString(profile, "dns_server_name")
		if !dnsHostname.MatchString(hostname) || strings.Contains(hostname, "..") {
			return nil, home, errors.New("Encrypted Tor DNS requires the captured certificate server name")
		}
		server["tls"] = map[string]any{"enabled": true, "server_name": hostname}
	}
	if protocol == "https" || protocol == "h3" {
		path := profileString(profile, "dns_path")
		if path == "" {
			path = "/dns-query"
		}
		parsed, err := url.ParseRequestURI(path)
		if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || parsed.IsAbs() || parsed.Host != "" || strings.ContainsAny(path, "\x00\r\n") || len(path) > 2048 {
			return nil, home, errors.New("Invalid captured Tor DoH request path")
		}
		server["path"] = path
	}
	return server, home, nil
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
	mtu, err := capturedTorMTUPreferences(profile)
	if err != nil {
		return err
	}
	// Auto/Default retain the compiled baseline, including a captured entry's
	// single interface. Historical effective_mtu is never current evidence.
	if mtu.fixed != 0 {
		tun["mtu"] = mtu.fixed
	}
	if mtu.jumbo {
		// TCP is segmented by the native stack and each encrypted underlay.
		// This virtual capacity is not a 9000-byte packet-path measurement.
		tun["mtu"] = 9000
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
