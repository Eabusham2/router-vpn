package mobilemultihop

import (
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// A selected DNS hostname needs an explicit bootstrap transport and exact
// native query options. Its transport uses a literal address through the same
// owned exit. No system/default resolver or replacement public DNS is inferred.
type externalDNSBootstrap struct {
	Server map[string]any `json:"server"`
	Query  map[string]any `json:"query"`
}

type externalDNSMetadata struct {
	mode, protocol, host, serverName, path, detour, bootstrapSHA256 string
	port                                                            int
	migrated                                                        bool
}

func externalSelectedDNS(selection externalPolicyCapture, ipv6 string, udp bool) (map[string]any, externalDNSMetadata, error) {
	var result externalDNSMetadata
	profile := selection.Profile
	values := map[string]string{}
	for _, key := range []string{"dns_mode", "dns_protocol", "dns_host", "dns_server_name", "dns_path", "fastest_dns_host"} {
		value, err := externalOptionalString(profile, key)
		if err != nil {
			return nil, result, err
		}
		values[key] = value
	}
	port := 0
	if raw, exists := profile["dns_port"]; exists {
		number, ok := raw.(float64)
		if !ok || number < 0 || number > 65535 || float64(int(number)) != number {
			return nil, result, errors.New("external DNS port must be an integer from 1 through 65535, or zero for the selected protocol default")
		}
		port = int(number)
	}
	result = externalDNSMetadata{
		mode: strings.ToLower(values["dns_mode"]), protocol: strings.ToLower(values["dns_protocol"]),
		host: values["dns_host"], port: port, serverName: values["dns_server_name"], path: values["dns_path"], detour: ExternalFinalTag,
	}
	if result.mode == "" {
		// Missing preferences retain the product's Home AdGuard default.
		// A direct external node must choose a reachable resolver explicitly;
		// it must never become a silent migration to a public DNS preset.
		result.mode = "home"
	}
	switch result.mode {
	case "rescue":
		// Rescue names one preset. Leftover custom fields never silently change
		// its certificate identity, path or port.
		result.protocol, result.host, result.port = "https", "1.1.1.1", 443
		result.serverName, result.path = "cloudflare-dns.com", "/dns-query"
	case "home":
		entry := selection.Entry
		kind, _ := entry["node_kind"].(string)
		node, _ := entry["node_proof_id"].(string)
		api, _ := entry["router_api"].(string)
		token, _ := entry["api_token"].(string)
		if entry == nil || selection.EntryTag == "" || kind != "" && kind != "router-vpn" || !proofID.MatchString(node) || len(token) == 0 || len(token) > 4096 {
			return nil, result, errors.New("Home AdGuard DNS requires the exact captured Router VPN entry and its private node-proof owner; choose that paired entry or explicitly select a reachable DNS policy for a direct external connection")
		}
		if _, err := privateAPI(api); err != nil {
			return nil, result, errors.New("Home DNS entry has no exact private proof endpoint")
		}
		addresses := []string{}
		for _, key := range []string{"adguard_ipv4", "adguard_ipv6"} {
			text, err := externalOptionalString(entry, key)
			if err != nil {
				return nil, result, err
			}
			if text == "" {
				continue
			}
			address, err := netip.ParseAddr(text)
			if err != nil || address.Is4In6() || address.Zone() != "" || !address.IsPrivate() || key == "adguard_ipv4" && !address.Is4() || key == "adguard_ipv6" && !address.Is6() {
				return nil, result, errors.New("Home DNS must use an explicit captured private AdGuard address")
			}
			addresses = append(addresses, text)
		}
		if len(addresses) == 0 {
			return nil, result, errors.New("Home DNS entry has no saved AdGuard address")
		}
		if result.host == "" {
			result.host = addresses[0]
		}
		matched := false
		for _, host := range addresses {
			if result.host == host {
				matched = true
			}
		}
		if !matched {
			return nil, result, errors.New("selected Home DNS belongs to a different node than the captured entry")
		}
		if result.protocol == "" {
			result.protocol = "udp"
		}
		result.detour = selection.EntryTag
		// This internal DNS request is carried only by the entry. A TCP-only
		// final exit does not constrain the private entry's own UDP DNS path.
		udp = true
	case "fastest":
		result.host, result.protocol, result.port = values["fastest_dns_host"], "udp", 53
		result.serverName, result.path = "", ""
		if result.host == "" || !externalFastestSelection(profile, result.host) {
			return nil, result, errors.New("Fastest DNS has no captured successful resolver selection")
		}
	case "dot":
		result.protocol = "tls"
	case "doh":
		result.protocol = "https"
	case "doh3":
		result.protocol = "h3"
	case "custom":
		if result.protocol == "" {
			return nil, result, errors.New("Custom DNS requires its explicit selected transport")
		}
	default:
		return nil, result, errors.New("unsupported external DNS policy")
	}
	switch result.protocol {
	case "dot":
		result.protocol = "tls"
	case "doh":
		result.protocol = "https"
	case "doh3":
		result.protocol = "h3"
	}
	if result.host == "" {
		return nil, result, errors.New("the selected external DNS policy has no resolver address")
	}
	if result.port == 0 {
		switch result.protocol {
		case "tls":
			result.port = 853
		case "https", "h3":
			result.port = 443
		default:
			result.port = 53
		}
	}
	if result.protocol == "https" || result.protocol == "h3" {
		if result.path == "" {
			result.path = "/dns-query"
		}
	} else {
		result.path = ""
	}
	if result.protocol == "udp" || result.protocol == "tcp" {
		result.serverName = ""
	}
	server := map[string]any{"type": result.protocol, "tag": ExternalDNSTag, "server": result.host, "server_port": result.port, "detour": result.detour}
	if result.protocol == "tls" || result.protocol == "https" || result.protocol == "h3" {
		server["tls"] = map[string]any{"enabled": true, "server_name": result.serverName}
		if result.path != "" {
			server["path"] = result.path
		}
	}
	// Normalize only numeric representation before applying the same validator
	// to generated and caller-supplied bootstrap transports.
	encoded, _ := json.Marshal(server)
	_ = json.Unmarshal(encoded, &server)
	if err := externalDNSTransport(server, result.detour, false, udp); err != nil {
		return nil, result, err
	}
	servers := []any{server}
	_, literalErr := netip.ParseAddr(result.host)
	if literalErr != nil {
		bootstrap := selection.DNSBootstrap
		if bootstrap == nil || bootstrap.Server == nil || bootstrap.Query == nil {
			return nil, result, errors.New("selected DNS hostname requires an explicit owned bootstrap transport and query options")
		}
		if bootstrap.Server["tag"] != "external-dns-bootstrap" {
			return nil, result, errors.New("DNS bootstrap tag is not owned by this external selection")
		}
		if err := externalDNSTransport(bootstrap.Server, result.detour, true, udp); err != nil {
			return nil, result, err
		}
		if err := externalDNSQuery(bootstrap.Query, "external-dns-bootstrap"); err != nil {
			return nil, result, err
		}
		server["domain_resolver"] = bootstrap.Query
		servers = append(servers, bootstrap.Server)
		captured, _ := json.Marshal(map[string]any{"server": bootstrap.Server, "query": bootstrap.Query})
		result.bootstrapSHA256 = externalDigest(captured)
	} else if selection.DNSBootstrap != nil {
		return nil, result, errors.New("a literal selected DNS server cannot adopt an unused bootstrap owner")
	}
	dns := map[string]any{"servers": servers, "final": ExternalDNSTag}
	if ipv6 == "off" {
		dns["strategy"] = "ipv4_only"
	}
	return dns, result, nil
}

// A configured hostname alone is not a successful Fastest selection. Keep the
// exact saved winning sample; a separate fresh native proof is still required
// before UP because an earlier benchmark does not establish current reachability.
func externalFastestSelection(profile map[string]any, host string) bool {
	positive := func(value any) bool {
		n, ok := value.(float64)
		return ok && n > 0 && !math.IsNaN(n) && !math.IsInf(n, 0)
	}
	if raw, exists := profile["dns_results"]; exists {
		results, ok := raw.([]any)
		if !ok || len(results) > 128 {
			return false
		}
		if len(results) != 0 {
			for _, raw := range results {
				result, ok := raw.(map[string]any)
				if ok && result["address"] == host && result["working"] == true && positive(result["latency_ms"]) {
					return true
				}
			}
			return false
		}
	}
	return positive(profile["fastest_dns_latency_ms"])
}

func externalDNSTransport(server map[string]any, detour string, literalOnly, udp bool) error {
	bad := errors.New("external DNS transport must retain its exact selected address, TLS identity and owned route")
	protocol, ok := server["type"].(string)
	if !ok || server["detour"] != detour || !externalPort(server["server_port"]) {
		return bad
	}
	tag, ok := server["tag"].(string)
	if !ok || !exactID.MatchString(tag) {
		return bad
	}
	host, ok := server["server"].(string)
	if !ok {
		return bad
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsLoopback() || address.String() != host {
			return bad
		}
	} else if literalOnly || !externalDNSHostname(host) {
		return bad
	}
	allowed := map[string]bool{"type": true, "tag": true, "server": true, "server_port": true, "detour": true}
	switch protocol {
	case "udp":
		if !udp {
			return errors.New("selected UDP DNS cannot traverse the captured TCP-only exit path")
		}
	case "tcp":
	case "tls", "https", "h3":
		if protocol == "h3" && !udp {
			return errors.New("selected DoH3 cannot traverse the captured TCP-only exit path")
		}
		allowed["tls"] = true
		if !externalTLS(server["tls"]) {
			return bad
		}
		if protocol == "https" || protocol == "h3" {
			allowed["path"] = true
			path, ok := server["path"].(string)
			if !ok || len(path) == 0 || len(path) > 2048 || strings.ContainsAny(path, "\x00\r\n\\") {
				return bad
			}
			parsed, err := url.ParseRequestURI(path)
			if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
				return bad
			}
		}
	default:
		return bad
	}
	for key := range server {
		if !allowed[key] {
			return bad
		}
	}
	return nil
}

func externalDNSQuery(query map[string]any, server string) error {
	bad := errors.New("external DNS bootstrap query options lost their exact transport owner")
	if query["server"] != server {
		return bad
	}
	for key, raw := range query {
		switch key {
		case "server":
		case "strategy":
			text, ok := raw.(string)
			if !ok {
				return bad
			}
			switch text {
			case "", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
			default:
				return bad
			}
		case "timeout":
			text, ok := raw.(string)
			if !ok {
				return bad
			}
			duration, err := time.ParseDuration(text)
			if err != nil || duration <= 0 || duration > time.Minute {
				return bad
			}
		case "disable_cache", "disable_optimistic_cache":
			if _, ok := raw.(bool); !ok {
				return bad
			}
		case "rewrite_ttl":
			n, ok := raw.(float64)
			if !ok || n < 0 || n > 4294967295 || n != float64(uint32(n)) {
				return bad
			}
		case "client_subnet":
			text, ok := raw.(string)
			if !ok {
				return bad
			}
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
				return bad
			}
		default:
			return bad
		}
	}
	return nil
}

func externalDNSHostname(host string) bool {
	if host == "" || len(host) > 253 || host != strings.TrimSpace(host) || strings.HasSuffix(host, ".") || strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

func externalTLSName(name string) bool {
	if address, err := netip.ParseAddr(name); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.IsGlobalUnicast() && !address.IsLoopback() && address.String() == name
	}
	return externalDNSHostname(name)
}
