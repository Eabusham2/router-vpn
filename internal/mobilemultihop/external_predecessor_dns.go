package mobilemultihop

import (
	"errors"
	"net/netip"
	"strconv"
)

// Capture every implicit resolver before dns.final changes to the external
// exit. Naive requires an explicit resolver even with a literal server; its
// bootstrap copy retains the selected endpoint and TLS policy but follows the
// already-selected lower encrypted layer, as in the Tor predecessor compiler.
func (p *externalPredecessor) captureDNS(route map[string]any) error {
	bad := errors.New("external predecessor requires captured nonrecursive bootstrap DNS")
	dns, ok := p.graph["dns"].(map[string]any)
	if p.graph["dns"] != nil && (!ok || !maxFields(dns, "servers", "final", "strategy", "disable_cache", "reverse_mapping", "independent_cache", "rules")) {
		return bad
	}
	if dns == nil {
		dns = map[string]any{"servers": []any{}}
		p.graph["dns"] = dns
	}
	if raw, exists := dns["rules"]; exists {
		rows, ok := raw.([]any)
		if !ok || len(rows) != 0 {
			return bad
		}
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) > 32 {
		return bad
	}
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		tag := predecessorText(server, "tag")
		if !ok || !exactID.MatchString(tag) || p.resolvers[tag] != nil ||
			!maxFields(server, "type", "tag", "server", "server_port", "domain_resolver", "detour", "tls", "path", "client_subnet", "connect_timeout") {
			return bad
		}
		switch server["type"] {
		case "udp", "tcp", "tls", "https", "h3", "quic":
		default:
			return bad
		}
		if raw, exists := server["server_port"]; exists && !externalPort(raw) {
			return bad
		}
		if tls, exists := server["tls"]; exists && !externalTLS(tls) {
			return bad
		}
		host := predecessorText(server, "server")
		if host == "" || host == "localhost" {
			return bad
		}
		p.resolvers[tag] = server
	}
	implicit := predecessorText(dns, "final")
	if implicit == "" && len(servers) == 1 {
		implicit = predecessorText(servers[0].(map[string]any), "tag")
	}
	index := 0
	// A selected encrypted resolver can itself have an explicitly captured
	// bootstrap. Copy that complete resolver tree to the lower transport too;
	// retaining a reference to its application-DNS copy would recurse into the
	// Naive outbound whose startup requires this very resolver.
	var bootstrap func(string, map[string]any, map[string]bool) (string, error)
	bootstrap = func(source string, node map[string]any, visiting map[string]bool) (string, error) {
		server := p.resolvers[source]
		if server == nil || visiting[source] || len(visiting) >= 32 || len(p.resolvers) >= 96 {
			return "", bad
		}
		visiting[source] = true
		defer delete(visiting, source)
		copy := predecessorCopy(server)
		tag := "routervpn-predecessor-bootstrap-" + strconv.Itoa(index)
		index++
		if p.resolvers[tag] != nil {
			return "", bad
		}
		copy["tag"] = tag
		delete(copy, "detour")
		if detour, exists := node["detour"]; exists {
			copy["detour"] = detour
		}
		if selection := copy["domain_resolver"]; selection != nil {
			query, err := predecessorResolverSelection(selection)
			if err != nil {
				return "", err
			}
			child, err := bootstrap(predecessorText(query, "server"), node, visiting)
			if err != nil {
				return "", err
			}
			query["server"] = child
			copy["domain_resolver"] = query
		}
		p.resolvers[tag] = copy
		servers = append(servers, copy)
		return tag, nil
	}
	// Slice order is deterministic; map iteration must never choose or name a
	// different bootstrap for the same captured source.
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := p.graph[family].([]any)
		for _, raw := range rows {
			node := raw.(map[string]any)
			selection := node["domain_resolver"]
			if selection == nil {
				selection = route["default_domain_resolver"]
			}
			host := predecessorText(node, "server")
			_, literalErr := netip.ParseAddr(host)
			needs := node["type"] == "naive" || host != "" && literalErr != nil
			if selection == nil && !needs {
				continue
			}
			var query map[string]any
			if selection != nil {
				var err error
				query, err = predecessorResolverSelection(selection)
				if err != nil {
					return err
				}
			} else {
				server := p.resolvers[implicit]
				if server == nil {
					return bad
				}
				if node["type"] == "naive" {
					tag, err := bootstrap(implicit, node, map[string]bool{})
					if err != nil {
						return err
					}
					query = map[string]any{"server": tag}
				} else {
					query = map[string]any{"server": implicit}
				}
				if strategy, exists := dns["strategy"]; exists {
					query["strategy"] = strategy
				}
			}
			node["domain_resolver"] = query
		}
	}
	dns["servers"] = servers
	return nil
}

func predecessorResolverSelection(value any) (map[string]any, error) {
	var result map[string]any
	switch value := value.(type) {
	case string:
		result = map[string]any{"server": value}
	case map[string]any:
		result = predecessorCopy(value)
	}
	if !maxFields(result, "server", "strategy", "disable_cache", "rewrite_ttl", "client_subnet") || !exactID.MatchString(predecessorText(result, "server")) {
		return nil, externalPredecessorError
	}
	if raw, exists := result["strategy"]; exists && raw != "" && raw != "prefer_ipv4" && raw != "prefer_ipv6" && raw != "ipv4_only" && raw != "ipv6_only" {
		return nil, externalPredecessorError
	}
	return result, nil
}

func predecessorRelabelResolver(value map[string]any, names map[string]string) error {
	if selection, exists := value["domain_resolver"]; exists {
		query, err := predecessorResolverSelection(selection)
		if err != nil {
			return err
		}
		tag := names[predecessorText(query, "server")]
		if tag == "" {
			return externalPredecessorError
		}
		query["server"] = tag
		value["domain_resolver"] = query
	}
	return nil
}

func (p *externalPredecessor) validateDependencies() error {
	bad := errors.New("external predecessor has an unresolved, recursive or unowned path")
	// An extra encrypted node does not become part of the selected entry merely
	// because an imported DNS server points at it. First establish the exact
	// transport closure independently of resolver references.
	owned, activeTransport := map[string]bool{}, map[string]bool{}
	var own func(string) error
	own = func(tag string) error {
		node := p.nodes[tag]
		if node == nil || activeTransport[tag] || node["type"] == "direct" || node["type"] == "block" {
			return bad
		}
		if owned[tag] {
			return nil
		}
		activeTransport[tag] = true
		defer delete(activeTransport, tag)
		for _, field := range []string{"detour", "tcp", "udp"} {
			if raw, exists := node[field]; exists {
				text, ok := raw.(string)
				if !ok {
					return bad
				}
				if err := own(text); err != nil {
					return err
				}
			}
		}
		owned[tag] = true
		return nil
	}
	if err := own(p.finalTag); err != nil {
		return err
	}
	for tag, node := range p.nodes {
		if !owned[tag] && node["type"] != "direct" && node["type"] != "block" {
			return bad
		}
	}
	active, checked, reachable := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var visit func(string, bool) error
	visit = func(tag string, dns bool) error {
		key, objects := "node:"+tag, p.nodes
		if dns {
			key, objects = "dns:"+tag, p.resolvers
		}
		value := objects[tag]
		if value == nil || active[key] || len(active) > 96 {
			return bad
		}
		if checked[key] {
			return nil
		}
		active[key], reachable[key] = true, true
		defer delete(active, key)
		if detour, exists := value["detour"]; exists {
			text, ok := detour.(string)
			if !ok || text == tag || p.nodes[text] == nil || p.nodes[text]["type"] == "block" || !dns && p.nodes[text]["type"] == "direct" {
				return bad
			}
			if err := visit(text, false); err != nil {
				return err
			}
		}
		if !dns && value["type"] == "routervpn-composite" {
			for _, field := range []string{"tcp", "udp"} {
				if err := visit(predecessorText(value, field), false); err != nil {
					return err
				}
			}
		}
		if raw, exists := value["domain_resolver"]; exists {
			query, err := predecessorResolverSelection(raw)
			if err != nil {
				return err
			}
			if err := visit(predecessorText(query, "server"), true); err != nil {
				return err
			}
		}
		host := predecessorText(value, "server")
		if host != "" {
			ip, err := netip.ParseAddr(host)
			if err == nil {
				if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLoopback() && value["detour"] == nil {
					return bad
				}
			} else if value["domain_resolver"] == nil {
				return bad
			}
		}
		checked[key] = true
		return nil
	}
	if err := visit(p.finalTag, false); err != nil {
		return err
	}
	// Resolver servers remain explicit bootstrap transports, never a new final
	// or a system fallback. Validate their entire own dependency trees too.
	for tag := range p.resolvers {
		if err := visit(tag, true); err != nil {
			return err
		}
	}
	for tag, node := range p.nodes {
		if !reachable["node:"+tag] && node["type"] != "direct" && node["type"] != "block" {
			return bad
		}
	}
	return nil
}
