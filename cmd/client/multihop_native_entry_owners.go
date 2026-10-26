package main

import (
	"encoding/json"
	"errors"
	"strings"

	"router-vpn/internal/mobilemultihop"
)

// Capture exactly the entry closure compiled from its immutable NodeProfile.
// This is checked on both sides of the Server substitution: replacing an exit
// may not remove or edit an entry engine, its selected/bootstrap DNS, or its
// performance service. Tags alone never admit a source; the caller first
// verifies the entire Local graph against the captured compiler output.
func nativeMultihopEntrySnapshot(graph map[string]any, captured mobilemultihop.NodeEntryOwners) (map[string]bool, []byte, error) {
	bad := errors.New("Server execution lost the complete captured native entry")
	owners, resolverOwners := map[string]bool{}, map[string]bool{}
	if len(captured.Nodes) == 0 || len(captured.Nodes) > 32 || len(captured.Resolvers) == 0 || len(captured.Resolvers) > 96 {
		return nil, nil, bad
	}
	for _, tag := range captured.Nodes {
		if owners[tag] || tag != "entry-wg" && !strings.HasPrefix(tag, "external-entry-node-") && tag != "routervpn-entry-composite-tcp" && tag != "routervpn-entry-composite-udp" && tag != "routervpn-entry-composite-start" {
			return nil, nil, bad
		}
		owners[tag] = true
	}
	if !owners["entry-wg"] {
		return nil, nil, bad
	}
	for _, tag := range captured.Resolvers {
		if resolverOwners[tag] || !strings.HasPrefix(tag, "external-entry-dns-") {
			return nil, nil, bad
		}
		resolverOwners[tag] = true
	}
	nodes, resolvers := map[string]any{}, map[string]any{}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, valid := graph[family].([]any)
		if graph[family] != nil && !valid {
			return nil, nil, bad
		}
		for _, raw := range rows {
			node, ok := raw.(map[string]any)
			tag, _ := node["tag"].(string)
			if !ok {
				return nil, nil, bad
			}
			if !owners[tag] {
				if strings.HasPrefix(tag, "external-entry-node-") || strings.HasPrefix(tag, "routervpn-entry-composite-") {
					return nil, nil, bad
				}
				continue
			}
			if nodes[tag] != nil {
				return nil, nil, bad
			}
			for _, field := range []string{"detour", "tcp", "udp"} {
				if raw, exists := node[field]; exists {
					ref, ok := raw.(string)
					if !ok || !owners[ref] || ref == tag {
						return nil, nil, bad
					}
				}
			}
			nodes[tag] = map[string]any{"family": family, "owner": node}
		}
	}
	if len(nodes) != len(owners) {
		return nil, nil, bad
	}
	dns, _ := graph["dns"].(map[string]any)
	servers, ok := dns["servers"].([]any)
	if !ok {
		return nil, nil, bad
	}
	for _, raw := range servers {
		resolver, ok := raw.(map[string]any)
		tag, _ := resolver["tag"].(string)
		if !ok {
			return nil, nil, bad
		}
		if !resolverOwners[tag] {
			if strings.HasPrefix(tag, "external-entry-dns-") {
				return nil, nil, bad
			}
			continue
		}
		if resolvers[tag] != nil {
			return nil, nil, bad
		}
		if raw, exists := resolver["detour"]; exists {
			ref, ok := raw.(string)
			if !ok || !owners[ref] {
				return nil, nil, bad
			}
		}
		resolvers[tag] = resolver
	}
	if len(resolvers) != len(resolverOwners) {
		return nil, nil, bad
	}
	services := []any{}
	rows, ok := graph["services"].([]any)
	if graph["services"] != nil && !ok {
		return nil, nil, bad
	}
	for _, raw := range rows {
		service, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, bad
		}
		if service["tag"] == "routervpn-cover-entry" {
			proof, _ := service["proof_tag"].(string)
			packet, _ := service["packet_tag"].(string)
			if len(services) != 0 || !owners[proof] || !owners[packet] {
				return nil, nil, bad
			}
			services = append(services, service)
		}
	}
	encoded, err := json.Marshal(map[string]any{"nodes": nodes, "resolvers": resolvers, "services": services})
	if err != nil {
		return nil, nil, err
	}
	return owners, encoded, nil
}
