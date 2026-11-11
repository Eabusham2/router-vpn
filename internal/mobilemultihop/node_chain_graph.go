package mobilemultihop

import (
	"encoding/json"
	"errors"
)

func compileNodeChain(nodes []*NodeProfile) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	bad := errors.New("ordered chain lost a complete captured node closure")
	fail := func(err error) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
		return "", nil, NodeChainDNSCapture{}, nil, err
	}
	if len(nodes) < 2 || len(nodes) > NodeChainMaximumNodes {
		return fail(bad)
	}
	closures := make([]*externalPredecessor, len(nodes))
	for i, node := range nodes {
		if node == nil || node.validateNodeDesktopCapture() != nil {
			return fail(bad)
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil || closure == nil {
			return fail(bad)
		}
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return fail(errors.New("ordered chain cover services require their per-position native owner integration"))
		}
		if i < len(nodes)-1 && (node.mode != "wg" || closure.final["type"] != "wireguard") ||
			i == len(nodes)-1 && (node.mode != "shadowsocks" || closure.final["method"] != NativeStartLayerMethod ||
				closure.final["type"] != "shadowsocks" && closure.final["type"] != "routervpn-aes-xor") {
			return fail(bad)
		}
		closures[i] = closure
	}
	if err := applyNodeChainMTU(nodes, closures); err != nil {
		return fail(err)
	}
	last := closures[len(closures)-1]
	tun := predecessorCopy(last.tun)
	tun["tag"] = "routervpn-chain-tun"
	dns := predecessorCopy(last.graph["dns"].(map[string]any))
	route := predecessorCopy(last.graph["route"].(map[string]any))
	delete(route, "default_domain_resolver")
	route["final"] = SelectorTag
	graph := map[string]any{"log": last.graph["log"], "inbounds": []any{tun},
		"outbounds": []any{}, "endpoints": []any{}, "route": route, "dns": dns}
	proofs := make([]NodeChainProof, 0, len(nodes))
	servers := []any{}
	for position, closure := range closures {
		node := nodes[position]
		names, dnsNames := map[string]string{}, map[string]string{}
		for tag := range closure.nodes {
			names[tag] = nodeChainNamespace(position, node.source, "node", tag)
		}
		for tag := range closure.resolvers {
			dnsNames[tag] = nodeChainNamespace(position, node.source, "dns", tag)
		}
		finalTag := names[closure.finalTag]
		outer := closure.final
		for depth := 0; outer["detour"] != nil; depth++ {
			owner := predecessorText(outer, "detour")
			if depth > 1 || owner != NativeStartLayerTag || closure.nodes[owner] == nil {
				return fail(bad)
			}
			outer = closure.nodes[owner]
		}
		for _, family := range []string{"endpoints", "outbounds"} {
			rows, _ := closure.graph[family].([]any)
			for _, raw := range rows {
				value := raw.(map[string]any)
				value["tag"] = names[predecessorText(value, "tag")]
				for _, field := range []string{"detour", "tcp", "udp"} {
					if original, exists := value[field]; exists {
						tag, ok := original.(string)
						if !ok || names[tag] == "" {
							return fail(bad)
						}
						value[field] = names[tag]
					}
				}
				if err := predecessorRelabelResolver(value, dnsNames); err != nil {
					return fail(err)
				}
			}
			graph[family] = append(graph[family].([]any), rows...)
		}
		if position != 0 {
			// The captured layer, when present, remains between this node's
			// inner protocol and the entire preceding selected-node prefix.
			outer["detour"] = proofs[position-1].Tag
		}
		originalDNS := closure.graph["dns"].(map[string]any)
		for _, raw := range originalDNS["servers"].([]any) {
			server := raw.(map[string]any)
			server["tag"] = dnsNames[predecessorText(server, "tag")]
			if original, exists := server["detour"]; exists {
				tag, ok := original.(string)
				if !ok || names[tag] == "" {
					return fail(bad)
				}
				server["detour"] = names[tag]
			} else if position != 0 {
				server["detour"] = proofs[position-1].Tag
			}
			if err := predecessorRelabelResolver(server, dnsNames); err != nil {
				return fail(err)
			}
			servers = append(servers, server)
		}
		if position == len(nodes)-1 {
			dns["final"] = dnsNames[predecessorText(originalDNS, "final")]
			if dns["final"] == "" {
				return fail(bad)
			}
		}
		layer := predecessorText(node.profile, "start_layer")
		if layer == "" {
			layer = "off"
		}
		proofs = append(proofs, NodeChainProof{position, predecessorText(node.profile, "id"),
			predecessorText(node.profile, "node_proof_id"), node.mode, layer, node.source, finalTag})
	}
	dns["servers"] = servers
	if err := applyNodeChainRestrictions(graph, closures); err != nil {
		return fail(err)
	}
	finalTag := proofs[len(proofs)-1].Tag
	graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{
		"type": "selector", "tag": SelectorTag, "outbounds": []any{finalTag},
		"default": finalTag, "interrupt_exist_connections": true})
	encoded, err := json.Marshal(graph)
	if err != nil || len(encoded) > 4<<20 {
		return fail(bad)
	}
	// Generic physical traversal sees the sealed single choice directly; it
	// does not gain the legacy two-candidate selector's Local/Server authority.
	projection := predecessorCopy(graph)
	projection["route"].(map[string]any)["final"] = finalTag
	projected, _ := json.Marshal(projection)
	expected, err := nodes[0].PhysicalEgress()
	if err != nil {
		return fail(err)
	}
	var physical []PhysicalEgress
	for _, proof := range proofs {
		physical, err = compiledPhysicalEgressWithDesktopProof(string(projected), []string{"tcp", "udp"}, nil, proof.Tag)
		if err != nil || !nodeChainSamePhysical(physical, expected) {
			return fail(errors.New("ordered chain introduced physical egress outside its original first node"))
		}
	}
	selected := predecessorText(dns, "final")
	var resolver map[string]any
	for _, raw := range servers {
		row := raw.(map[string]any)
		if row["tag"] == selected {
			if resolver != nil || row["detour"] != finalTag {
				return fail(bad)
			}
			resolver = row
		}
	}
	if resolver == nil {
		return fail(bad)
	}
	resolverBytes, _ := json.Marshal(resolver)
	capture := NodeChainDNSCapture{TUNTag: predecessorText(tun, "tag"), ResolverTag: selected,
		ResolverSHA256: externalDigest(resolverBytes), FinalTag: finalTag}
	return string(encoded), proofs, capture, physical, nil
}
