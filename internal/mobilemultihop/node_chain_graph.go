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
	if len(nodes) < 2 || len(nodes) > NodeChainMaximumNodes && !extendedPairedLocalNodes(nodes) {
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
		if i < len(nodes)-1 && (!NodeChainPrefixMode(node.mode) || closure.final["type"] != nodeChainPrefixType(node.mode)) ||
			i == len(nodes)-1 && !nodeChainFinalClosure(node, closure) {
			return fail(bad)
		}
		closures[i] = closure
	}
	members := make([]nodeChainGraphMember, len(nodes))
	for i, node := range nodes {
		members[i] = nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode}
	}
	expected, err := nodes[0].PhysicalEgress()
	if err != nil {
		return fail(err)
	}
	return compileNodeChainClosures(members, closures, expected)
}

type nodeChainGraphMember struct {
	profile      map[string]any
	source, mode string
	imported     bool
	externalHome bool // Final DNS is the authenticated first Router’s selected AdGuard.
}

func compileNodeChainClosures(nodes []nodeChainGraphMember, closures []*externalPredecessor, expected []PhysicalEgress) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	return compileNodeChainClosuresWithCONNECT(nodes, closures, expected, nil)
}

func compileNodeChainClosuresWithCONNECT(nodes []nodeChainGraphMember, closures []*externalPredecessor, expected []PhysicalEgress, connect *nodeChainCONNECTProofScope) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	var scope nodeChainCapturedTransportScope
	if connect != nil {
		scope = connect
	}
	return compileNodeChainClosuresWithTransport(nodes, closures, expected, scope)
}

func compileNodeChainClosuresWithTransport(nodes []nodeChainGraphMember, closures []*externalPredecessor, expected []PhysicalEgress, connect nodeChainCapturedTransportScope) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	return compileNodeChainClosuresWithServerScope(nodes, closures, expected, connect, nil)
}

func compileNodeChainClosuresWithServerScope(nodes []nodeChainGraphMember, closures []*externalPredecessor, expected []PhysicalEgress, connect nodeChainCapturedTransportScope, server *nodeChainMultipleImportedServerScope) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	return compileNodeChainGraph(nodes, closures, expected, connect, server, nil)
}

func compileNodeChainGraph(nodes []nodeChainGraphMember, closures []*externalPredecessor, expected []PhysicalEgress, connect nodeChainCapturedTransportScope, server *nodeChainMultipleImportedServerScope, closed *NodeChainCandidatePlan) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	return compileNodeChainGraphWithHome(nodes, closures, expected, connect, server, closed, nil)
}

func compileNodeChainGraphWithHome(nodes []nodeChainGraphMember, closures []*externalPredecessor, expected []PhysicalEgress, connect nodeChainCapturedTransportScope, server *nodeChainMultipleImportedServerScope, closed *NodeChainCandidatePlan, home *NodeChainServerHomeDNS) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	bad := errors.New("ordered chain lost a complete captured node closure")
	fail := func(err error) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
		return "", nil, NodeChainDNSCapture{}, nil, err
	}
	// A literal imported intermediate has no application resolver. A closed
	// test may keep the original entry resolver attached to its own outbound.
	// Only the separately owned closed-ingress constructor can request this.
	resolverPosition := len(nodes) - 1
	if closed != nil {
		if closed.validate() != nil || closed.measurement == "" || len(nodes) != closed.prefix.Position+1 || connect != nil || server != nil {
			return fail(bad)
		}
		resolverPosition = 0
	}
	if connect != nil {
		if err := connect.validate(nodes, closures); err != nil {
			return fail(err)
		}
	}
	if err := applyNodeChainMemberMTUWithServerScope(nodes, closures, server); err != nil {
		return fail(err)
	}
	last := closures[len(closures)-1]
	tun := predecessorCopy(last.tun)
	tun["tag"] = "routervpn-chain-tun"
	dns := predecessorCopy(closures[resolverPosition].graph["dns"].(map[string]any))
	route := predecessorCopy(last.graph["route"].(map[string]any))
	delete(route, "default_domain_resolver")
	route["final"] = SelectorTag
	graph := map[string]any{"log": last.graph["log"], "inbounds": []any{tun},
		"outbounds": []any{}, "endpoints": []any{}, "route": route, "dns": dns}
	if home != nil {
		if connect != nil || server != nil || closed != nil || len(nodes) < 2 || !nodes[len(nodes)-1].imported {
			return fail(bad)
		}
		graph["outbounds"] = []any{home.outbound()}
	}
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
			if home != nil && position == len(nodes)-1 && server["detour"] == externalEntryTag {
				server["detour"] = NodeChainServerEntryHomeTag
			} else if node.externalHome && server["detour"] == externalEntryTag && position == len(nodes)-1 && len(proofs) > 0 {
				server["detour"] = proofs[0].Tag
			} else if original, exists := server["detour"]; exists {
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
		if position == resolverPosition {
			dns["final"] = dnsNames[predecessorText(originalDNS, "final")]
			if dns["final"] == "" {
				return fail(bad)
			}
		}
		layer := predecessorText(node.profile, "start_layer")
		if layer == "" {
			layer = "off"
		}
		proof := NodeChainProof{Position: position, ProfileID: predecessorText(node.profile, "id"), NodeID: predecessorText(node.profile, "node_proof_id"), Mode: node.mode, StartLayer: layer, SourceSHA256: node.source, Tag: finalTag}
		if node.imported {
			proof.NodeKind, proof.Kind = "external", "public-path"
		}
		proofs = append(proofs, proof)
	}
	dns["servers"] = servers
	if err := applyNodeChainRestrictions(graph, nodes, closures); err != nil {
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
	var connectPhysical nodeChainCapturedTransportProof
	if connect != nil {
		connectPhysical, err = connect.captureTransport(string(projected), proofs)
		if err != nil {
			return fail(err)
		}
	}
	var physical []PhysicalEgress
	var projections [][]PhysicalEgress
	aggregate := server != nil && server.firstPacket > 0
	traversal, err := parseCapturedEgressGraph(string(projected), connectPhysical)
	if err != nil {
		return fail(err)
	}
	traversal.serverHome = home
	for _, proof := range proofs {
		physical, err = traversal.physical([]string{"tcp", "udp"}, nil, proof.Tag, false)
		if err != nil || !aggregate && !nodeChainSamePhysical(physical, expected) {
			return fail(errors.New("ordered chain introduced physical egress outside its original first node"))
		}
		if aggregate {
			projections = append(projections, append([]PhysicalEgress(nil), physical...))
		}
	}
	if aggregate {
		physical, err = server.completePhysicalEgress(projections, expected)
		if err != nil {
			return fail(err)
		}
	}
	selected := predecessorText(dns, "final")
	resolverDetour := proofs[resolverPosition].Tag
	if home != nil {
		resolverDetour = NodeChainServerEntryHomeTag
	} else if nodes[resolverPosition].externalHome {
		resolverDetour = proofs[0].Tag
	}
	var resolver map[string]any
	for _, raw := range servers {
		row := raw.(map[string]any)
		if row["tag"] == selected {
			if resolver != nil || row["detour"] != resolverDetour {
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
