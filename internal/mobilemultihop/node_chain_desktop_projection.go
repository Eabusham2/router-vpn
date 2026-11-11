package mobilemultihop

import "encoding/json"

const nodeChainDesktopPhysicalKind = "desktop-physical"

// Native physical owner objects carry no packet envelope. Remove only the
// exact sealed projection for read-only MTU validation, then require every
// original prefix as usual. The executable graph is never rewritten here.
func nodeChainProjectedMTUPlan(config string, proofs []NodeChainProof, projection nodeChainProjection) (NodeChainMTUPlan, error) {
	if projection.Kind == "" {
		if projection.SessionID != "" || projection.PhysicalSourceSHA256 != "" || projection.BaseConfigSHA256 != "" {
			return NodeChainMTUPlan{}, nodeChainError
		}
		return nodeChainMTUPlan(config, proofs)
	}
	if projection.Kind != nodeChainDesktopPhysicalKind || !desktopExternalSessionID.MatchString(projection.SessionID) ||
		!proofID.MatchString(projection.PhysicalSourceSHA256) || !proofID.MatchString(projection.BaseConfigSHA256) ||
		projection.TargetOS != "linux" && projection.TargetOS != "windows" && projection.TargetOS != "darwin" {
		return NodeChainMTUPlan{}, nodeChainError
	}
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return NodeChainMTUPlan{}, nodeChainError
	}
	ownerMatches := func(value map[string]any, kind, tag string) bool {
		return len(value) == 4 && value["type"] == kind && value["tag"] == tag &&
			value["session_id"] == projection.SessionID && value["source_sha256"] == projection.PhysicalSourceSHA256
	}
	services, ok := graph["services"].([]any)
	if !ok || len(services) != 1 {
		return NodeChainMTUPlan{}, nodeChainError
	}
	service, ok := services[0].(map[string]any)
	if !ok || !ownerMatches(service, DesktopNodeNetworkType, DesktopNodeNetworkTag) {
		return NodeChainMTUPlan{}, nodeChainError
	}
	delete(graph, "services")
	physicalFound, roots := false, 0
	for _, family := range []string{"outbounds", "endpoints"} {
		rows, ok := graph[family].([]any)
		if !ok {
			return NodeChainMTUPlan{}, nodeChainError
		}
		kept := make([]any, 0, len(rows))
		for _, raw := range rows {
			value, ok := raw.(map[string]any)
			if !ok {
				return NodeChainMTUPlan{}, nodeChainError
			}
			if value["tag"] == DesktopNodePhysicalTag || value["type"] == DesktopNodePhysicalType {
				if physicalFound || family != "outbounds" || !ownerMatches(value, DesktopNodePhysicalType, DesktopNodePhysicalTag) {
					return NodeChainMTUPlan{}, nodeChainError
				}
				physicalFound = true
				continue
			}
			if value["detour"] == DesktopNodePhysicalTag {
				delete(value, "detour")
				roots++
			}
			kept = append(kept, value)
		}
		graph[family] = kept
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return NodeChainMTUPlan{}, nodeChainError
	}
	servers, ok := dns["servers"].([]any)
	if !ok {
		return NodeChainMTUPlan{}, nodeChainError
	}
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		if !ok {
			return NodeChainMTUPlan{}, nodeChainError
		}
		if server["detour"] == DesktopNodePhysicalTag {
			delete(server, "detour")
		}
	}
	raw, err := json.Marshal(graph)
	// The base hash is derived from the complete original source and captured
	// target/restore. An injected physical edge on a middle node, application
	// DNS or another object cannot disappear into this validation projection.
	if err != nil || !physicalFound || roots == 0 || externalDigest(raw) != projection.BaseConfigSHA256 {
		return NodeChainMTUPlan{}, nodeChainError
	}
	return nodeChainMTUPlan(string(raw), proofs)
}
