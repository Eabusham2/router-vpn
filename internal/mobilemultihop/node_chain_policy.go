package mobilemultihop

import (
	"encoding/json"
	"errors"
)

// Project each nested packet edge against the already-derived prefix budget.
// Fixed settings never clamp and historical effective_mtu never becomes
// current-path evidence. A prefix too small for the next WG handshake fails.
func applyNodeChainMTU(nodes []*NodeProfile, closures []*externalPredecessor) error {
	for i := 1; i < len(nodes); i++ {
		envelope, err := nodePacketEnvelope(closures[i], nodes[i].mode)
		if err != nil {
			return err
		}
		selection := externalPolicyCapture{Profile: predecessorCopy(nodes[i].profile),
			Entry: predecessorCopy(nodes[i-1].profile)}
		if err := nodeMultihopMTU(closures[i-1], closures[i], selection, envelope, nodes[i].mode); err != nil {
			return err
		}
	}
	return nil
}

func applyNodeChainRestrictions(graph map[string]any, closures []*externalPredecessor) error {
	route, ok := graph["route"].(map[string]any)
	inbounds, valid := graph["inbounds"].([]any)
	if !ok || !valid || len(inbounds) != 1 {
		return nodeChainError
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" {
		return nodeChainError
	}
	seen, rules, ipv6Off := map[string]bool{}, []any{}, false
	add := func(original map[string]any) {
		rule := predecessorCopy(original)
		rule["inbound"] = []any{tun["tag"]}
		if rule["action"] == "reject" && rule["ip_version"] == float64(6) {
			ipv6Off = true
		}
		raw, _ := json.Marshal(rule)
		if !seen[string(raw)] {
			seen[string(raw)] = true
			rules = append(rules, rule)
		}
	}
	for _, closure := range closures {
		for _, restriction := range closure.restrictions {
			add(restriction.(map[string]any))
		}
	}
	lastRoute := closures[len(closures)-1].graph["route"].(map[string]any)
	for _, raw := range lastRoute["rules"].([]any) {
		rule := raw.(map[string]any)
		if rule["action"] == "hijack-dns" {
			add(rule)
		} else if rule["action"] != "reject" && rule["action"] != "sniff" {
			return errors.New("ordered chain cannot discard a selected node routing policy")
		}
	}
	if ipv6Off {
		tun["route_address"] = []any{"0.0.0.0/0", "::/0"}
	}
	route["rules"] = rules
	return nil
}
