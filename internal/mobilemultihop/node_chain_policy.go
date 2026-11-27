package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
)

func applyNodeChainMemberMTUWithServerScope(nodes []nodeChainGraphMember, closures []*externalPredecessor, server *nodeChainMultipleImportedServerScope) error {
	return applyNodeChainMemberMTUWithAppendScope(nodes, closures, server, nil)
}

func applyNodeChainMemberMTUWithAppendScope(nodes []nodeChainGraphMember, closures []*externalPredecessor, server *nodeChainMultipleImportedServerScope, appendScope *nodeChainAppendGraphScope) error {
	return applyNodeChainMemberMTUWithOwnedScopes(nodes, closures, server, appendScope, nil)
}

func applyNodeChainMemberMTUWithOwnedScopes(nodes []nodeChainGraphMember, closures []*externalPredecessor, server *nodeChainMultipleImportedServerScope, appendScope *nodeChainAppendGraphScope, completeScope *nodeChainPairedHysteriaGraphScope) error {
	if completeScope != nil && (server != nil || appendScope != nil) {
		return nodeChainError
	}
	if server != nil && server.validateCompilation(nodes, closures) != nil {
		return nodeChainServerError
	}
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
		// The complete imported source or distinct append scope retains every
		// SS member crossed before the next packet interface. Its packet budget
		// uses that complete proxy path, not the proxy's OS TUN baseline.
		if ((nodes[i-1].imported || appendScope != nil || completeScope != nil) && nodes[i-1].mode == "shadowsocks" ||
			(appendScope != nil || completeScope != nil) && nodes[i-1].mode == "hysteria2") && NodeChainPrefixMode(nodes[i].mode) &&
			(server == nil || !server.firstPhysicalPacket(i)) {
			if err := applyNodeChainCapturedStreamPacketMTUOwned(nodes, closures, i, appendScope, completeScope); err != nil {
				return err
			}
		}
		// A proxy can itself be the next predecessor. Keep the computed
		// integer in the same JSON number representation its parser validates.
		if value, ok := closures[i].tun["mtu"].(int); ok {
			closures[i].tun["mtu"] = float64(value)
		}
	}
	return nil
}

func applyNodeChainRestrictions(graph map[string]any, nodes []nodeChainGraphMember, closures []*externalPredecessor) error {
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
	last := closures[len(closures)-1]
	member := nodes[len(nodes)-1]
	var control map[string]any
	var controlAddress netip.Addr
	if !member.imported {
		endpoint, _ := privateAPI(predecessorText(member.profile, "router_api"))
		control = pairedNodeControlRoute(member.profile, endpoint, predecessorText(last.tun, "tag"))
		if control != nil {
			controlAddress, _ = netip.ParseAddr(endpoint.Hostname())
		}
	}
	var lan []map[string]any
	for i, closure := range closures {
		for _, restriction := range closure.restrictions {
			rule := restriction.(map[string]any)
			if control != nil && rule["action"] == "reject" && rule["ip_cidr"] != nil {
				_, ranges, err := externalDevicePolicy(nodes[i].profile)
				if err != nil {
					return err
				}
				original := map[string]any{"inbound": []any{closure.tun["tag"]}, "ip_cidr": ranges, "action": "reject"}
				if reflect.DeepEqual(rule, predecessorCopy(original)) && slices.ContainsFunc(ranges, func(cidr string) bool {
					return netip.MustParsePrefix(cidr).Contains(controlAddress)
				}) {
					lan = append(lan, rule)
					continue
				}
			}
			add(rule)
		}
	}
	matched := false
	lastRoute := last.graph["route"].(map[string]any)
	for _, raw := range lastRoute["rules"].([]any) {
		rule := raw.(map[string]any)
		switch rule["action"] {
		case "hijack-dns":
			add(rule)
		case "reject", "sniff":
		case "route":
			if matched || member.profile["home_lan_access"] != false || control == nil || !reflect.DeepEqual(rule, predecessorCopy(control)) {
				return errors.New("ordered chain has an unowned final application route")
			}
			matched = true
		default:
			return errors.New("ordered chain cannot discard a selected node routing policy")
		}
	}
	// Only a source-derived LAN deny may yield to the authenticated final API.
	// Every other restriction, including IPv6-Off, and selected DNS stay first.
	if len(lan) != 0 {
		control["outbound"] = SelectorTag
		add(control)
		for _, rule := range lan {
			add(rule)
		}
	}
	if ipv6Off {
		tun["route_address"] = []any{"0.0.0.0/0", "::/0"}
	}
	route["rules"] = rules
	return nil
}
