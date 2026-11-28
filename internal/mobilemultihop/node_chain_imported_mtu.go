package mobilemultihop

import (
	"fmt"

	"router-vpn/internal/awgpolicy"
)

// Build a disposable, exactly linked view of the original prefix closures for
// envelope arithmetic. The source/profile/TUN values and native detours are not
// changed. Only the current compiled Auto packet cap may be reduced; subsequent
// positions see that reduced interface through the normal ordered MTU pass.
func applyNodeChainImportedPacketMTU(members []nodeChainGraphMember, closures []*externalPredecessor, position int) error {
	return applyNodeChainCapturedStreamPacketMTU(members, closures, position, nil)
}

func applyNodeChainCapturedStreamPacketMTU(members []nodeChainGraphMember, closures []*externalPredecessor, position int, appendScope *nodeChainAppendGraphScope) error {
	return applyNodeChainCapturedStreamPacketMTUOwned(members, closures, position, appendScope, nil)
}

func applyNodeChainCapturedStreamPacketMTUOwned(members []nodeChainGraphMember, closures []*externalPredecessor, position int, appendScope *nodeChainAppendGraphScope, completeScope nodeChainCompleteLocalScope) error {
	if appendScope != nil && completeScope != nil || len(members) != len(closures) || position < 1 || position >= len(closures) || !NodeChainPrefixMode(members[position].mode) {
		return nodeChainError
	}
	physicalProxy := nodeChainPhysicalProxyRoot(members, closures, appendScope, completeScope)
	if position == 1 && !physicalProxy {
		return nodeChainError
	}
	all := map[string]map[string]any{}
	hostnameIPv4Only := map[string]bool{}
	var packet, previousOuter map[string]any
	for at := position; at >= 0; at-- {
		closure := closures[at]
		if closure == nil || closure.final == nil {
			return nodeChainError
		}
		final := predecessorCopy(closure.final)
		final["tag"] = fmt.Sprintf("packet-budget-%d", at)
		all[final["tag"].(string)] = final
		if appendScope != nil && at < len(appendScope.imports) && appendScope.imports[at] != nil && appendScope.imports[at].hostname != nil {
			member := appendScope.imports[at]
			if appendScope.owner == nil || appendScope.owner.memberCapturesCurrent() != nil || at >= len(appendScope.owner.imports) || member != appendScope.owner.imports[at] || appendScope.closures[at] != closure {
				return nodeChainError
			}
			query, ok := final["domain_resolver"].(map[string]any)
			if !ok || predecessorText(query, "server") != nodeChainImportedResolver {
				return nodeChainError
			}
			onlyIPv4 := predecessorText(query, "strategy") == "ipv4_only"
			if onlyIPv4 != (member.hostname.Device.IPv6Mode == "off") {
				return nodeChainError
			}
			hostnameIPv4Only[final["tag"].(string)] = onlyIPv4
		}
		outer := final
		if detour, exists := final["detour"]; exists {
			if detour != NativeStartLayerTag || closure.nodes[NativeStartLayerTag] == nil {
				return nodeChainError
			}
			outer = predecessorCopy(closure.nodes[NativeStartLayerTag])
			if outer["detour"] != nil {
				return nodeChainError
			}
			outer["tag"] = fmt.Sprintf("packet-budget-%d-layer", at)
			final["detour"] = outer["tag"]
			all[outer["tag"].(string)] = outer
		}
		if at == position {
			packet = final
		} else {
			previousOuter["detour"] = final["tag"]
			if NodeChainPrefixMode(members[at].mode) {
				break
			}
			if members[at].mode == "hysteria2" {
				appendOwned := appendScope != nil && at < len(appendScope.nodes) && at < len(appendScope.closures) && appendScope.nodes[at] != nil &&
					appendScope.closures[at] == closure && nodeChainAppendHysteriaClosure(appendScope.nodes[at], closure)
				if !appendOwned && (completeScope == nil || !completeScope.admitsProxy(at, closure, "hysteria2")) {
					return nodeChainError
				}
				// HY2 fragments its complete UDP message, whose finite native
				// bound includes this packet and every intervening SS wrapper.
				// It is not the preceding proxy's TUN or a physical IP MTU.
				envelope, err := awgpolicy.CapturedHysteriaPacketEnvelopeWithHostnameFamilies(packet, all, final["tag"].(string), hostnameIPv4Only)
				if err != nil {
					return err
				}
				requested, err := mtuNumber(packet["mtu"])
				if err != nil {
					return err
				}
				fixed, err := fixedMTU(members[position].profile)
				if err != nil {
					return err
				}
				capacity, err := envelope.Capacity(requested, fixed != 0)
				if err != nil {
					return err
				}
				closures[position].final["mtu"] = float64(capacity)
				return nil
			}
			if members[at].mode != "shadowsocks" {
				return nodeChainError
			}
			if !members[at].imported {
				appendOwned := appendScope != nil && at < len(appendScope.nodes) && at < len(appendScope.closures) &&
					appendScope.nodes[at] != nil && appendScope.nodes[at].mode == "shadowsocks" &&
					appendScope.closures[at] == closure && nodeChainAppendSSClosure(closure)
				if !appendOwned && (completeScope == nil || !completeScope.admitsProxy(at, closure, "shadowsocks")) {
					return nodeChainError
				}
			}
		}
		previousOuter = outer
	}
	var envelope awgpolicy.PacketEnvelope
	var entry map[string]any
	var err error
	if len(hostnameIPv4Only) == 0 {
		envelope, entry, err = awgpolicy.NestedPacketEnvelope(packet, all)
	} else {
		envelope, entry, err = awgpolicy.NestedPacketEnvelopeWithHostnameFamilies(packet, all, hostnameIPv4Only)
	}
	if err != nil {
		return err
	}
	if entry == nil {
		if !physicalProxy || len(hostnameIPv4Only) != 0 {
			return nodeChainError
		}
		// The actual SS root has no earlier packet interface. The unchanged
		// ordinary pass retained the source packet cap and device TUN policy;
		// do not manufacture an ancestor MTU or claim physical PMTU discovery.
		return nil
	}
	outer, err := mtuNumber(entry["mtu"])
	if err != nil {
		return err
	}
	inner, err := mtuNumber(packet["mtu"])
	if err != nil {
		return err
	}
	fixed, err := fixedMTU(members[position].profile)
	if err != nil {
		return err
	}
	entryFixed, err := fixedMTU(members[position-1].profile)
	if err != nil {
		return err
	}
	cap, err := envelope.Capacity(outer, inner, fixed != 0 || entryFixed != 0)
	if err != nil {
		return err
	}
	closures[position].final["mtu"] = float64(cap)
	return nil
}
