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

func applyNodeChainCapturedStreamPacketMTUOwned(members []nodeChainGraphMember, closures []*externalPredecessor, position int, appendScope *nodeChainAppendGraphScope, completeScope *nodeChainPairedHysteriaGraphScope) error {
	if appendScope != nil && completeScope != nil || len(members) != len(closures) || position < 2 || position >= len(closures) || !NodeChainPrefixMode(members[position].mode) {
		return nodeChainError
	}
	all := map[string]map[string]any{}
	var packet, previousOuter map[string]any
	for at := position; at >= 0; at-- {
		closure := closures[at]
		if closure == nil || closure.final == nil {
			return nodeChainError
		}
		final := predecessorCopy(closure.final)
		final["tag"] = fmt.Sprintf("packet-budget-%d", at)
		all[final["tag"].(string)] = final
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
				if !appendOwned && !completeScope.admitsProxy(at, closure, "hysteria2") {
					return nodeChainError
				}
				// HY2 owns native UDP message fragmentation/reassembly. The
				// normal ordered MTU pass already retained this proxy TUN and
				// the packet cap; raw SS overhead cannot be extended across QUIC.
				return nil
			}
			if members[at].mode != "shadowsocks" {
				return nodeChainError
			}
			if !members[at].imported {
				appendOwned := appendScope != nil && at < len(appendScope.nodes) && at < len(appendScope.closures) &&
					appendScope.nodes[at] != nil && appendScope.nodes[at].mode == "shadowsocks" &&
					appendScope.closures[at] == closure && nodeChainAppendSSClosure(closure)
				if !appendOwned && !completeScope.admitsProxy(at, closure, "shadowsocks") {
					return nodeChainError
				}
			}
		}
		previousOuter = outer
	}
	envelope, entry, err := awgpolicy.NestedPacketEnvelope(packet, all)
	if err != nil {
		return err
	}
	if entry == nil {
		return nodeChainError
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
