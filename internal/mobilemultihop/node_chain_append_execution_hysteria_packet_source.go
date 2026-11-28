package mobilemultihop

import "router-vpn/internal/multihoprelay"

// Preserve the original HY2 family's canonical source. Family 6 is needed only
// for a packet NEXT after HY2 or a prefix which already retained that packet.
func nodeChainPrefixHysteriaExecutionSchemas(nodes []*NodeProfile, nextMode string) (int, int, error) {
	if local, remote, err := nodeChainPrefixHysteriaSchemas(nodes, nextMode); err == nil {
		return local, remote, nil
	}
	packetNext := nodeChainAppendExecutionPacketMode(nextMode)
	if len(nodes) < 2 || len(nodes) > multihoprelay.NodeChainPrefixMaximumMembers ||
		nodes[0] == nil || !NodeChainPrefixMode(nodes[0].mode) ||
		!packetNext && nextMode != "shadowsocks" && nextMode != "hysteria2" {
		return 0, 0, errNodeChainAppendExecution
	}
	hysteria, packetAfterHysteria := false, false
	for _, node := range nodes {
		if node == nil || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
			return 0, 0, errNodeChainAppendExecution
		}
		if NodeChainPrefixMode(node.mode) {
			packetAfterHysteria = packetAfterHysteria || hysteria
			continue
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil {
			return 0, 0, errNodeChainAppendExecution
		}
		switch node.mode {
		case "shadowsocks":
			if !nodeChainCapturedSSClosure(closure) {
				return 0, 0, errNodeChainAppendExecution
			}
		case "hysteria2":
			if !nodeChainCapturedHysteriaClosure(node, closure) {
				return 0, 0, errNodeChainAppendExecution
			}
			hysteria = true
		default:
			return 0, 0, errNodeChainAppendExecution
		}
	}
	if !hysteria || !packetNext && !packetAfterHysteria {
		return 0, 0, errNodeChainAppendExecution
	}
	return 2, 6, nil
}
