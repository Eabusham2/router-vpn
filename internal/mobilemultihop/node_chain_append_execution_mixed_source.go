package mobilemultihop

import "router-vpn/internal/multihoprelay"

// Select the remote version from the actual original captured prefix. The
// legacy packet-head/SS-tail helper remains exact for its existing callers.
func nodeChainPrefixExecutionSchemas(nodes []*NodeProfile, nextMode string) (int, int, error) {
	if nextMode == "hysteria2" {
		return nodeChainPrefixHysteriaExecutionSchemas(nodes, nextMode)
	}
	for _, node := range nodes {
		if node != nil && node.mode == "hysteria2" {
			return nodeChainPrefixHysteriaExecutionSchemas(nodes, nextMode)
		}
	}
	packetNext := nodeChainAppendExecutionPacketMode(nextMode)
	if nextMode != "shadowsocks" && !packetNext {
		return 0, 0, errNodeChainAppendExecution
	}
	if local, err := nodeChainPrefixLocalSchema(nodes); err == nil {
		remote := local
		if packetNext {
			remote = 3
			if local == 2 {
				remote = 4
			}
		}
		return local, remote, nil
	}
	if len(nodes) < 2 || len(nodes) > multihoprelay.NodeChainPrefixMaximumMembers ||
		nodes[0] == nil || !NodeChainPrefixMode(nodes[0].mode) {
		return 0, 0, errNodeChainAppendExecution
	}
	stream, packetAfterStream := false, false
	for _, node := range nodes {
		if node == nil || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
			return 0, 0, errNodeChainAppendExecution
		}
		if NodeChainPrefixMode(node.mode) {
			packetAfterStream = packetAfterStream || stream
			continue
		}
		closure, err := nodeMultihopPredecessor(node)
		if node.mode != "shadowsocks" || err != nil || !nodeChainCapturedSSClosure(closure) {
			return 0, 0, errNodeChainAppendExecution
		}
		stream = true
	}
	if !stream || !packetAfterStream {
		return 0, 0, errNodeChainAppendExecution
	}
	return 2, 4, nil
}

// The original full descriptor validation remains mandatory. This helper only
// selects the already captured packet candidate representation for schemas3/4/6.
func nodeChainPrefixHasPacketCandidates(source NodeChainServerPrefixSource) bool {
	return source.Schema == 3 || (source.Schema == 4 || source.Schema == 6) && source.PacketCandidatePairs != nil
}
