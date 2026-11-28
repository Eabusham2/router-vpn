package mobilemultihop

import (
	"reflect"

	"router-vpn/internal/awgpolicy"
)

// This is arithmetic readback of the original family-6 graph, not a new UDP
// grant. Its callers already retain the exact prefix or prospective candidate
// graph. Only that graph's captured HY2 owner may terminate the SS envelope;
// its native QUIC session fragments only complete messages within its finite
// payload limit. The separately typed envelope retains that exact limit.
func (s *NodeChainServerPrefixSession) originalHysteriaPacketBoundary(packet map[string]any, all map[string]map[string]any) (awgpolicy.HysteriaPacketEnvelope, bool, error) {
	if s == nil || s.policy == nil || s.policy.record.Schema != 6 || s.policy.validate() != nil ||
		s.policy.prefix == nil || s.policy.prefix != s.policy.capturedPrefix || s.policy.prefix.validate() != nil ||
		s.policy.plan == nil || s.policy.plan.appendSource != s.policy.prefix ||
		len(s.policy.nodes) != len(s.policy.prefix.proofs) || packet == nil ||
		packet["type"] != "wireguard" && packet["type"] != nodeChainPrefixType("awg2-fast") {
		return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
	}
	if _, err := mtuNumber(packet["mtu"]); err != nil {
		return awgpolicy.HysteriaPacketEnvelope{}, false, err
	}
	tag := predecessorText(packet, "tag")
	if tag == "" || all[tag] == nil || !reflect.DeepEqual(all[tag], packet) {
		return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
	}
	seen := map[string]bool{tag: true}
	current := packet
	for len(seen) <= len(s.policy.prefix.proofs) {
		next := predecessorText(current, "detour")
		if next == "" || seen[next] {
			return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
		}
		seen[next] = true
		position := -1
		for i, proof := range s.policy.prefix.proofs {
			if proof.Tag == next {
				if position != -1 {
					return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
				}
				position = i
			}
		}
		if position < 0 || position >= len(s.policy.nodes) {
			return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
		}
		node, proof := s.policy.nodes[position], s.policy.prefix.proofs[position]
		row := all[next]
		if node == nil || node.source != proof.SourceSHA256 || node.mode != proof.Mode ||
			proof.StartLayer != "off" || row == nil || predecessorText(row, "tag") != proof.Tag {
			return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
		}
		if NodeChainPrefixMode(node.mode) {
			// The existing exact packet-envelope calculation owns this bound.
			return awgpolicy.HysteriaPacketEnvelope{}, false, nil
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil || !packetPairLayerOff(node) ||
			node.mode == "shadowsocks" && !nodeChainCapturedSSClosure(closure) ||
			node.mode == "hysteria2" && !nodeChainCapturedHysteriaClosure(node, closure) ||
			node.mode != "shadowsocks" && node.mode != "hysteria2" {
			return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
		}
		expected := predecessorCopy(closure.final)
		expected["tag"] = proof.Tag
		if position > 0 {
			expected["detour"] = s.policy.prefix.proofs[position-1].Tag
		}
		if !reflect.DeepEqual(expected, row) {
			return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
		}
		if node.mode == "hysteria2" {
			envelope, err := awgpolicy.CapturedHysteriaPacketEnvelope(packet, all, proof.Tag)
			return envelope, err == nil, err
		}
		if position == 0 {
			// The original physical SS calculation remains responsible here.
			return awgpolicy.HysteriaPacketEnvelope{}, false, nil
		}
		current = row
	}
	return awgpolicy.HysteriaPacketEnvelope{}, false, nodeChainServerCarrierError
}
