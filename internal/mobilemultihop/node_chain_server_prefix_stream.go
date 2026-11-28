package mobilemultihop

import "router-vpn/internal/multihoprelay"

// The new execution family is the recursive SS tail of an actual packet
// prefix. A later packet, another proxy family or a synthetic entry is refused.
func nodeChainPrefixLocalSchema(nodes []*NodeProfile) (int, error) {
	if len(nodes) < 1 || len(nodes) > multihoprelay.NodeChainPrefixMaximumMembers || nodes[0] == nil || !NodeChainPrefixMode(nodes[0].mode) {
		return 0, errNodeChainAppendExecution
	}
	schema := 1
	for _, node := range nodes {
		if node == nil || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
			return 0, errNodeChainAppendExecution
		}
		if NodeChainPrefixMode(node.mode) {
			if schema != 1 {
				return 0, errNodeChainAppendExecution
			}
			continue
		}
		closure, err := nodeMultihopPredecessor(node)
		if node.mode != "shadowsocks" || err != nil || !nodeChainCapturedSSClosure(closure) {
			return 0, errNodeChainAppendExecution
		}
		schema = 2
	}
	return schema, nil
}

func nodeChainPrefixCapturedMember(node *NodeProfile, identity string, position, schema int) (multihoprelay.NodeChainPrefixMember, error) {
	if schema == 7 {
		if position == 0 {
			return nodeChainPrefixProxyEntryMember(node, identity)
		}
		if node == nil || node.mode != "shadowsocks" {
			return multihoprelay.NodeChainPrefixMember{}, errNodeChainAppendExecution
		}
		return nodeChainPrefixCapturedMember(node, identity, position, 2)
	}
	if node == nil || validateNodeChainIdentity(identity, node) != nil {
		return multihoprelay.NodeChainPrefixMember{}, errNodeChainAppendExecution
	}
	if NodeChainPrefixMode(node.mode) {
		return nodeChainPrefixPacketMember(node, position)
	}
	if (schema == 5 || schema == 6) && node.mode == "hysteria2" {
		return nodeChainPrefixHysteriaMember(node, identity, position)
	}
	closure, err := nodeMultihopPredecessor(node)
	if schema != 2 && schema != 4 && schema != 5 && schema != 6 || position < 1 || node.mode != "shadowsocks" || err != nil || !packetPairLayerOff(node) ||
		node.validateNodeDesktopCapture() != nil || !nodeChainCapturedSSClosure(closure) {
		return multihoprelay.NodeChainPrefixMember{}, errNodeChainAppendExecution
	}
	files, err := nodeProfileAssets(identity)
	if err != nil {
		return multihoprelay.NodeChainPrefixMember{}, err
	}
	defer clearNodeChainIdentityAssets(files)
	companion, err := nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-ss-companion-v1", files)
	if err != nil {
		return multihoprelay.NodeChainPrefixMember{}, err
	}
	client, server, err := chainCompanionKeys(identity, node.profile)
	if err != nil {
		return multihoprelay.NodeChainPrefixMember{}, err
	}
	return multihoprelay.NodeChainPrefixMember{Position: position, ProfileID: predecessorText(node.profile, "id"), NodeID: predecessorText(node.profile, "node_proof_id"),
		Mode: "shadowsocks", StartLayer: "off", SourceSHA256: node.source, TransportSHA256: externalDigest([]byte(node.config)),
		CompanionSHA256: companion, CompanionClientPublicKey: client, CompanionServerPublicKey: server}, nil
}

// The source retains the real SS TCP and UDP tuple. This helper returns its
// TCP tuple; schema4 separately captures the same original source's UDP tuple.
func nodeChainPrefixStreamPhysical(node *NodeProfile, schema int) (PhysicalEgress, error) {
	if schema != 2 && schema != 4 && schema != 5 && schema != 6 && schema != 7 || node == nil || node.mode != "shadowsocks" || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
		return PhysicalEgress{}, errNodeChainAppendExecution
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil || !nodeChainCapturedSSClosure(closure) {
		return PhysicalEgress{}, errNodeChainAppendExecution
	}
	physical, err := node.PhysicalEgress()
	if err != nil || len(physical) != 2 {
		return PhysicalEgress{}, errNodeChainAppendExecution
	}
	var tcp, udp PhysicalEgress
	for _, target := range physical {
		switch target.Network {
		case "tcp":
			if tcp.Network != "" {
				return PhysicalEgress{}, errNodeChainAppendExecution
			}
			tcp = target
		case "udp":
			if udp.Network != "" {
				return PhysicalEgress{}, errNodeChainAppendExecution
			}
			udp = target
		default:
			return PhysicalEgress{}, errNodeChainAppendExecution
		}
	}
	if tcp.Network != "tcp" || udp.Network != "udp" || tcp.Host != udp.Host || tcp.Port != udp.Port {
		return PhysicalEgress{}, errNodeChainAppendExecution
	}
	return tcp, nil
}
