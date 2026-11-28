package mobilemultihop

import (
	"encoding/json"
	"reflect"

	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/multihoprelay"
)

// Families4/5 retain separate real UDP ownership for an actual SS-root
// suffix. Ordinary schema2 keeps its original TCP-only contract.
func (s *NodeChainServerPrefixSession) mixedStreamRoot() bool {
	return s != nil && s.policy != nil && (s.policy.record.Schema == 4 || s.policy.record.Schema == 5) &&
		len(s.policy.nodes) > 0 && s.policy.nodes[0] != nil && s.policy.nodes[0].mode == "shadowsocks"
}

func nodeChainPrefixStreamUDPPhysical(node *NodeProfile) (PhysicalEgress, error) {
	tcp, err := nodeChainPrefixStreamPhysical(node, 4)
	if err != nil {
		return PhysicalEgress{}, err
	}
	physical, err := node.PhysicalEgress()
	if err != nil {
		return PhysicalEgress{}, err
	}
	for _, target := range physical {
		if target.Network == "udp" && target.Host == tcp.Host && target.Port == tcp.Port {
			return target, nil
		}
	}
	return PhysicalEgress{}, nodeChainServerCarrierError
}

func (s *NodeChainServerPrefixSession) mixedStreamCarriersMatch() bool {
	if !s.mixedStreamRoot() || s.carrier == nil || s.udpCarrier == nil ||
		!s.carrier.sealed() || !s.udpCarrier.sealed() || s.carrier == s.udpCarrier ||
		s.mixedCloseGate == nil || cap(s.mixedCloseGate) != 1 {
		return false
	}
	tcp, err := nodeChainPrefixStreamPhysical(s.policy.nodes[0], 4)
	udp, other := nodeChainPrefixStreamUDPPhysical(s.policy.nodes[0])
	if err != nil || other != nil || s.carrier.target != tcp || s.udpCarrier.target != udp ||
		s.carrier.family != 7 || s.udpCarrier.family != 7 ||
		s.carrier.source != s.policy.source || s.udpCarrier.source != s.policy.source ||
		s.carrier.sourceSHA != s.policy.sourceSHA || s.udpCarrier.sourceSHA != s.policy.sourceSHA {
		return false
	}
	a, b := s.carrier.snapshot, s.udpCarrier.snapshot
	return a.NamespaceDevice == b.NamespaceDevice && a.NamespaceInode == b.NamespaceInode &&
		a.InterfaceIndex == b.InterfaceIndex && a.InterfaceName == b.InterfaceName &&
		a.InterfaceAddress == b.InterfaceAddress && a.InterfaceMTU == b.InterfaceMTU &&
		a.SourceAddress == b.SourceAddress
}

func (s *NodeChainServerPrefixSession) mixedStreamPacketBound() (int, error) {
	if !s.mixedStreamCarriersMatch() || s.policy.prefix == nil || s.policy.plan == nil ||
		s.policy.plan.appendSource != s.policy.prefix || len(s.policy.prefix.proofs) == 0 {
		return 0, nodeChainServerCarrierError
	}
	bound := min(s.udpCarrier.snapshot.InterfaceMTU, 9000)
	if s.udpCarrier.snapshot.RouteMTU != 0 {
		bound = min(bound, s.udpCarrier.snapshot.RouteMTU)
	}
	return bound, nil
}

// Retained endpoint MTUs must fit unchanged. A new candidate is admitted later
// on its original request, retaining its own captured Auto or Fixed policy.
func (s *NodeChainServerPrefixSession) validateMixedStreamPacketBounds() error {
	bound, err := s.mixedStreamPacketBound()
	if err != nil {
		return err
	}
	all, packets, err := nodeChainPrefixPacketGraph(s.policy.prefix.config)
	if err != nil {
		return err
	}
	physicalPackets := 0
	for _, packet := range packets {
		requested, err := mtuNumber(packet["mtu"])
		envelope, capacity, physical, other := nodeChainPrefixPacketEnvelope(packet, all, s.policy.prefix.proofs[0].Tag, bound)
		if err != nil || other != nil {
			return nodeChainServerCarrierError
		}
		actual, err := envelope.Capacity(capacity, requested, true)
		if err != nil || actual != requested {
			return nodeChainServerCarrierError
		}
		if physical {
			physicalPackets++
		}
	}
	if physicalPackets == 0 && !nodeChainPrefixHasPacketCandidates(s.policy.record) && s.policy.record.Schema != 5 {
		return nodeChainServerCarrierError
	}
	return nil
}

func nodeChainPrefixPacketGraph(config string) (map[string]map[string]any, []map[string]any, error) {
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return nil, nil, nodeChainServerCarrierError
	}
	all := map[string]map[string]any{}
	packets := []map[string]any{}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, ok := graph[family].([]any)
		if !ok {
			return nil, nil, nodeChainServerCarrierError
		}
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return nil, nil, nodeChainServerCarrierError
			}
			tag := predecessorText(row, "tag")
			if tag == "" || all[tag] != nil {
				return nil, nil, nodeChainServerCarrierError
			}
			all[tag] = row
			if row["type"] == "wireguard" || row["type"] == awgpolicy.Type {
				packets = append(packets, row)
			}
		}
	}
	return all, packets, nil
}

func nodeChainPrefixPacketEnvelope(packet map[string]any, all map[string]map[string]any, rootTag string, physicalBound int) (awgpolicy.PacketEnvelope, int, bool, error) {
	envelope, entry, err := awgpolicy.NestedPacketEnvelope(packet, all)
	if err != nil {
		return awgpolicy.PacketEnvelope{}, 0, false, err
	}
	if entry != nil {
		bound, err := mtuNumber(entry["mtu"])
		return envelope, bound, false, err
	}
	envelope, err = awgpolicy.PhysicalSSPacketEnvelope(packet, all, rootTag)
	return envelope, physicalBound, true, err
}

// The same original source/plan/pair and UDP carrier derive only this new
// candidate's options before its endpoint exists. All retained rows stay exact.
func (s *NodeChainServerPrefixSession) mixedStreamPacketOptions(capture multihoprelay.NodeChainPrefixCandidateCapture, response candidateResponseSource) (string, error) {
	bound, err := s.mixedStreamPacketBound()
	if err != nil || s.policy.BindCapture(capture.Lease) != nil {
		return "", nodeChainServerCarrierError
	}
	pair, err := capture.PacketPair()
	if err != nil {
		return "", err
	}
	original, err := s.policy.candidate(capture)
	if err != nil || !reflect.DeepEqual(original, response) {
		return "", errNodeChainAppendExecution
	}
	for i, expected := range s.policy.record.PacketCandidatePairs {
		if expected != pair || i >= len(s.policy.candidates) || i >= len(s.policy.record.Candidates) ||
			!nodeChainPrefixPacketServerMatches(pair, s.policy.candidates[i]) {
			continue
		}
		input := s.policy.record.Candidates[i]
		options, err := s.policy.prefix.candidatePacketOptions(input)
		if err != nil || options != response.PacketOptions {
			return "", errNodeChainAppendExecution
		}
		config, proofs, err := s.policy.prefix.candidateConfig(input)
		if err != nil || len(proofs) != len(s.policy.prefix.proofs)+1 {
			return "", errNodeChainAppendExecution
		}
		all, _, err := nodeChainPrefixPacketGraph(config)
		if err != nil {
			return "", err
		}
		packet := all[proofs[len(proofs)-1].Tag]
		if packet == nil || packet["type"] != nodeChainPrefixType(pair.Mode) ||
			packet["detour"] != s.policy.prefix.proofs[len(s.policy.prefix.proofs)-1].Tag {
			return "", errNodeChainAppendExecution
		}
		requested, err := mtuNumber(packet["mtu"])
		fixed, fixedErr := fixedMTU(s.policy.candidates[i].profile)
		envelope, capacity, _, envelopeErr := nodeChainPrefixPacketEnvelope(packet, all, s.policy.prefix.proofs[0].Tag, bound)
		if err != nil || fixedErr != nil || envelopeErr != nil || fixed != 0 && requested != fixed {
			return "", nodeChainServerCarrierError
		}
		derived, err := envelope.Capacity(capacity, requested, fixed != 0)
		if err != nil {
			return "", err
		}
		var projected map[string]any
		if exactJSON([]byte(options), &projected, NodeChainInputLimit) != nil {
			return "", errNodeChainAppendExecution
		}
		if actual, err := mtuNumber(projected["mtu"]); err != nil || actual != requested {
			return "", errNodeChainAppendExecution
		}
		projected["mtu"] = float64(derived)
		raw, err := json.Marshal(projected)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	return "", errNodeChainAppendExecution
}
