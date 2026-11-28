package awgpolicy

import (
	"errors"
	"net/netip"
)

// HysteriaPacketEnvelope is the complete UDP message payload delivered to the
// original HY2 session. It excludes the physical IP/UDP headers: native HY2
// fragments that payload into QUIC datagrams and reconstructs it at its peer.
// The pinned sing-quic v0.7.0 hysteria2/internal/protocol/proxy.go limits that
// complete payload to 4096 bytes before fragmentation.
type HysteriaPacketEnvelope struct {
	dataOverhead int
	controlMax   int
	bound        bool
}

const hysteriaPacketMessageLimit = 4096

// CapturedHysteriaPacketEnvelope follows the actual captured datagram edges.
// It grants no socket, physical MTU, source identity or native session owner.
func CapturedHysteriaPacketEnvelope(packet map[string]any, all map[string]map[string]any, boundaryTag string) (HysteriaPacketEnvelope, error) {
	return CapturedHysteriaPacketEnvelopeWithHostnameFamilies(packet, all, boundaryTag, nil)
}

func CapturedHysteriaPacketEnvelopeWithHostnameFamilies(packet map[string]any, all map[string]map[string]any, boundaryTag string, ipv4Only map[string]bool) (HysteriaPacketEnvelope, error) {
	bad := errors.New("invalid captured HY2 packet message envelope")
	if packet == nil || packet["type"] != "wireguard" && packet["type"] != Type || boundaryTag == "" {
		return HysteriaPacketEnvelope{}, bad
	}
	boundary := all[boundaryTag]
	if boundary == nil || boundary["tag"] != boundaryTag || boundary["type"] != "hysteria2" {
		return HysteriaPacketEnvelope{}, bad
	}
	server, ok := boundary["server"].(string)
	address, err := netip.ParseAddr(server)
	if !ok || err != nil || address.Zone() != "" || address.Is4In6() {
		return HysteriaPacketEnvelope{}, bad
	}
	if _, err := packetCarrierPort(boundary["server_port"]); err != nil {
		return HysteriaPacketEnvelope{}, bad
	}
	tag, ok := packet["tag"].(string)
	if !ok || tag == "" || tag == boundaryTag {
		return HysteriaPacketEnvelope{}, bad
	}
	seen := map[string]bool{tag: true}
	layers := []map[string]any{}
	current := packet
	for {
		next, ok := current["detour"].(string)
		if !ok || next == "" || seen[next] {
			return HysteriaPacketEnvelope{}, bad
		}
		seen[next] = true
		layer := all[next]
		if layer == nil || layer["tag"] != next {
			return HysteriaPacketEnvelope{}, bad
		}
		if next == boundaryTag {
			break
		}
		if layer["type"] != "shadowsocks" && layer["type"] != "routervpn-aes-xor" {
			return HysteriaPacketEnvelope{}, bad
		}
		layers = append(layers, layer)
		current = layer
	}
	// Reuse the exact WG/AWG padding, handshake/junk, SS2022 address, key,
	// reply and port-53 padding arithmetic. Its final IP/UDP header belongs
	// to a physical datagram, so remove exactly that captured family's bytes.
	envelope, err := packetCarriersEnvelopeWithHostnameFamilies(packet, layers, ipv4Only)
	if err != nil {
		return HysteriaPacketEnvelope{}, err
	}
	peer := packet["peers"].([]any)[0].(map[string]any)
	outer, _ := peer["address"].(string)
	var outerTag string
	if len(layers) != 0 {
		outer, _ = layers[len(layers)-1]["server"].(string)
		outerTag, _ = layers[len(layers)-1]["tag"].(string)
	}
	ip, err := netip.ParseAddr(outer)
	ipv6 := ip.Is6()
	if err != nil {
		onlyIPv4, captured := ipv4Only[outerTag]
		if !captured {
			return HysteriaPacketEnvelope{}, bad
		}
		ipv6 = !onlyIPv4
	}
	ipUDP := 28
	if ipv6 {
		ipUDP = 48
	}
	return HysteriaPacketEnvelope{dataOverhead: envelope.DataOverhead - ipUDP,
		controlMax: envelope.ControlMax - ipUDP, bound: true}, nil
}

// Capacity is a native message-size bound, not physical PMTU discovery.
// Fixed must fit unchanged; Auto can only reduce the original packet cap.
func (e HysteriaPacketEnvelope) Capacity(requested int, fixed bool) (int, error) {
	if !e.bound || requested < 1280 || requested > 9000 || e.dataOverhead < 32 ||
		e.dataOverhead > hysteriaPacketMessageLimit || e.controlMax < 148 || e.controlMax > hysteriaPacketMessageLimit {
		return 0, errors.New("captured HY2 cannot carry the packet data or control envelope")
	}
	limit := (hysteriaPacketMessageLimit - e.dataOverhead) / 16 * 16
	if limit < 1280 || fixed && requested > limit {
		return 0, errors.New("captured packet MTU exceeds the HY2 message bound")
	}
	return min(requested, limit), nil
}
