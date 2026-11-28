package awgpolicy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

// NestedPacketEnvelope follows only the captured datagram carrier edges between
// a WG/AWG endpoint and its preceding WG/AWG interface. Other native transport
// families retain their own MTU validators. The returned map is the original
// predecessor, never a proxy's unrelated TUN baseline or historical measurement.
func NestedPacketEnvelope(packet map[string]any, all map[string]map[string]any) (PacketEnvelope, map[string]any, error) {
	return nestedPacketEnvelope(packet, all, nil)
}

// PhysicalSSPacketEnvelope calculates only the literal SS2022 datagram path
// ending at the caller's exact root tag. It grants no route, MTU observation or
// native owner. The ordinary nested-packet API keeps its existing semantics.
func PhysicalSSPacketEnvelope(packet map[string]any, all map[string]map[string]any, rootTag string) (PacketEnvelope, error) {
	bad := errors.New("invalid captured physical SS2022 packet path")
	if packet == nil || packet["type"] != "wireguard" && packet["type"] != Type || rootTag == "" {
		return PacketEnvelope{}, bad
	}
	tag, ok := packet["tag"].(string)
	if !ok || tag == "" || tag == rootTag {
		return PacketEnvelope{}, bad
	}
	root := all[rootTag]
	if root == nil || root["tag"] != rootTag || root["type"] != "shadowsocks" {
		return PacketEnvelope{}, bad
	}
	seen := map[string]bool{tag: true}
	layers := []map[string]any{}
	current := packet
	for {
		next, ok := current["detour"].(string)
		if !ok || next == "" || seen[next] || len(seen) >= 16 {
			return PacketEnvelope{}, bad
		}
		layer := all[next]
		if layer == nil || layer["tag"] != next || layer["type"] != "shadowsocks" {
			return PacketEnvelope{}, bad
		}
		seen[next] = true
		layers = append(layers, layer)
		if next == rootTag {
			if detour, exists := layer["detour"]; exists && detour != "" {
				return PacketEnvelope{}, bad
			}
			return packetCarriersEnvelope(packet, layers)
		}
		current = layer
	}
}

// The caller must own the captured hostname resolver policy. This pure
// arithmetic input grants no endpoint, DNS, route or execution authority.
// True means enforced IPv4-only; false reserves the IPv6 worst case.
func NestedPacketEnvelopeWithHostnameFamilies(packet map[string]any, all map[string]map[string]any, ipv4Only map[string]bool) (PacketEnvelope, map[string]any, error) {
	return nestedPacketEnvelope(packet, all, ipv4Only)
}

func nestedPacketEnvelope(packet map[string]any, all map[string]map[string]any, ipv4Only map[string]bool) (PacketEnvelope, map[string]any, error) {
	bad := errors.New("invalid captured packet carrier path")
	if packet == nil || packet["type"] != "wireguard" && packet["type"] != Type {
		return PacketEnvelope{}, nil, bad
	}
	tag, ok := packet["tag"].(string)
	if !ok || tag == "" {
		return PacketEnvelope{}, nil, bad
	}
	seen := map[string]bool{tag: true}
	layers := []map[string]any{}
	current := packet
	for {
		next, exists := current["detour"]
		if !exists || next == "" {
			return PacketEnvelope{}, nil, nil
		}
		id, ok := next.(string)
		if !ok || seen[id] || len(seen) >= 16 {
			return PacketEnvelope{}, nil, bad
		}
		entry := all[id]
		if entry == nil || entry["tag"] != id {
			return PacketEnvelope{}, nil, bad
		}
		seen[id] = true
		switch entry["type"] {
		case "wireguard", Type:
			envelope, err := packetCarriersEnvelopeWithHostnameFamilies(packet, layers, ipv4Only)
			return envelope, entry, err
		case "shadowsocks", "routervpn-aes-xor":
			layers = append(layers, entry)
			current = entry
		default:
			return PacketEnvelope{}, nil, nil
		}
	}
}

// The pinned sing-shadowsocks v0.2.8 shadowaead_2022 packet writers use a
// 16-byte session/packet header, type(1), timestamp(8), padding length(2),
// literal SOCKS address(7/19), and authentication tag(16). Client AES identity
// headers add 16 bytes per extra key; replies add a remote session ID(8).
// ChaCha uses a 24-byte nonce and exactly one key. Port 53 pads payloads below
// 900 bytes, including control messages. Each wrapper adds these bytes to the
// previous payload; only the outermost destination contributes IP/UDP headers.
func packetCarriersEnvelope(packet map[string]any, layers []map[string]any) (PacketEnvelope, error) {
	return packetCarriersEnvelopeWithHostnameFamilies(packet, layers, nil)
}

func packetCarriersEnvelopeWithHostnameFamilies(packet map[string]any, layers []map[string]any, ipv4Only map[string]bool) (PacketEnvelope, error) {
	bad := errors.New("invalid captured SS2022 packet envelope")
	envelope, err := EndpointEnvelope(packet, nil)
	if err != nil {
		return PacketEnvelope{}, err
	}
	peer := packet["peers"].([]any)[0].(map[string]any)
	ip, _ := netip.ParseAddr(peer["address"].(string))
	port, err := packetCarrierPort(peer["port"])
	if err != nil && len(layers) != 0 {
		return PacketEnvelope{}, err
	}
	ipv6 := ip.Is6()
	ipUDP := func(isIPv6 bool) int {
		if isIPv6 {
			return 48
		}
		return 28
	}
	envelope.DataOverhead -= ipUDP(ipv6)
	envelope.ControlMax -= ipUDP(ipv6)
	for _, layer := range layers {
		method, _ := layer["method"].(string)
		keySize, nonce := 32, 0
		switch method {
		case "2022-blake3-aes-128-gcm":
			keySize = 16
		case "2022-blake3-aes-256-gcm":
		case "2022-blake3-chacha20-poly1305":
			nonce = 24
		default:
			return PacketEnvelope{}, bad
		}
		if layer["type"] == "routervpn-aes-xor" && method != "2022-blake3-aes-256-gcm" ||
			!packetCarrierUDPNetwork(layer["network"]) || !packetCarrierUOTDisabled(layer["udp_over_tcp"]) {
			return PacketEnvelope{}, bad
		}
		password, ok := layer["password"].(string)
		if !ok || password == "" || len(password) > 4096 {
			return PacketEnvelope{}, bad
		}
		keys := strings.Split(password, ":")
		if len(keys) > 64 || nonce != 0 && len(keys) != 1 {
			return PacketEnvelope{}, bad
		}
		for _, key := range keys {
			decoded, failure := base64.StdEncoding.Strict().DecodeString(key)
			valid := failure == nil && len(decoded) == keySize
			clear(decoded)
			if !valid {
				return PacketEnvelope{}, bad
			}
		}
		addressBytes := 7
		if ipv6 {
			addressBytes = 19
		}
		overhead := nonce + max(43+addressBytes+16*(len(keys)-1), 51+addressBytes)
		envelope.DataOverhead += overhead
		if port == 53 {
			envelope.ControlMax = max(envelope.ControlMax, 900)
		}
		envelope.ControlMax += overhead
		server, ok := layer["server"].(string)
		if !ok {
			return PacketEnvelope{}, bad
		}
		ip, err = netip.ParseAddr(server)
		if err != nil {
			tag, _ := layer["tag"].(string)
			onlyIPv4, captured := ipv4Only[tag]
			if !captured || layer["type"] != "shadowsocks" || layer["domain_resolver"] == nil {
				return PacketEnvelope{}, bad
			}
			ipv6 = !onlyIPv4
		} else {
			if ip.Zone() != "" || ip.Is4In6() {
				return PacketEnvelope{}, bad
			}
			ipv6 = ip.Is6()
		}
		port, err = packetCarrierPort(layer["server_port"])
		if err != nil {
			return PacketEnvelope{}, err
		}
	}
	envelope.DataOverhead += ipUDP(ipv6)
	envelope.ControlMax += ipUDP(ipv6)
	return envelope, nil
}

// Match the pinned native NetworkList JSON forms, including its empty-list
// default, without confusing the invalid literal empty string with that default.
func packetCarrierUDPNetwork(raw any) bool {
	if raw == nil {
		return true
	}
	var values []any
	switch value := raw.(type) {
	case string:
		values = []any{value}
	case []any:
		values = value
	case []string:
		for _, item := range value {
			values = append(values, item)
		}
	default:
		return false
	}
	udp := len(values) == 0
	for _, value := range values {
		if value == "udp" {
			udp = true
		} else if value != "tcp" {
			return false
		}
	}
	return udp
}

// UDPOverTCPOptions accepts a bool or a strict {enabled,version} object.
// A disabled option preserves ordinary datagrams; an enabled option must never
// acquire packet-envelope authority through a TCP-only carrier calculation.
func packetCarrierUOTDisabled(raw any) bool {
	if raw == nil || raw == false {
		return true
	}
	value, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	for key, item := range value {
		switch key {
		case "enabled":
			if item != nil && item != false {
				return false
			}
		case "version":
			if item == nil {
				continue
			}
			var n int64
			switch v := item.(type) {
			case int:
				n = int64(v)
			case float64:
				n = int64(v)
				if float64(n) != v {
					return false
				}
			case json.Number:
				var err error
				n, err = v.Int64()
				if err != nil {
					return false
				}
			default:
				return false
			}
			if n < 0 || n > 255 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func packetCarrierPort(raw any) (int, error) {
	var port int
	switch value := raw.(type) {
	case int:
		port = value
	case float64:
		port = int(value)
		if float64(port) != value {
			port = 0
		}
	case json.Number:
		number, err := value.Int64()
		if err == nil && number >= 1 && number <= 65535 {
			port = int(number)
		}
	}
	if port < 1 || port > 65535 {
		return 0, errors.New("packet carrier requires its original literal destination port")
	}
	return port, nil
}
