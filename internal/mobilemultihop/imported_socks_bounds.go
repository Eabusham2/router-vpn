package mobilemultihop

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"router-vpn/internal/awgpolicy"
	"strings"
)

// SOCKSPacketBounds describes serialization only. It is neither an observed
// physical path MTU nor permission to enlarge a captured TUN/packet endpoint.
type SOCKSPacketBounds struct{ DataMax, ControlMax, IPUDPBytes, UDPPayloadMax int }

// ImportedSOCKSPacketBounds accounts for both captured SS2022 layers around a
// WG/AWG final and the intervening SOCKS UDP header. The authenticated relay's
// address is learned at runtime, so its largest supported address encoding and
// possible port-53 padding are included instead of assuming a particular reply.
func ImportedSOCKSPacketBounds(config string) (SOCKSPacketBounds, error) {
	bad := errors.New("both-layer SOCKS packet serialization is not fully captured")
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return SOCKSPacketBounds{}, bad
	}
	nodes := map[string]map[string]any{}
	for _, family := range []string{"outbounds", "endpoints"} {
		rows, _ := graph[family].([]any)
		for _, r := range rows {
			n, ok := r.(map[string]any)
			if !ok {
				return SOCKSPacketBounds{}, bad
			}
			tag := predecessorText(n, "tag")
			if tag == "" || nodes[tag] != nil {
				return SOCKSPacketBounds{}, bad
			}
			nodes[tag] = n
		}
	}
	packet, entry := nodes[LocalTag], nodes["entry-wg"]
	if packet == nil || entry == nil || entry["type"] != "socks" {
		return SOCKSPacketBounds{}, bad
	}
	outer, carrier := nodes[predecessorText(packet, "detour")], nodes[predecessorText(entry, "detour")]
	if outer == nil || carrier == nil || predecessorText(packet, "detour") == predecessorText(entry, "detour") || outer["detour"] != "entry-wg" || predecessorText(carrier, "detour") != "" {
		return SOCKSPacketBounds{}, bad
	}
	env, err := awgpolicy.EndpointEnvelope(packet, nil)
	if err != nil {
		return SOCKSPacketBounds{}, err
	}
	peers := packet["peers"].([]any)
	peer := peers[0].(map[string]any)
	innerIP, err := netip.ParseAddr(predecessorText(peer, "address"))
	if err != nil || !innerIP.IsPrivate() || innerIP.IsLoopback() {
		return SOCKSPacketBounds{}, bad
	}
	finalIP, err := netip.ParseAddr(predecessorText(outer, "server"))
	if err != nil || finalIP.Is4In6() || finalIP.Zone() != "" {
		return SOCKSPacketBounds{}, bad
	}
	physicalIP, err := netip.ParseAddr(predecessorText(carrier, "server"))
	if err != nil || physicalIP.Is4In6() || physicalIP.Zone() != "" {
		return SOCKSPacketBounds{}, bad
	}
	addressBytes := func(ip netip.Addr) int {
		if ip.Is6() {
			return 19
		}
		return 7
	}
	ipUDP := func(ip netip.Addr) int {
		if ip.Is6() {
			return 48
		}
		return 28
	}
	header := func(layer map[string]any, addr int) (int, error) {
		if layer["type"] != "shadowsocks" && layer["type"] != "routervpn-aes-xor" || layer["method"] != NativeStartLayerMethod {
			return 0, bad
		}
		password := predecessorText(layer, "password")
		if password == "" || len(password) > 4096 {
			return 0, bad
		}
		keys := strings.Split(password, ":")
		for _, key := range keys {
			raw, e := base64.StdEncoding.Strict().DecodeString(key)
			valid := e == nil && len(raw) == 32
			clear(raw)
			if !valid {
				return 0, bad
			}
		}
		return max(43+addr+16*(len(keys)-1), 51+addr), nil
	}
	finalHeader, err := header(outer, addressBytes(innerIP))
	if err != nil {
		return SOCKSPacketBounds{}, err
	}
	// ATYP + maximum 255-byte domain length/value + uint16 port: 259 bytes.
	// Numeric private replies are smaller, but no unauthenticated reply is assumed.
	entryHeader, err := header(carrier, 259)
	if err != nil {
		return SOCKSPacketBounds{}, err
	}
	mtu, err := mtuNumber(packet["mtu"])
	if err != nil {
		return SOCKSPacketBounds{}, err
	}
	port, ok := exactStartPort(peer["port"])
	if !ok {
		return SOCKSPacketBounds{}, bad
	}
	data := (mtu+15)/16*16 + env.DataOverhead - ipUDP(innerIP)
	control := env.ControlMax - ipUDP(innerIP)
	if port == 53 {
		control = max(control, 900)
	}
	data += finalHeader
	control += finalHeader
	socksHeader := 3 + addressBytes(finalIP)
	data += socksHeader
	control += socksHeader
	// The original authenticated SOCKS association may choose relay port 53.
	control = max(control, 900)
	data += entryHeader
	control += entryHeader
	limit := 65507 // IPv4 total length also contains its 20-byte IP header.
	if physicalIP.Is6() {
		limit = 65527
	} // IPv6 payload length includes the UDP header; no jumbogram.
	if data > limit || control > limit {
		return SOCKSPacketBounds{}, errors.New("captured layers exceed native UDP serialization capacity")
	}
	return SOCKSPacketBounds{data + ipUDP(physicalIP), control + ipUDP(physicalIP), ipUDP(physicalIP), limit}, nil
}
