package mobilemultihop

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
)

// WireGuardClientPublicKey derives the canonical public identity from the
// validated private node capture. Different clamped private-key encodings
// cannot authorize a second Server peer with the same WireGuard identity.
// Neither returned errors nor public capabilities expose the private key.
func (p *NodeProfile) WireGuardClientPublicKey() (string, error) {
	bad := errors.New("native WireGuard exit has no exact captured client identity")
	if p == nil || p.mode != "wg" {
		return "", bad
	}
	var graph map[string]any
	if exactJSON([]byte(p.config), &graph, 4<<20) != nil {
		return "", bad
	}
	endpoints, ok := graph["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return "", bad
	}
	endpoint, ok := endpoints[0].(map[string]any)
	if !ok || endpoint["tag"] != "proxy" || endpoint["type"] != "wireguard" {
		return "", bad
	}
	encoded, ok := endpoint["private_key"].(string)
	if !ok {
		return "", bad
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	defer clear(raw)
	if err != nil || len(raw) != 32 {
		return "", bad
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", bad
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// A WG packet normally needs its 32-byte transport header plus outer IP/UDP.
// With a native Start Layer it also carries SS2022's authenticated datagram
// envelope and the private destination address. XOR preserves that length.
// The public outer address determines IPv4/IPv6 overhead, not the rewritten
// private WireGuard service address. This is a configured bound, not PMTU proof.
func nodeWireGuardPacketEnvelope(exit *externalPredecessor, mode string) (int, error) {
	if mode != "wg" {
		return 0, nil
	}
	bad := errors.New("WireGuard exit Start Layer lost its captured packet envelope")
	if exit == nil || exit.final == nil {
		return 0, bad
	}
	if exit.final["detour"] == nil {
		return 0, nil
	}
	layer := exit.nodes[NativeStartLayerTag]
	if exit.final["type"] != "wireguard" || exit.final["detour"] != NativeStartLayerTag || layer == nil ||
		(layer["type"] != "shadowsocks" && layer["type"] != "routervpn-aes-xor") || layer["method"] != NativeStartLayerMethod {
		return 0, bad
	}
	outer, err := netip.ParseAddr(predecessorText(layer, "server"))
	if err != nil || outer.Zone() != "" || outer.Is4In6() {
		return 0, bad
	}
	peers, ok := exit.final["peers"].([]any)
	if !ok || len(peers) != 1 {
		return 0, bad
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return 0, bad
	}
	inner, err := netip.ParseAddr(predecessorText(peer, "address"))
	if err != nil || inner.Zone() != "" || inner.Is4In6() {
		return 0, bad
	}
	addressBytes, packet := 7, 60
	if inner.Is6() {
		addressBytes = 19
	}
	if outer.Is6() {
		packet = 80
	}
	keys := strings.Split(predecessorText(layer, "password"), ":")
	if len(keys) == 0 || len(keys) > 64 {
		return 0, bad
	}
	for _, encoded := range keys {
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		valid := err == nil && len(key) == 32
		clear(key)
		if !valid {
			return 0, bad
		}
	}
	request, response := 43+addressBytes+16*(len(keys)-1), 51+addressBytes
	if response > request {
		request = response
	}
	return packet + request, nil
}
