package awgpolicy

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
)

// EndpointEnvelope reads a compiled WG/AWG endpoint and its optional single
// authenticated Start Layer. It does not mutate captured configuration.
func EndpointEnvelope(endpoint, layer map[string]any) (PacketEnvelope, error) {
	bad := errors.New("packet envelope requires an exact WG/AWG peer and Start Layer")
	if endpoint == nil || endpoint["type"] != "wireguard" && endpoint["type"] != Type {
		return PacketEnvelope{}, bad
	}
	peers, ok := endpoint["peers"].([]any)
	if !ok || len(peers) != 1 {
		return PacketEnvelope{}, bad
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return PacketEnvelope{}, bad
	}
	address, ok := peer["address"].(string)
	if !ok {
		return PacketEnvelope{}, bad
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" || ip.Is4In6() {
		return PacketEnvelope{}, bad
	}
	var params map[string]string
	if endpoint["type"] == Type {
		raw, ok := endpoint["amnezia"].(map[string]any)
		if !ok {
			return PacketEnvelope{}, bad
		}
		params = map[string]string{}
		for k, v := range raw {
			s, ok := v.(string)
			if !ok {
				return PacketEnvelope{}, bad
			}
			params[k] = s
		}
	}
	layerBytes := 0
	if layer != nil {
		if layer["type"] != "shadowsocks" && layer["type"] != "routervpn-aes-xor" || layer["method"] != "2022-blake3-aes-256-gcm" || endpoint["detour"] != layer["tag"] {
			return PacketEnvelope{}, bad
		}
		server, ok := layer["server"].(string)
		if !ok {
			return PacketEnvelope{}, bad
		}
		carrier, err := netip.ParseAddr(server)
		if err != nil || carrier.Zone() != "" || carrier.Is4In6() {
			return PacketEnvelope{}, bad
		}
		password, ok := layer["password"].(string)
		if !ok {
			return PacketEnvelope{}, bad
		}
		keys := strings.Split(password, ":")
		if len(keys) > 64 {
			return PacketEnvelope{}, bad
		}
		for _, s := range keys {
			b, e := base64.StdEncoding.Strict().DecodeString(s)
			valid := e == nil && len(b) == 32
			clear(b)
			if !valid {
				return PacketEnvelope{}, bad
			}
		}
		addressBytes := 7
		if ip.Is6() {
			addressBytes = 19
		}
		layerBytes = max(43+addressBytes+16*(len(keys)-1), 51+addressBytes)
		ip = carrier
	}
	return Envelope(params, ip.Is6(), layerBytes)
}
