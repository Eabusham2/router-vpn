package mobilemultihop

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"router-vpn/internal/nativeopenvpn"
)

const externalOpenVPNType = "openvpn-client"

// The graph must be exactly the endpoint produced from the captured inline
// profile, not merely a plausible TLS object with another server or credential.
func externalCapturedOpenVPN(endpoint, captured map[string]any) error {
	bad := errors.New("native OpenVPN endpoint differs from its captured inline profile")
	if !maxFields(captured, "config", "username", "password") {
		return bad
	}
	config, ok := captured["config"].(string)
	if !ok {
		return bad
	}
	credentials := [2]string{}
	for index, field := range []string{"username", "password"} {
		if value, exists := captured[field]; exists {
			credentials[index], ok = value.(string)
			if !ok {
				return bad
			}
		}
	}
	compiled, err := nativeopenvpn.CompileEndpoint(config, credentials[0], credentials[1], predecessorText(endpoint, "tag"), predecessorText(endpoint, "detour"))
	if err != nil {
		return bad
	}
	var expected map[string]any
	if json.Unmarshal([]byte(compiled), &expected) != nil || !reflect.DeepEqual(endpoint, expected) {
		return bad
	}
	return nil
}

func externalOpenVPNRequiresUDP(endpoint map[string]any) bool {
	if strings.HasPrefix(predecessorText(endpoint, "network"), "udp") {
		return true
	}
	servers, _ := endpoint["servers"].([]any)
	for _, raw := range servers {
		server, _ := raw.(map[string]any)
		if strings.HasPrefix(predecessorText(server, "network"), "udp") {
			return true
		}
	}
	return false
}

func externalExitRequiresUDP(endpoint map[string]any, protocol string) bool {
	return protocol == "wireguard" || protocol == "amneziawg" || protocol == "hysteria2" || protocol == "openvpn" && externalOpenVPNRequiresUDP(endpoint)
}

func externalOpenVPNMTU(tun, endpoint map[string]any, mtu, entryMTU, fixed int) (int, error) {
	configured := 1500 // The pinned native TLS client default; not a measurement.
	if raw, exists := endpoint["mtu"]; exists {
		var err error
		configured, err = mtuNumber(raw)
		if err != nil {
			return 0, err
		}
	}
	if fixed != 0 {
		configured = fixed
	}
	if entryMTU != 0 && externalOpenVPNRequiresUDP(endpoint) {
		if fragment, _ := endpoint["fragment"].(float64); fragment > 0 {
			// Native fragment bounds its OpenVPN datagram, including data
			// framing/cipher overhead. Reserve IPv6 plus UDP outside that.
			if fragment > float64(entryMTU-48) {
				return 0, errors.New("captured OpenVPN fragments exceed the entry packet MTU")
			}
		} else {
			// Upper bound for every permitted data cipher/MAC: opcode/peer
			// 4 + packet ID 4 + IV 16 + SHA512 64 + block padding 16 +
			// optional stub/fragment framing 6 + IPv6/UDP 48 = 158 bytes.
			// This is a conservative configured bound, never an Auto result.
			limit := entryMTU - 160
			if limit < 1280 {
				return 0, errors.New("entry packet MTU cannot carry the selected unfragmented OpenVPN UDP path")
			}
			if configured > limit {
				if fixed != 0 {
					return 0, errors.New("fixed OpenVPN exit MTU does not fit its captured packet entry")
				}
				configured = limit
			}
		}
	}
	endpoint["mtu"] = configured
	if fixed == 0 && mtu > configured {
		mtu = configured
	}
	tun["mtu"] = mtu
	return mtu, nil
}
