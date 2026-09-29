package mobilemultihop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CompileWireGuardProfile converts a bounded generated wg-quick profile into a
// native userspace endpoint. No shell directives, host routes, DNS lookups or
// second OS VPN are executed. The peer key must match the frozen paired node.
// This output contains private keys: it is configuration, never status/log data.
func CompileWireGuardProfile(config, expectedNodeID string) (string, error) {
	profile, err := parseWireGuardProfile(config, expectedNodeID)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(profile)
	return string(encoded), err
}

type wireGuardProfile struct {
	Endpoint map[string]any `json:"endpoint"`
	DNS      []string       `json:"dns"`
}

// WireGuardExitConfig supplies the full-device graph consumed by the existing
// Android/Apple multihop composer. The composer subsequently adds the entry
// detour, frozen DNS/IPv6/LAN/MTU policies and independent proof lanes.
func WireGuardExitConfig(config, expectedNodeID string) (string, error) {
	profile, err := parseWireGuardProfile(config, expectedNodeID)
	if err != nil {
		return "", err
	}
	return nativeExitConfig(profile)
}

func nativeExitConfig(profile wireGuardProfile) (string, error) {
	if len(profile.DNS) != 1 {
		return "", errors.New("WireGuard exit requires one literal selected DNS resolver")
	}
	profile.Endpoint["tag"] = "proxy"
	root := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true,
			"stack": "system", "mtu": 1280,
			"address": []string{"172.29.94.1/30", "fd29:94::1/126"},
		}},
		"endpoints": []any{profile.Endpoint}, "outbounds": []any{},
		"dns": map[string]any{
			"servers": []any{map[string]any{"type": "udp", "tag": "selected-dns", "server": profile.DNS[0], "server_port": 53, "detour": "proxy"}},
			"final":   "selected-dns",
		},
		"route": map[string]any{"final": "proxy", "auto_detect_interface": true,
			"rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}},
	}
	encoded, err := json.Marshal(root)
	return string(encoded), err
}

func parseWireGuardProfile(config, expectedNodeID string) (wireGuardProfile, error) {
	bad := errors.New("invalid bounded WireGuard profile for the paired node")
	fail := func() (wireGuardProfile, error) { return wireGuardProfile{}, bad }
	if len(config) == 0 || len(config) > 1024*1024 || !utf8.ValidString(config) || !proofID.MatchString(expectedNodeID) {
		return fail()
	}
	for _, r := range config {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' || r == 0x7f {
			return fail()
		}
	}
	iface, peer := map[string]string{}, map[string]string{}
	var current map[string]string
	interfaces, peers := 0, 0
	allowedInterface := map[string]bool{"privatekey": true, "address": true, "dns": true, "mtu": true, "listenport": true}
	allowedPeer := map[string]bool{"publickey": true, "presharedkey": true, "endpoint": true, "allowedips": true, "persistentkeepalive": true}
	for _, raw := range strings.Split(config, "\n") {
		if len(raw) > 16384 {
			return fail()
		}
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "[interface]":
			interfaces++
			if interfaces != 1 || peers != 0 {
				return fail()
			}
			current = iface
			continue
		case "[peer]":
			peers++
			if interfaces != 1 || peers > 1 {
				return fail()
			}
			current = peer
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		allowed := allowedInterface
		if peers == 1 {
			allowed = allowedPeer
		}
		if !ok || current == nil || !allowed[key] || value == "" {
			return fail()
		}
		if _, exists := current[key]; exists {
			return fail()
		}
		current[key] = value
	}
	if interfaces != 1 || peers != 1 || !validWGKey(iface["privatekey"]) || !validWGKey(peer["publickey"]) {
		return fail()
	}
	proof := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + peer["publickey"]))
	if hex.EncodeToString(proof[:]) != expectedNodeID {
		return wireGuardProfile{}, errors.New("WireGuard peer does not match the paired node identity")
	}
	if psk, ok := peer["presharedkey"]; ok && !validWGKey(psk) {
		return fail()
	}
	addresses, ok := wireGuardPrefixes(iface["address"], false)
	if !ok {
		return fail()
	}
	allowed, ok := wireGuardPrefixes(peer["allowedips"], true)
	if !ok || len(allowed) != 2 || !(allowed[0] == "0.0.0.0/0" && allowed[1] == "::/0" || allowed[1] == "0.0.0.0/0" && allowed[0] == "::/0") {
		return wireGuardProfile{}, errors.New("full-device WireGuard hops require both IPv4 and IPv6 default routes")
	}
	host, portText, err := net.SplitHostPort(peer["endpoint"])
	if err != nil || !wireGuardServerIP(host) {
		return wireGuardProfile{}, errors.New("WireGuard hop requires a literal unicast endpoint; no direct DNS bootstrap")
	}
	port, err := wireGuardNumber(portText, 1, 65535)
	if err != nil {
		return fail()
	}
	mtu := 1280
	if text, exists := iface["mtu"]; exists {
		mtu, err = wireGuardNumber(text, 1280, 9000)
		if err != nil {
			return fail()
		}
	}
	remote := map[string]any{"address": host, "port": port, "public_key": peer["publickey"], "allowed_ips": allowed}
	if psk := peer["presharedkey"]; psk != "" {
		remote["pre_shared_key"] = psk
	}
	// This field exists in the exact pinned 1.14.1 WireGuardPeer schema. Keep
	// it rather than silently dropping the generated persistent keepalive.
	if text, exists := peer["persistentkeepalive"]; exists {
		keepalive, err := wireGuardNumber(text, 0, 65535)
		if err != nil {
			return fail()
		}
		remote["persistent_keepalive_interval"] = keepalive
	}
	endpoint := map[string]any{"type": "wireguard", "system": false, "private_key": iface["privatekey"], "address": addresses, "mtu": mtu, "peers": []any{remote}}
	if text, exists := iface["listenport"]; exists {
		port, err := wireGuardNumber(text, 0, 65535)
		if err != nil {
			return fail()
		}
		endpoint["listen_port"] = port
	}
	dns := []string{}
	if text, exists := iface["dns"]; exists {
		seen := map[string]bool{}
		for _, raw := range strings.Split(text, ",") {
			host := strings.TrimSpace(raw)
			if !wireGuardServerIP(host) || seen[host] || len(dns) == 4 {
				return fail()
			}
			seen[host] = true
			dns = append(dns, host)
		}
	}
	return wireGuardProfile{Endpoint: endpoint, DNS: dns}, nil
}

func validWGKey(key string) bool {
	data, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil || len(data) != 32 || base64.StdEncoding.EncodeToString(data) != key {
		return false
	}
	var nonzero byte
	for _, b := range data {
		nonzero |= b
	}
	return nonzero != 0
}

func wireGuardServerIP(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err == nil && ip.Is4() {
		bytes := ip.As4()
		if bytes[0] == 0 || bytes[0] >= 224 {
			return false
		}
	}
	return err == nil && ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && ip != netip.MustParseAddr("255.255.255.255")
}

func wireGuardPrefixes(text string, routes bool) ([]string, bool) {
	result, seen := []string{}, map[string]bool{}
	for _, value := range strings.Split(text, ",") {
		value = strings.TrimSpace(value)
		p, err := netip.ParsePrefix(value)
		if err != nil || p.Addr().Is4In6() || seen[p.String()] || len(result) == 16 || (!routes && !wireGuardServerIP(p.Addr().String())) {
			return nil, false
		}
		if routes && p != p.Masked() {
			return nil, false
		}
		seen[p.String()] = true
		result = append(result, p.String())
	}
	return result, len(result) != 0
}

func wireGuardNumber(value string, minimum, maximum int) (int, error) {
	if value == "" {
		return 0, errors.New("missing WireGuard numeric field")
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid WireGuard numeric field")
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < minimum || n > maximum {
		return 0, errors.New("WireGuard numeric field outside supported range")
	}
	return n, nil
}
