package mobilemultihop

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const AmneziaType = "routervpn-amneziawg"
const AmneziaVersion = "v3.1.20260814"

// AmneziaEndpointConfig is an owned native endpoint, not a WireGuard profile
// with its obfuscation options discarded. Runtime revalidates it before UAPI.
type AmneziaEndpointConfig struct {
	Type       string            `json:"type,omitempty"`
	Tag        string            `json:"tag,omitempty"`
	Detour     string            `json:"detour,omitempty"`
	System     bool              `json:"system,omitempty"`
	MTU        int               `json:"mtu"`
	Address    []string          `json:"address"`
	PrivateKey string            `json:"private_key"`
	ListenPort int               `json:"listen_port,omitempty"`
	Peers      []AmneziaPeer     `json:"peers"`
	Parameters map[string]string `json:"amnezia"`
}
type AmneziaPeer struct {
	Address      string   `json:"address"`
	Port         int      `json:"port"`
	PublicKey    string   `json:"public_key"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"persistent_keepalive_interval,omitempty"`
}
type AmneziaRuntime struct {
	TransportPadding int
	UAPI             string
	Addresses        []netip.Prefix
	Remote           netip.AddrPort
	MTU              int
}

// CompileAmneziaProfile retains every accepted AWG-specific option. The durable
// Router VPN ID is anchored to its different standard WG key: a successful
// AWG handshake is not that identity proof. The service must prove nodeID after
// the encrypted path starts, just as it does with the raw AWG backend.
func CompileAmneziaProfile(text, nodeID string) (string, error) {
	if !proofID.MatchString(nodeID) || len(text) == 0 || len(text) > 1024*1024 || !utf8.ValidString(text) {
		return "", errors.New("invalid paired AmneziaWG profile")
	}
	parameters := map[string]string{}
	lines := []string{}
	section := ""
	public := ""
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 16384 {
			return "", errors.New("oversized AmneziaWG profile line")
		}
		for _, ch := range line {
			if ch < 32 && ch != '\r' && ch != '\t' || ch == 127 {
				return "", errors.New("invalid AmneziaWG profile character")
			}
		}
		clean := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(clean, "[") {
			section = strings.ToLower(clean)
		}
		key, value, found := strings.Cut(clean, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if found && isAmneziaParameter(key) {
			if section != "[interface]" || value == "" {
				return "", errors.New("AmneziaWG parameter outside its interface")
			}
			if _, exists := parameters[key]; exists {
				return "", errors.New("duplicate AmneziaWG parameter")
			}
			parameters[key] = value
			continue
		}
		if found && section == "[peer]" && key == "publickey" {
			public = value
		}
		lines = append(lines, line)
	}
	if _, err := amneziaParameterUAPI(parameters); err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
	parsed, err := parseWireGuardProfile(strings.Join(lines, "\n"), hex.EncodeToString(hash[:]))
	if err != nil {
		return "", err
	}
	// A single connected client dialer never starts a second OS VPN/listener.
	if value, ok := parsed.Endpoint["listen_port"]; ok && value != 0 {
		return "", errors.New("native AmneziaWG client cannot bind an imported listener")
	}
	parsed.Endpoint["type"] = AmneziaType
	parsed.Endpoint["amnezia"] = parameters
	encoded, err := json.Marshal(parsed)
	return string(encoded), err
}

// AmneziaRuntimeConfig validates even hand-written native JSON. Unrecognized
// fields, marks, bind hints and process directives cannot bypass the compiler.
func AmneziaRuntimeConfig(raw string) (AmneziaRuntime, error) {
	var config AmneziaEndpointConfig
	var object map[string]any
	if exactJSON([]byte(raw), &object, 2*1024*1024) != nil {
		return AmneziaRuntime{}, errors.New("invalid native AmneziaWG JSON")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return AmneziaRuntime{}, errors.New("unrecognized native AmneziaWG field")
	}
	if config.System || config.ListenPort != 0 || len(config.Peers) != 1 || config.Type != "" && config.Type != AmneziaType || config.Tag != "" && !exactID.MatchString(config.Tag) || config.Detour != "" && !exactID.MatchString(config.Detour) {
		return AmneziaRuntime{}, errors.New("invalid native AmneziaWG ownership")
	}
	parameterText, err := amneziaParameterUAPI(config.Parameters)
	if err != nil {
		return AmneziaRuntime{}, err
	}
	p := config.Peers[0]
	profile := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s\nMTU=%d\n[Peer]\nPublicKey=%s\nEndpoint=%s\nAllowedIPs=%s\nPersistentKeepalive=%d\n", config.PrivateKey, strings.Join(config.Address, ","), config.MTU, p.PublicKey, net.JoinHostPort(p.Address, strconv.Itoa(p.Port)), strings.Join(p.AllowedIPs, ","), p.Keepalive)
	if p.PreSharedKey != "" {
		profile += "PresharedKey=" + p.PreSharedKey + "\n"
	}
	hash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + p.PublicKey))
	if _, err = parseWireGuardProfile(profile, hex.EncodeToString(hash[:])); err != nil {
		return AmneziaRuntime{}, err
	}
	private, _ := base64.StdEncoding.DecodeString(config.PrivateKey)
	public, _ := base64.StdEncoding.DecodeString(p.PublicKey)
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%x\n%sreplace_peers=true\npublic_key=%x\nendpoint=%s\n", private, parameterText, public, net.JoinHostPort(p.Address, strconv.Itoa(p.Port)))
	if p.PreSharedKey != "" {
		psk, _ := base64.StdEncoding.DecodeString(p.PreSharedKey)
		fmt.Fprintf(&uapi, "preshared_key=%x\n", psk)
	}
	for _, prefix := range p.AllowedIPs {
		fmt.Fprintf(&uapi, "allowed_ip=%s\n", prefix)
	}
	fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", p.Keepalive)
	padding, _ := strconv.Atoi(config.Parameters["s4"])
	result := AmneziaRuntime{TransportPadding: padding, UAPI: uapi.String(), MTU: config.MTU, Remote: netip.AddrPortFrom(netip.MustParseAddr(p.Address), uint16(p.Port))}
	for _, prefix := range config.Address {
		result.Addresses = append(result.Addresses, netip.MustParsePrefix(prefix))
	}
	return result, nil
}
func isAmneziaParameter(key string) bool {
	switch key {
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4":
		return true
	}
	return false
}
func amneziaParameterUAPI(parameters map[string]string) (string, error) {
	if len(parameters) != 11 {
		return "", errors.New("native AmneziaWG requires its complete generated obfuscation policy")
	}
	for key := range parameters {
		if !isAmneziaParameter(key) {
			return "", errors.New("unowned AmneziaWG parameter")
		}
	}
	values := map[string]int{}
	for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"} {
		max := 1280
		if key == "jc" {
			max = 128
		}
		n, err := wireGuardNumber(parameters[key], 0, max)
		if err != nil {
			return "", errors.New("AmneziaWG noise or padding exceeds its bounded native budget")
		}
		values[key] = n
	}
	if values["jmin"] > values["jmax"] || values["s1"]+148 == values["s2"]+92 {
		return "", errors.New("inconsistent AmneziaWG padding sizes")
	}
	ranges := [][2]uint64{}
	for _, key := range []string{"h1", "h2", "h3", "h4"} {
		parts := strings.Split(parameters[key], "-")
		if len(parts) < 1 || len(parts) > 2 {
			return "", errors.New("invalid AmneziaWG header range")
		}
		bounds := [2]uint64{}
		for i, text := range parts {
			if text == "" || strings.Trim(text, "0123456789") != "" {
				return "", errors.New("invalid AmneziaWG header range")
			}
			n, err := strconv.ParseUint(text, 10, 32)
			if err != nil || n <= 4 {
				return "", errors.New("AmneziaWG headers must not masquerade as ordinary WireGuard")
			}
			bounds[i] = n
		}
		if len(parts) == 1 {
			bounds[1] = bounds[0]
		}
		if bounds[1] < bounds[0] {
			return "", errors.New("reversed AmneziaWG header range")
		}
		for _, other := range ranges {
			if bounds[0] <= other[1] && other[0] <= bounds[1] {
				return "", errors.New("AmneziaWG header ranges overlap")
			}
		}
		ranges = append(ranges, bounds)
	}
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	for _, key := range keys {
		fmt.Fprintf(&out, "%s=%s\n", key, parameters[key])
	}
	return out.String(), nil
}

// Keep the native AWG endpoint in the same one-TUN exit graph, never relabel it.
func AmneziaExitConfig(text, nodeID string) (string, error) {
	encoded, err := CompileAmneziaProfile(text, nodeID)
	if err != nil {
		return "", err
	}
	var profile wireGuardProfile
	if err = json.Unmarshal([]byte(encoded), &profile); err != nil {
		return "", err
	}
	return nativeExitConfig(profile)
}
