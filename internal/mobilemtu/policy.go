package mobilemtu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const MinMTU = 1280
const MaxMTU = 9000
const ProbePort = 45999

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)
var proofPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var requestPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Profile struct {
	ID        string
	Proof     string
	API       string
	Token     string
	Sink      string
	Automatic bool
	Jumbo     bool
}

func privateIP(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && !ip.Is4In6() && ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
func ReadProfile(raw string) (Profile, error) {
	var object map[string]any
	if strictJSON(raw, &object, 256*1024) != nil || object == nil {
		return Profile{}, errors.New("invalid captured MTU node profile")
	}
	for _, key := range []string{"id", "node_kind", "node_proof_id", "router_api", "api_token", "socks_host", "daita_host", "mtu_policy"} {
		if _, err := stringField(object, key, ""); err != nil {
			return Profile{}, err
		}
	}
	kind, _ := stringField(object, "node_kind", "router-vpn")
	if kind != "" && kind != "router-vpn" {
		return Profile{}, errors.New("private MTU measurements require a paired Router VPN node")
	}
	mode, _ := stringField(object, "mtu_policy", "auto")
	mode = strings.ToLower(mode)
	if mode == "" {
		mode = "auto"
	}
	if mode != "auto" && mode != "default" && mode != "manual" && mode != "fixed" {
		return Profile{}, errors.New("unknown frozen MTU policy")
	}
	var profile Profile
	profile.ID, _ = stringField(object, "id", "")
	profile.Proof, _ = stringField(object, "node_proof_id", "")
	profile.API, _ = stringField(object, "router_api", "")
	profile.Token, _ = stringField(object, "api_token", "")
	profile.Sink, _ = stringField(object, "daita_host", "")
	if profile.Sink == "" {
		profile.Sink, _ = stringField(object, "socks_host", "")
	}
	var err error
	profile.Jumbo, err = boolField(object, "jumbo_tun")
	if err != nil {
		return Profile{}, err
	}
	port, err := intField(object, "daita_port", ProbePort)
	if err != nil || port != ProbePort {
		return Profile{}, errors.New("MTU uses only the paired node's existing private probe endpoint")
	}
	if !idPattern.MatchString(profile.ID) || !proofPattern.MatchString(profile.Proof) || !privateIP(profile.Sink) || profile.Token == "" || len(profile.Token) > 4096 {
		return Profile{}, errors.New("MTU profile lacks exact private node authority")
	}
	for _, ch := range profile.Token {
		if ch < 32 || ch == 127 {
			return Profile{}, errors.New("invalid MTU credential")
		}
	}
	api, err := url.Parse(profile.API)
	if err != nil || api == nil || (api.Scheme != "http" && api.Scheme != "https") || api.User != nil || api.RawQuery != "" || api.Fragment != "" || api.RawPath != "" || (api.Path != "" && api.Path != "/") || !privateIP(api.Hostname()) {
		return Profile{}, errors.New("MTU requires an explicit private literal node API")
	}
	// Requiring an explicit port prevents different host adapters from silently
	// choosing different HTTP endpoints after a reload.
	portNumber, portErr := strconv.Atoi(api.Port())
	if portErr != nil || portNumber < 1 || portNumber > 65535 {
		return Profile{}, errors.New("MTU private API port is invalid")
	}
	profile.Automatic = mode == "auto"
	return profile, nil
}

type Plan struct {
	Original int
	Ceiling  int
	TunTag   string
	source   string
}

// NewPlan constrains TUN-only changes to the already validated encrypted packet
// envelope. It never changes WG/AWG keys, endpoint MTUs, routes, DNS or helpers.
func NewPlan(config string, actual int) (*Plan, error) {
	var object map[string]any
	if strictJSON(config, &object, 4*1024*1024) != nil || object == nil || actual < MinMTU || actual > MaxMTU {
		return nil, errors.New("MTU needs the exact live TUN graph")
	}
	inbounds, ok := object["inbounds"].([]any)
	if !ok {
		return nil, errors.New("MTU graph lacks its full-device TUN")
	}
	var tun map[string]any
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid MTU inbound")
		}
		if inbound["type"] != "tun" {
			continue
		}
		if tun != nil {
			return nil, errors.New("more than one MTU TUN owner")
		}
		tun = inbound
	}
	if tun == nil || tun["auto_route"] != true || tun["strict_route"] != true {
		return nil, errors.New("MTU requires one full-device strict-route TUN")
	}
	tag, err := stringField(tun, "tag", "")
	if err != nil || !idPattern.MatchString(tag) {
		return nil, errors.New("MTU TUN identity is missing")
	}
	configured, err := intField(tun, "mtu", actual)
	if err != nil || configured != actual {
		return nil, errors.New("configured MTU differs from system-interface readback")
	}
	route, ok := object["route"].(map[string]any)
	if !ok {
		return nil, errors.New("MTU graph lacks its exit route")
	}
	final, err := stringField(route, "final", "")
	if err != nil || !idPattern.MatchString(final) {
		return nil, errors.New("MTU exit identity is missing")
	}
	all := map[string]map[string]any{}
	for _, key := range []string{"endpoints", "outbounds"} {
		values, exists := object[key]
		if !exists {
			continue
		}
		items, ok := values.([]any)
		if !ok {
			return nil, errors.New("invalid MTU graph collection")
		}
		for _, raw := range items {
			value, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid native transport")
			}
			id, err := stringField(value, "tag", "")
			if err != nil || !idPattern.MatchString(id) || all[id] != nil {
				return nil, errors.New("ambiguous native transport identity")
			}
			all[id] = value
		}
	}
	exit := all[final]
	if exit == nil {
		return nil, errors.New("selected MTU exit does not exist")
	}
	if exit["type"] == "direct" || exit["type"] == "block" || exit["type"] == "dns" {
		return nil, errors.New("MTU cannot tune an unencrypted direct exit")
	}
	ceiling := 1500
	packet := exit
	if exit["type"] == "selector" {
		// Both local/server choices share this OS TUN. A conservative bound must fit
		// the configured encrypted local leg even when server execution won.
		packet = all["routervpn-execution-local"]
		if packet == nil {
			return nil, errors.New("unowned execution selector")
		}
	}
	if packet["type"] == "wireguard" || packet["type"] == "routervpn-amneziawg" {
		value, err := intField(packet, "mtu", 0)
		if err != nil || value < MinMTU || value > MaxMTU {
			return nil, errors.New("invalid encrypted packet envelope")
		}
		ceiling = min(ceiling, value)
		detour, err := stringField(packet, "detour", "")
		if err != nil {
			return nil, err
		}
		if detour != "" {
			entry := all[detour]
			if entry == nil {
				return nil, errors.New("nested MTU entry is missing")
			}
			if entry["type"] == "wireguard" || entry["type"] == "routervpn-amneziawg" {
				outer, err := intField(entry, "mtu", 0)
				if err != nil || outer < MinMTU {
					return nil, errors.New("invalid entry MTU")
				}
				peers, ok := packet["peers"].([]any)
				if !ok || len(peers) != 1 {
					return nil, errors.New("ambiguous MTU packet peer")
				}
				peer, ok := peers[0].(map[string]any)
				if !ok {
					return nil, errors.New("invalid packet peer")
				}
				host, err := stringField(peer, "address", "")
				ip, ipErr := netip.ParseAddr(host)
				if err != nil || ipErr != nil {
					return nil, errors.New("MTU packet peer must be a literal address")
				}
				overhead := 60
				if ip.Is6() {
					overhead = 80
				}
				if packet["type"] == "routervpn-amneziawg" {
					params, ok := packet["amnezia"].(map[string]any)
					if !ok {
						return nil, errors.New("missing AWG overhead policy")
					}
					s4, err := stringField(params, "s4", "")
					if err != nil {
						return nil, err
					}
					var n int
					for _, ch := range s4 {
						if ch < '0' || ch > '9' {
							return nil, errors.New("invalid AWG overhead")
						}
						n = n*10 + int(ch-'0')
						if n > 1280 {
							return nil, errors.New("AWG overhead outside bound")
						}
					}
					if s4 == "" {
						return nil, errors.New("missing AWG overhead")
					}
					overhead += n
				}
				ceiling = min(ceiling, (outer-overhead)/16*16)
			}
		}
	}
	if ceiling < MinMTU || actual > ceiling {
		return nil, errors.New("current TUN MTU exceeds its captured safe envelope")
	}
	return &Plan{Original: actual, Ceiling: ceiling, TunTag: tag, source: config}, nil
}
func (p *Plan) Candidates(cached int) []int {
	values := []int{p.Original}
	add := func(n int) {
		if n < MinMTU || n > p.Ceiling || len(values) >= 5 {
			return
		}
		for _, value := range values {
			if value == n {
				return
			}
		}
		values = append(values, n)
	}
	add(cached)
	add(p.Ceiling)
	add(MinMTU)
	add((p.Ceiling + MinMTU) / 40 * 20)
	return values
}
func (p *Plan) Config(mtu int) (string, error) {
	if mtu < MinMTU || mtu > p.Ceiling {
		return "", errors.New("MTU candidate exceeds its captured budget")
	}
	if mtu == p.Original {
		return p.source, nil
	}
	var object map[string]any
	if strictJSON(p.source, &object, 4*1024*1024) != nil {
		return "", errors.New("captured MTU graph changed")
	}
	for _, raw := range object["inbounds"].([]any) {
		value := raw.(map[string]any)
		if value["type"] == "tun" {
			value["mtu"] = mtu
		}
	}
	data, err := json.Marshal(object)
	return string(data), err
}
func (p *Plan) PathKey(profile Profile, path string) string {
	digest := sha256.Sum256([]byte("router-vpn-os-mtu-v3\x00" + p.source + "\x00" + profile.ID + "\x00" + profile.Proof + "\x00" + path))
	return hex.EncodeToString(digest[:])
}
