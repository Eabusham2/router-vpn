package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const NativeStartLayerTag = "start-layer-aes"
const NativeStartLayerMethod = "2022-blake3-aes-256-gcm"

// ComposeNativeBaseStartLayer encloses a single native WG/AWG endpoint in the
// node's authenticated SS2022 transport. It returns a new graph, never mutates
// the imported peer/profile, and never starts a second OS VPN or a local relay.
// The inner UDP service is reached at the paired node's private Router API IP:
// that address is resolved by the remote AES node, not on the phone's LAN.
func ComposeNativeBaseStartLayer(config, shadowsocks, metadata string) (string, error) {
	var policy struct {
		Mode      string `json:"mode"`
		RawMode   string `json:"raw_mode"`
		NodeKind  string `json:"node_kind"`
		RouterAPI string `json:"router_api"`
	}
	if exactJSON([]byte(metadata), &policy, 16384) != nil {
		return "", errors.New("invalid captured Start Layer policy")
	}
	if policy.NodeKind != "router-vpn" || (policy.RawMode != "wg" && policy.RawMode != "awg2-fast" && policy.RawMode != "awg2-strong") {
		return "", errors.New("native Start Layer requires an exact Router VPN WG/AWG mode")
	}
	if policy.Mode != "aes-256-gcm" && policy.Mode != "aes-256-gcm+xor-whitening" {
		return "", errors.New("native Start Layer requires authenticated AES; XOR alone is not encryption")
	}
	api, err := url.Parse(policy.RouterAPI)
	if err != nil || api == nil || (api.Scheme != "http" && api.Scheme != "https") || api.User != nil || api.RawQuery != "" || api.Fragment != "" || api.RawPath != "" || (api.Path != "" && api.Path != "/") {
		return "", errors.New("paired node has no exact private service address")
	}
	service, err := netip.ParseAddr(api.Hostname())
	if err != nil || service.Zone() != "" || service.Is4In6() || !service.IsPrivate() || service.IsLoopback() || service.IsUnspecified() || service.IsLinkLocalUnicast() || service.IsMulticast() {
		return "", errors.New("paired node service must be a private literal IPv4/IPv6 address")
	}
	if port := api.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid paired service port")
		}
	}
	var graph, source map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil || exactJSON([]byte(shadowsocks), &source, 4<<20) != nil || graph == nil || source == nil {
		return "", errors.New("Start Layer requires bounded unambiguous native JSON")
	}
	endpoints, ok := graph["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return "", errors.New("native base Start Layer requires exactly one endpoint")
	}
	ep, ok := endpoints[0].(map[string]any)
	if !ok || ep["tag"] != "proxy" || ep["system"] != false || ep["detour"] != nil {
		return "", errors.New("native base has an existing or ambiguous transport owner")
	}
	expected := "wireguard"
	if policy.RawMode != "wg" {
		expected = AmneziaType
	}
	if ep["type"] != expected {
		return "", errors.New("native base label does not match its actual protocol")
	}
	endpointFields := map[string]bool{"type": true, "tag": true, "system": true, "mtu": true, "address": true, "private_key": true, "listen_port": true, "peers": true}
	if expected == AmneziaType {
		endpointFields["amnezia"] = true
	}
	for field := range ep {
		if !endpointFields[field] {
			return "", errors.New("native base has an unowned endpoint option")
		}
	}
	if _, ok := ep["private_key"].(string); !ok {
		return "", errors.New("native base private identity is missing")
	}
	peers, ok := ep["peers"].([]any)
	if !ok || len(peers) != 1 {
		return "", errors.New("native base requires exactly one paired peer")
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return "", errors.New("invalid native base peer")
	}
	port, ok := exactStartPort(peer["port"])
	if !ok {
		return "", errors.New("invalid native base service port")
	}
	_ = port // the exact validated port remains unchanged in the copied graph
	for _, field := range []string{"private_key"} {
		text, ok := ep[field].(string)
		raw, e := base64.StdEncoding.Strict().DecodeString(text)
		if !ok || e != nil || len(raw) != 32 {
			return "", errors.New("invalid native base key")
		}
	}
	for _, field := range []string{"public_key", "pre_shared_key"} {
		value, present := peer[field]
		if !present && field == "pre_shared_key" {
			continue
		}
		text, ok := value.(string)
		raw, e := base64.StdEncoding.Strict().DecodeString(text)
		if !ok || e != nil || len(raw) != 32 {
			return "", errors.New("invalid native base peer key")
		}
	}
	outbounds, ok := graph["outbounds"].([]any)
	if !ok {
		return "", errors.New("native base outbound list is missing")
	}
	// Existing policy outbounds remain intact, but no second proxy owner, imported
	// Start Layer, endpoint collision or anonymous outbound may be smuggled in.
	tags := map[string]bool{"proxy": true}
	for _, raw := range outbounds {
		out, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid native outbound")
		}
		tag, ok := out["tag"].(string)
		if !ok || !exactID.MatchString(tag) || tag == NativeStartLayerTag || tags[tag] {
			return "", errors.New("native Start Layer tag ownership collision")
		}
		tags[tag] = true
	}
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return "", errors.New("native base no longer owns the final route")
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok {
		return "", errors.New("native TUN is missing")
	}
	count := 0
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid native inbound")
		}
		if inbound["type"] == "tun" {
			count++
			if inbound["auto_route"] != true || inbound["strict_route"] != true {
				return "", errors.New("native TUN route policy is not owned")
			}
		}
	}
	if count != 1 {
		return "", errors.New("native Start Layer must retain one full-device TUN")
	}
	sourceOutbounds, ok := source["outbounds"].([]any)
	if !ok {
		return "", errors.New("generated AES transport is missing")
	}
	var outer map[string]any
	allowed := map[string]bool{"type": true, "tag": true, "server": true, "server_port": true, "method": true, "password": true}
	for _, raw := range sourceOutbounds {
		value, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid generated AES transport")
		}
		if value["type"] != "shadowsocks" {
			continue
		}
		if outer != nil {
			return "", errors.New("generated AES transport is ambiguous")
		}
		for field := range value {
			if !allowed[field] {
				return "", errors.New("Start Layer cannot discard an imported plugin or transport policy")
			}
		}
		outer = value
	}
	if outer == nil || outer["method"] != NativeStartLayerMethod {
		return "", errors.New("Start Layer requires Shadowsocks 2022 AES-256-GCM")
	}
	if _, ok := exactStartPort(outer["server_port"]); !ok {
		return "", errors.New("invalid AES transport port")
	}
	password, ok := outer["password"].(string)
	if !ok || len(password) < 16 || len(password) > 4096 || strings.ContainsAny(password, "\x00\r\n") {
		return "", errors.New("invalid AES transport credential")
	}
	// Accept the established SS2022 single/server:user key representation only;
	// never normalize or trim secret bytes. The pinned engine checks key lengths.
	for _, part := range strings.Split(password, ":") {
		key, e := base64.StdEncoding.Strict().DecodeString(part)
		if e != nil || len(key) != 32 {
			return "", errors.New("AES transport requires exact 256-bit keys")
		}
	}
	host, ok := outer["server"].(string)
	if !ok || host != strings.TrimSpace(host) || host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n/@%") || strings.EqualFold(host, "localhost") {
		return "", errors.New("invalid AES transport host")
	}
	if ip, e := netip.ParseAddr(host); e == nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast()) {
		return "", errors.New("AES transport cannot point to a local bypass")
	}
	if policy.Mode == "aes-256-gcm+xor-whitening" {
		outer["type"] = "routervpn-aes-xor"
		outer["server_port"] = 8389
	}
	outer["tag"] = NativeStartLayerTag
	peer["address"] = service.String()
	ep["detour"] = NativeStartLayerTag
	graph["outbounds"] = append(outbounds, outer)
	if expected == AmneziaType {
		raw, _ := json.Marshal(ep)
		if _, e := AmneziaRuntimeConfig(string(raw)); e != nil {
			return "", errors.New("composed native AWG endpoint failed its parameter/peer validation")
		}
	}
	result, err := json.Marshal(graph)
	if err != nil || len(result) > 4<<20 {
		return "", errors.New("composed Start Layer config exceeds safety limit")
	}
	return string(result), nil
}

func exactStartPort(raw any) (int, bool) {
	n, ok := raw.(float64)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) || n < 1 || n > 65535 {
		return 0, false
	}
	return int(n), true
}
