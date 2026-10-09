package applexray

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

const StartLayerTag = "start-layer-aes"

// ComposeStartLayer encloses the exact native REALITY/XHTTP connection and,
// for Split/MAX, its separate Hysteria2 UDP leg inside the selected node's AES
// transport. Only service addresses and owned detours change. Private keys,
// PQ/REALITY authentication, Vision flow, FinalMask, TLS and DNS remain intact.
// No second system VPN, local listener, resolver or unowned helper is created.
func ComposeStartLayer(mode string, wrapper, xray, aes, metadata []byte) ([]byte, error) {
	bad := errors.New("invalid native Xray Start Layer composition")
	policy, e := Object(metadata)
	if e != nil || keys(policy, "mode", "raw_mode", "node_kind", "router_api") != nil || len(policy) != 4 || policy["raw_mode"] != mode || policy["node_kind"] != "router-vpn" {
		return nil, bad
	}
	layer := text(policy["mode"])
	if layer != "aes-256-gcm" && layer != "aes-256-gcm+xor-whitening" {
		return nil, bad
	}
	api, e := url.Parse(text(policy["router_api"]))
	if e != nil || api == nil || (api.Scheme != "http" && api.Scheme != "https") || api.User != nil || api.RawPath != "" || api.RawQuery != "" || api.Fragment != "" || (api.Path != "" && api.Path != "/") {
		return nil, bad
	}
	service, e := netip.ParseAddr(api.Hostname())
	if e != nil || service.Is4In6() || !safeIP(service) || !service.IsPrivate() {
		return nil, bad
	}
	if api.Port() != "" {
		if _, e = port(json.Number(api.Port())); e != nil {
			return nil, bad
		}
	}
	plan, e := prepare(mode, xray, true)
	if e != nil {
		return nil, e
	}
	// Ordinary compilation verifies the exact raw sidecar, one TUN and the
	// original route graph before adding a new transport owner.
	compiled, e := compile(mode, wrapper, xray, true)
	if e != nil {
		return nil, e
	}
	graph, e := Object(compiled)
	if e != nil {
		return nil, e
	}
	source, e := Object(aes)
	if e != nil {
		return nil, e
	}
	list, ok := source["outbounds"].([]any)
	if !ok {
		return nil, bad
	}
	var outer map[string]any
	for _, raw := range list {
		value, ok := raw.(map[string]any)
		if !ok {
			return nil, bad
		}
		if value["type"] != "shadowsocks" {
			continue
		}
		if outer != nil || keys(value, "type", "tag", "method", "password", "server", "server_port") != nil || len(value) != 6 {
			return nil, bad
		}
		outer = value
	}
	if outer == nil || outer["method"] != "2022-blake3-aes-256-gcm" || !sameStartHost(text(outer["server"]), plan.ServerHost) {
		return nil, errors.New("Start Layer must belong to the same authenticated node")
	}
	if _, e = port(outer["server_port"]); e != nil {
		return nil, bad
	}
	password := text(outer["password"])
	if password == "" || len(password) > 4096 {
		return nil, bad
	}
	for _, part := range strings.Split(password, ":") {
		raw, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != part {
			return nil, bad
		}
	}
	// Use the node's private service IP rather than dialing the phone's localhost.
	// The native binding freezes this rewritten endpoint and sends it only through
	// the newly-owned encrypted detour; application targets stay VLESS payloads.
	rewritten, _ := Object(xray)
	remote := rewritten["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	remote["address"] = service.String()
	inner, e := json.Marshal(rewritten)
	if e != nil {
		return nil, bad
	}
	if _, e = Prepare(mode, inner); e != nil {
		return nil, e
	}
	protected := 0
	outbounds := graph["outbounds"].([]any)
	for _, raw := range outbounds {
		out := raw.(map[string]any)
		if out["tag"] == StartLayerTag {
			return nil, errors.New("Start Layer tag already belongs to another outbound")
		}
		switch out["type"] {
		case Type:
			if _, exists := out["detour"]; exists {
				return nil, errors.New("native Xray transport already has an owner")
			}
			out["config_json"] = string(inner)
			out["detour"] = StartLayerTag
			protected++
		case "hysteria2":
			if _, exists := out["detour"]; exists {
				return nil, errors.New("native UDP transport already has an owner")
			}
			if !sameStartHost(text(out["server"]), plan.ServerHost) {
				return nil, errors.New("dual transport cannot retarget a foreign UDP node")
			}
			out["server"] = service.String()
			out["detour"] = StartLayerTag
			protected++
		}
	}
	expected := 1
	if mode == "split" || mode == "max" {
		expected = 2
	}
	if protected != expected {
		return nil, bad
	}
	outer["tag"] = StartLayerTag
	if layer == "aes-256-gcm+xor-whitening" {
		outer["type"] = "routervpn-aes-xor"
		outer["server_port"] = 8389
	}
	graph["outbounds"] = append(outbounds, outer)
	result, e := json.Marshal(graph)
	if e != nil || len(result) > MaxConfig {
		return nil, bad
	}
	return result, nil
}

func sameStartHost(a, b string) bool {
	if a == "" || b == "" || a != strings.TrimSpace(a) || b != strings.TrimSpace(b) {
		return false
	}
	x, xe := netip.ParseAddr(a)
	y, ye := netip.ParseAddr(b)
	if xe == nil || ye == nil {
		return xe == nil && ye == nil && safeIP(x) && safeIP(y) && x.Unmap() == y.Unmap()
	}
	return safeHostname(a) && safeHostname(b) && strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}
