package nativesip003

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

const StartLayerTag = "start-layer-aes"

// ComposeStartLayer encloses BOTH authenticated SIP003 legs in the selected
// home node's AES transport. It preserves the TCP plugin's TLS/SNI/path, the
// Hysteria2 authentication/obfuscation, and DNS's existing protocol-aware leg.
// There is one TUN and no helper listener or independent VPN. Unknown input
// policy is rejected rather than removed to make a graph appear supported.
func ComposeStartLayer(wrapper, helper, aes, metadata []byte) ([]byte, error) {
	policy, err := Object(metadata)
	if err != nil || !keys(policy, "mode", "raw_mode", "node_kind", "router_api") || len(policy) != 4 || policy["raw_mode"] != Mode || policy["node_kind"] != "router-vpn" {
		return nil, invalid
	}
	mode := text(policy["mode"])
	if mode != "aes-256-gcm" && mode != "aes-256-gcm+xor-whitening" {
		return nil, errors.New("SIP003 Start Layer requires authenticated AES; standalone XOR is not encryption")
	}
	api, err := url.Parse(text(policy["router_api"]))
	if err != nil || api == nil || (api.Scheme != "http" && api.Scheme != "https") || api.User != nil || api.RawPath != "" || api.RawQuery != "" || api.Fragment != "" || (api.Path != "" && api.Path != "/") {
		return nil, invalid
	}
	service, err := netip.ParseAddr(api.Hostname())
	if err != nil || service.Zone() != "" || service.Is4In6() || !service.IsPrivate() || service.IsLoopback() || service.IsUnspecified() || service.IsLinkLocalUnicast() || service.IsMulticast() {
		return nil, invalid
	}
	if api.Port() != "" {
		if _, err = port(json.Number(api.Port())); err != nil {
			return nil, invalid
		}
	}
	// Reuse the same byte-precise compiler as ordinary native mode preparation.
	// It validates the original helper, both leg identities and the DNS routes.
	compiled, err := Compile(wrapper, helper)
	if err != nil {
		return nil, err
	}
	graph, err := Object(compiled)
	if err != nil {
		return nil, err
	}
	source, err := Object(aes)
	if err != nil {
		return nil, err
	}
	list, ok := source["outbounds"].([]any)
	if !ok {
		return nil, invalid
	}
	var outer map[string]any
	for _, item := range list {
		candidate, ok := item.(map[string]any)
		if !ok {
			return nil, invalid
		}
		if candidate["type"] != "shadowsocks" {
			continue
		}
		if outer != nil || !keys(candidate, "type", "tag", "server", "server_port", "method", "password") || len(candidate) != 6 {
			return nil, invalid
		}
		outer = candidate
	}
	if outer == nil || outer["method"] != "2022-blake3-aes-256-gcm" || !hostname(text(outer["server"])) {
		return nil, invalid
	}
	if _, err = port(outer["server_port"]); err != nil {
		return nil, err
	}
	password := text(outer["password"])
	if len(password) == 0 || len(password) > 4096 {
		return nil, invalid
	}
	for _, part := range strings.Split(password, ":") {
		key, e := base64.StdEncoding.Strict().DecodeString(part)
		if e != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != part {
			return nil, invalid
		}
	}
	outbounds := graph["outbounds"].([]any)
	protected := 0
	for _, item := range outbounds {
		out := item.(map[string]any)
		if out["tag"] == StartLayerTag {
			return nil, errors.New("Start Layer transport tag already has an owner")
		}
		switch out["type"] {
		case "shadowsocks", "hysteria2":
			// Both services must be on the same paired server; do not retarget an
			// imported two-provider graph based on a convenient UI label.
			if out["server"] != outer["server"] {
				return nil, errors.New("SIP003 Start Layer cannot retarget an unrelated node")
			}
			if _, exists := out["detour"]; exists {
				return nil, errors.New("Start Layer cannot overwrite an existing transport owner")
			}
			out["server"] = service.String()
			out["detour"] = StartLayerTag
			protected++
		}
	}
	if protected != 2 {
		return nil, invalid
	}
	outer["tag"] = StartLayerTag
	if mode == "aes-256-gcm+xor-whitening" {
		outer["type"] = "routervpn-aes-xor"
		outer["server_port"] = 8389
	}
	graph["outbounds"] = append(outbounds, outer)
	result, err := json.Marshal(graph)
	if err != nil || len(result) > MaxConfig {
		return nil, invalid
	}
	return result, nil
}
