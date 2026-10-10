package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"router-vpn/internal/applexray"
)

// CompileXrayExit returns a single native full-device graph and preserves the
// exit's resolver/transport settings. Raw protocol files are embedded as bytes
// in the native outbound, not staged for a second process or system VPN.
func CompileXrayExit(profile, mode string) (string, error) {
	entryText, e := compileXrayEntry(profile, mode)
	if e != nil {
		return "", e
	}
	var entry map[string]any
	if e = json.Unmarshal([]byte(entryText), &entry); e != nil {
		return "", e
	}
	var assets map[string]string
	if exactJSON([]byte(profile), &assets, 8<<20) != nil {
		return "", errors.New("invalid native exit assets")
	}
	var graph map[string]any
	if encoded, ok := assets["sing-box.json"]; ok {
		raw, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil {
			return "", e
		}
		source, e := base64.StdEncoding.Strict().DecodeString(assets["xray.json"])
		if e != nil {
			return "", e
		}
		normalized, e := applexray.Compile(mode, raw, source)
		if e != nil {
			return "", e
		}
		if exactJSON(normalized, &graph, 4<<20) != nil {
			return "", errors.New("invalid compiled exit graph")
		}
	} else {
		// Legacy raw XHTTP did not ship a wrapper. The host must still supply the
		// captured selected DNS policy before startup; no resolver is invented here.
		graph = map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.29.94.1/30", "fd29:94::1/126"}, "mtu": 1280, "auto_route": true, "strict_route": true}}, "route": map[string]any{"final": "proxy"}, "outbounds": []any{entry}}
	}
	route := graph["route"].(map[string]any)
	previous, _ := route["final"].(string)
	entries := graph["outbounds"].([]any)
	for _, raw := range entries {
		out := raw.(map[string]any)
		if out["type"] == applexray.Type {
			out["tag"] = "proxy"
		} else if out["tag"] == "proxy" {
			return "", errors.New("exit final tag is already owned")
		}
	}
	if rawDNS, exists := graph["dns"]; exists {
		dns, ok := rawDNS.(map[string]any)
		if !ok {
			return "", errors.New("invalid exit DNS policy")
		}
		servers, ok := dns["servers"].([]any)
		if !ok {
			return "", errors.New("invalid exit DNS policy")
		}
		for _, raw := range servers {
			resolver, ok := raw.(map[string]any)
			if !ok || resolver["detour"] != previous {
				return "", errors.New("exit DNS must remain on the exact encrypted transport")
			}
			resolver["detour"] = "proxy"
		}
	}
	route["final"] = "proxy"
	graph["outbounds"] = entries
	body, e := json.Marshal(graph)
	if e != nil || len(body) > 4<<20 {
		return "", errors.New("native exit graph exceeds bound")
	}
	return string(body), nil
}

func validateNestedXrayExit(out map[string]any, mode, entryTag string) error {
	if out["detour"] != entryTag {
		return errors.New("native exit is not owned by the captured entry")
	}
	copy := make(map[string]any, len(out)-1)
	for key, value := range out {
		if key != "detour" {
			copy[key] = value
		}
	}
	return applexray.ValidateSingleTransport(copy, mode)
}
