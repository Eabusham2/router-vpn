package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"router-vpn/internal/applexray"
)

// A single native REALITY/XHTTP outbound provides both TCP and UDP. Split/MAX
// have two independent transport legs and cannot be relabeled as this entry.
func XrayEntryMode(mode string) bool {
	return applexray.SingleTransportMode(mode)
}
func proxyEntryType(mode string) string {
	if XrayEntryMode(mode) {
		return applexray.Type
	}
	return mode
}
func proxyModeForOutbound(out map[string]any) string {
	kind, _ := out["type"].(string)
	if kind == applexray.Type {
		mode, _ := out["mode"].(string)
		return mode
	}
	return kind
}

// compileXrayEntry consumes this entry's exact files, validates the native
// authentication and wrapper policy, and returns only its owned outbound.
// No hostname lookup, listener, device, credential rewrite, or file staging.
func compileXrayEntry(profile, mode string) (string, error) {
	bad := errors.New("Xray entry requires one self-contained authenticated native profile")
	if !XrayEntryMode(mode) {
		return "", bad
	}
	var encoded map[string]string
	if exactJSON([]byte(profile), &encoded, 8<<20) != nil || len(encoded) < 1 || len(encoded) > 2 {
		return "", bad
	}
	files := map[string][]byte{}
	total := 0
	for name, text := range encoded {
		if name != "sing-box.json" && name != "xray.json" {
			return "", errors.New("Xray entry has an unowned helper or asset")
		}
		raw, e := base64.StdEncoding.Strict().DecodeString(text)
		if e != nil || len(raw) == 0 || len(raw) > 4<<20 || base64.StdEncoding.EncodeToString(raw) != text {
			return "", bad
		}
		total += len(raw)
		if total > 4<<20 {
			return "", bad
		}
		files[name] = raw
	}
	original := files["xray.json"]
	plan, e := applexray.Prepare(mode, original)
	if e != nil {
		return "", bad
	}
	if !wireGuardServerIP(plan.ServerHost) {
		return "", errors.New("Xray entry requires a literal unicast server; resolve before capturing the graph")
	}
	wrapper := files["sing-box.json"]
	if wrapper == nil {
		if mode != "reality-xhttp" {
			return "", bad
		}
		// This is the same legacy raw-XHTTP wrapper used by standalone preparation;
		// its SOCKS ingress is compiled away, never opened as an auxiliary listener.
		generated := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": plan.ListenerPort, "version": "5"}}, "route": map[string]any{"final": "proxy"}}
		wrapper, e = json.Marshal(generated)
		if e != nil {
			return "", bad
		}
	}
	compiled, e := applexray.Compile(mode, wrapper, original)
	if e != nil {
		return "", bad
	}
	var graph map[string]any
	if exactJSON(compiled, &graph, 4<<20) != nil {
		return "", bad
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return "", bad
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return "", bad
	}
	for _, key := range []string{"route_address", "route_exclude_address", "route_address_set", "route_exclude_address_set", "include_interface", "exclude_interface", "include_uid", "exclude_uid", "include_package", "exclude_package", "include_android_user"} {
		if _, present := tun[key]; present {
			return "", errors.New("Xray entry split or bypass policy cannot be discarded")
		}
	}
	route, ok := graph["route"].(map[string]any)
	if !ok {
		return "", bad
	}
	for key, value := range route {
		switch key {
		case "final":
		case "auto_detect_interface":
			if value != true {
				return "", bad
			}
		case "rules":
			rules, ok := value.([]any)
			if !ok {
				return "", bad
			}
			for _, raw := range rules {
				rule, ok := raw.(map[string]any)
				if !ok || len(rule) != 2 || rule["protocol"] != "dns" || rule["action"] != "hijack-dns" {
					return "", errors.New("Xray entry custom routes cannot be discarded")
				}
			}
		default:
			return "", bad
		}
	}
	list, ok := graph["outbounds"].([]any)
	if !ok {
		return "", bad
	}
	var entry map[string]any
	for _, raw := range list {
		out, ok := raw.(map[string]any)
		if !ok {
			return "", bad
		}
		if out["type"] == applexray.Type {
			if entry != nil {
				return "", bad
			}
			entry = out
		} else if out["type"] != "direct" || len(out) != 2 {
			return "", bad
		}
	}
	if entry == nil || route["final"] != entry["tag"] {
		return "", bad
	}
	entry["tag"] = "routervpn-hop-entry"
	if e = validateXrayEntry(entry, mode); e != nil {
		return "", e
	}
	result, e := json.Marshal(entry)
	return string(result), e
}

// Validation is repeated from frozen metadata at selection and MTU application.
// A forged label cannot turn a TCP-only, unauthenticated or multi-owner graph
// into an entry, and a pre-existing detour can never be overwritten silently.
func validateXrayEntry(entry map[string]any, mode string) error {
	bad := errors.New("Xray entry lost its exact native authentication or transport ownership")
	if !XrayEntryMode(mode) || entry["type"] != applexray.Type || entry["mode"] != mode || len(entry) != 4 {
		return bad
	}
	tag, ok := entry["tag"].(string)
	if !ok || !exactID.MatchString(tag) {
		return bad
	}
	raw, ok := entry["config_json"].(string)
	if !ok {
		return bad
	}
	plan, e := applexray.Prepare(mode, []byte(raw))
	if e != nil || !wireGuardServerIP(plan.ServerHost) {
		return bad
	}
	return nil
}
