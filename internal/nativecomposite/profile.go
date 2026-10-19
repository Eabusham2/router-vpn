package nativecomposite

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativesip003"
)

func decodeProfile(source string) (map[string][]byte, error) {
	encoded, err := object([]byte(source))
	if err != nil || len(encoded) == 0 || len(encoded) > 8 {
		return nil, invalid
	}
	result := map[string][]byte{}
	total := 0
	for name, value := range encoded {
		if !id.MatchString(name) || strings.Contains(name, "..") {
			return nil, invalid
		}
		data, ok := value.(string)
		if !ok {
			return nil, invalid
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(data)
		if err != nil || len(raw) == 0 || len(raw) > MaxSize || !utf8.Valid(raw) || base64.StdEncoding.EncodeToString(raw) != data {
			return nil, invalid
		}
		total += len(raw)
		if total > MaxSize {
			return nil, invalid
		}
		result[name] = raw
	}
	return result, nil
}

// Compile consumes only the exact captured files. start is empty when disabled,
// otherwise the same node's generated Shadowsocks asset map. TLS trust is
// embedded from this profile before node files can be combined or staged.
func Compile(mode, profile, metadata, start string) (string, error) {
	policy, err := object([]byte(metadata))
	if err != nil || !Mode(mode) || len(policy) != 4 || !fields(policy, "node_id", "node_kind", "router_api", "start_layer") || !nodeID.MatchString(text(policy["node_id"])) || policy["node_kind"] != "router-vpn" {
		return "", invalid
	}
	layer, ok := policy["start_layer"].(string)
	if !ok {
		return "", invalid
	}
	if layer == "off" {
		layer = ""
	}
	if !Layer(layer) || (layer == "") != (start == "") {
		return "", invalid
	}
	api, err := url.Parse(text(policy["router_api"]))
	if err != nil || api == nil || (api.Scheme != "http" && api.Scheme != "https") || api.User != nil || api.RawQuery != "" || api.RawPath != "" || api.Fragment != "" || api.Path != "" && api.Path != "/" || !literal(api.Hostname()) {
		return "", invalid
	}
	files, err := decodeProfile(profile)
	if err != nil {
		return "", err
	}
	helper := "xray.json"
	if mode == "ss-v2ray" {
		helper = "sslocal.json"
	}
	if len(files["sing-box.json"]) == 0 || len(files[helper]) == 0 {
		return "", invalid
	}
	var compiled []byte
	if mode == "ss-v2ray" {
		compiled, err = nativesip003.Compile(files["sing-box.json"], files[helper])
	} else {
		compiled, err = applexray.Compile(mode, files["sing-box.json"], files[helper])
	}
	if err != nil {
		return "", errors.New("captured composite protocol assets failed native validation")
	}
	graph, err := object(compiled)
	if err != nil {
		return "", err
	}
	outputs, ok := graph["outbounds"].([]any)
	if !ok {
		return "", invalid
	}
	used := map[string]bool{"sing-box.json": true, helper: true}
	if manifest, exists := files["stack.json"]; exists {
		if mode == "ss-v2ray" || !validManifest(mode, manifest) {
			return "", errors.New("composite manifest disagrees with its authenticated transports")
		}
		used["stack.json"] = true
	}
	for _, raw := range outputs {
		out, ok := raw.(map[string]any)
		if !ok {
			return "", invalid
		}
		if out["type"] != "hysteria2" {
			continue
		}
		tls, ok := out["tls"].(map[string]any)
		if !ok {
			return "", invalid
		}
		if path, exists := tls["certificate_path"]; exists {
			name, ok := path.(string)
			if !ok || !id.MatchString(name) || strings.Contains(name, "..") || used[name] || tls["certificate"] != nil || !certificates(string(files[name])) {
				return "", errors.New("composite UDP trust must belong to its captured profile")
			}
			used[name] = true
			delete(tls, "certificate_path")
			tls["certificate"] = string(files[name])
		}
	}
	for name := range files {
		if !used[name] {
			return "", errors.New("composite profile contains an unowned helper or asset")
		}
	}
	compiled, err = json.Marshal(graph)
	if err != nil {
		return "", invalid
	}
	if layer != "" {
		assets, err := decodeProfile(start)
		if err != nil || len(assets) != 1 || len(assets["sing-box.json"]) == 0 {
			return "", errors.New("composite Start Layer requires its exact generated AES source")
		}
		parameters, _ := json.Marshal(map[string]any{"mode": layer, "raw_mode": mode, "node_kind": "router-vpn", "router_api": policy["router_api"]})
		if mode == "ss-v2ray" {
			compiled, err = nativesip003.ComposeStartLayer(compiled, files[helper], assets["sing-box.json"], parameters)
		} else {
			compiled, err = applexray.ComposeStartLayer(mode, compiled, files[helper], assets["sing-box.json"], parameters)
		}
		if err != nil {
			return "", errors.New("captured composite Start Layer failed native validation")
		}
		graph, err = object(compiled)
		if err != nil {
			return "", err
		}
	}
	outputs, _ = graph["outbounds"].([]any)
	var tcp, udp, outer map[string]any
	for _, raw := range outputs {
		out := raw.(map[string]any)
		switch {
		case out["type"] == applexray.Type || out["type"] == "shadowsocks" && out["plugin"] == "v2ray-plugin":
			if tcp != nil {
				return "", invalid
			}
			tcp = out
		case out["type"] == "hysteria2":
			if udp != nil {
				return "", invalid
			}
			udp = out
		case out["type"] == "shadowsocks" || out["type"] == "routervpn-aes-xor":
			if layer == "" || outer != nil {
				return "", invalid
			}
			outer = out
		case out["type"] == "direct" && len(out) == 2:
		default:
			return "", invalid
		}
	}
	if tcp == nil || udp == nil || (layer == "") != (outer == nil) {
		return "", invalid
	}
	// The generated split/MAX wrapper inherited the source mode's DNS tag
	// "proxy" while renaming its TCP lane to "tcp-stack". Resolve only that
	// absent, generator-owned alias; a real third transport is never adopted.
	if mode != "ss-v2ray" && tcp["tag"] == "tcp-stack" {
		for _, raw := range outputs {
			if raw.(map[string]any)["tag"] == "proxy" {
				return "", invalid
			}
		}
		dns, _ := graph["dns"].(map[string]any)
		servers, _ := dns["servers"].([]any)
		for _, raw := range servers {
			resolver, ok := raw.(map[string]any)
			if ok && resolver["detour"] == "proxy" {
				resolver["detour"] = tcp["tag"]
			}
		}
	}
	if err := wrapper(graph, text(tcp["tag"]), text(udp["tag"]), true); err != nil {
		return "", err
	}
	plan := map[string]any{"type": PlanType, "mode": mode, "node_id": policy["node_id"], "start_layer": layer}
	for name, value := range map[string]map[string]any{"tcp": tcp, "udp": udp, "start": outer} {
		if value == nil {
			continue
		}
		copied, err := copyMap(value)
		if err != nil {
			return "", err
		}
		copied["tag"] = SourcePrefix + name
		if name != "start" && layer != "" {
			if copied["detour"] != outer["tag"] {
				return "", invalid
			}
			copied["detour"] = StartTag
		}
		plan[name] = copied
	}
	owner, children, err := Relabel(plan, mode, text(policy["node_id"]), layer, "proxy", SourcePrefix, "")
	if err != nil {
		return "", err
	}
	graph["outbounds"] = append([]any{owner}, children...)
	route := graph["route"].(map[string]any)
	route["final"] = "proxy"
	route["rules"] = []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}
	for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
		raw.(map[string]any)["detour"] = "proxy"
	}
	result, err := json.Marshal(graph)
	if err != nil || len(result) > MaxSize {
		return "", invalid
	}
	return string(result), nil
}

// wrapper rejects custom bypass/routing that a composite must not discard.
// Replacing exactly the two protocol rules by one fixed network dispatcher
// preserves the generator's choice for TCP, UDP and protocol-specific DNS.
func wrapper(graph map[string]any, tcp, udp string, split bool) error {
	if !fields(graph, "log", "inbounds", "outbounds", "route", "dns") {
		return invalid
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return invalid
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || !fields(tun, "type", "tag", "interface_name", "address", "mtu", "stack", "auto_route", "strict_route") || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return invalid
	}
	route, ok := graph["route"].(map[string]any)
	if !ok || !fields(route, "final", "rules", "auto_detect_interface") || route["final"] != tcp || route["auto_detect_interface"] != nil && route["auto_detect_interface"] != true {
		return invalid
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return invalid
	}
	seen := map[string]bool{}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return invalid
		}
		if len(rule) == 2 && rule["protocol"] == "dns" && rule["action"] == "hijack-dns" {
			if seen["dns"] {
				return invalid
			}
			seen["dns"] = true
			continue
		}
		network := text(rule["network"])
		expected := tcp
		if network == "udp" {
			expected = udp
		}
		if !split || network != "tcp" && network != "udp" || seen[network] || len(rule) != 3 || !fields(rule, "network", "action", "outbound") || rule["action"] != "route" || rule["outbound"] != expected {
			return invalid
		}
		seen[network] = true
	}
	if !seen["dns"] || split && (!seen["tcp"] || !seen["udp"]) {
		return invalid
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok || !fields(dns, "servers", "final", "strategy", "disable_cache", "disable_expire", "independent_cache", "cache_capacity") {
		return invalid
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) == 0 || len(servers) > 8 {
		return invalid
	}
	final := dns["final"] == nil && len(servers) == 1
	seenResolvers := map[string]bool{}
	for _, raw := range servers {
		resolver, ok := raw.(map[string]any)
		if !ok || resolver["detour"] != tcp && resolver["detour"] != udp || !id.MatchString(text(resolver["tag"])) || seenResolvers[text(resolver["tag"])] {
			return invalid
		}
		seenResolvers[text(resolver["tag"])] = true
		if text(resolver["tag"]) == text(dns["final"]) {
			final = true
		}
	}
	if !final {
		return invalid
	}
	return nil
}

func validManifest(mode string, raw []byte) bool {
	value, err := object(raw)
	if err != nil || len(value) != 6 || !fields(value, "name", "transport", "post_quantum", "shared_layers", "tcp_stack", "udp_stack") || value["transport"] != "both" || value["post_quantum"] != (mode == "max") || text(value["name"]) == "" {
		return false
	}
	for _, field := range []string{"shared_layers", "tcp_stack", "udp_stack"} {
		values, ok := value[field].([]any)
		if !ok || len(values) == 0 || len(values) > 32 {
			return false
		}
		for _, raw := range values {
			line, ok := raw.(string)
			if !ok || line == "" || len(line) > 256 {
				return false
			}
		}
	}
	return true
}

// Plan returns a non-runnable, self-contained paired transport from a compiled
// standalone graph. Both lanes and optional AES remain bound to one node.
func Plan(config, mode, node, layer string) (map[string]any, error) {
	if layer == "off" {
		layer = ""
	}
	graph, err := object([]byte(config))
	if err != nil || wrapper(graph, "proxy", "proxy", false) != nil {
		return nil, invalid
	}
	plan, err := Extract(graph, mode, node, layer, "proxy", SourcePrefix, "")
	if err != nil {
		return nil, err
	}
	count := 3
	if layer != "" {
		count++
	}
	if len(graph["outbounds"].([]any)) != count {
		return nil, invalid
	}
	return plan, nil
}
