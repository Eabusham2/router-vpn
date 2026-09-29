package mobileperf

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

func exact(data string, out any, limit int) error {
	failure := errors.New("bounded unambiguous performance JSON required")
	if len(data) == 0 || len(data) > limit || !utf8.ValidString(data) {
		return failure
	}
	d := json.NewDecoder(strings.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 40 {
			return failure
		}
		value, err := d.Token()
		if err != nil {
			return failure
		}
		delim, ok := value.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				value, err := d.Token()
				key, ok := value.(string)
				if err != nil || !ok || seen[key] {
					return failure
				}
				seen[key] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return failure
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return failure
			}
		default:
			return failure
		}
		return nil
	}
	if walk(0) != nil {
		return failure
	}
	if _, err := d.Token(); err != io.EOF {
		return failure
	}
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return failure
	}
	return nil
}
func flag(profile map[string]any, key string) (bool, error) {
	value, exists := profile[key]
	if !exists {
		return false, nil
	}
	b, ok := value.(bool)
	if !ok {
		return false, errors.New("performance policy flags must be booleans")
	}
	return b, nil
}
func text(profile map[string]any, key string) string {
	value, _ := profile[key].(string)
	return strings.TrimSpace(value)
}
func number(value any, def int) (int, error) {
	if value == nil {
		return def, nil
	}
	n, ok := value.(float64)
	if !ok || n != float64(int(n)) || n < 0 || n > 65535 {
		return 0, errors.New("invalid performance policy integer")
	}
	return int(n), nil
}

// Apply composes only the owned TUN and bounded services. It never rewrites
// routes, keys, DNS, crypto settings, socket protection or imported helper files.
func Apply(config, profiles string) (string, error) {
	var pair struct {
		Entry map[string]any `json:"entry"`
		Exit  map[string]any `json:"exit"`
	}
	if exact(profiles, &pair, 256*1024) != nil || pair.Entry == nil || pair.Exit == nil {
		return "", errors.New("performance policy requires frozen entry and exit profiles")
	}
	wantEntry, e1 := flag(pair.Entry, "daita_enabled")
	wantExit, e2 := flag(pair.Exit, "daita_enabled")
	jumbo, e3 := flag(pair.Exit, "jumbo_tun")
	entryJumbo, e4 := flag(pair.Entry, "jumbo_tun")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return "", errors.New("invalid performance flags")
	}
	var root map[string]any
	if exact(config, &root, 4*1024*1024) != nil || root == nil {
		return "", errors.New("invalid native performance graph")
	}
	requestedCoverTags := map[string]bool{}
	if !wantEntry && !wantExit && !jumbo && !entryJumbo {
		if services, ok := root["services"].([]any); ok {
			for _, raw := range services {
				value, ok := raw.(map[string]any)
				if !ok {
					return "", errors.New("invalid native service")
				}
				if value["type"] == CoverType {
					return "", errors.New("unrequested imported cover service")
				}
			}
		}
		return config, nil
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return "", errors.New("native performance graph lacks its TUN")
	}
	var tun map[string]any
	for _, raw := range inbounds {
		value, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid inbound")
		}
		if value["type"] == "tun" {
			if tun != nil {
				return "", errors.New("performance policy requires one owned OS TUN")
			}
			tun = value
		}
	}
	if tun == nil || tun["auto_route"] != true || tun["strict_route"] != true {
		return "", errors.New("performance policy requires the existing full-device TUN")
	}
	byTag := map[string]map[string]any{}
	for _, key := range []string{"outbounds", "endpoints"} {
		values, _ := root[key].([]any)
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return "", errors.New("invalid performance outbound")
			}
			tag := text(value, "tag")
			if !tokenPattern.MatchString(tag) || byTag[tag] != nil {
				return "", errors.New("ambiguous performance outbound identity")
			}
			byTag[tag] = value
		}
	}
	route, ok := root["route"].(map[string]any)
	if !ok {
		return "", errors.New("native performance graph lacks an exit route")
	}
	final := text(route, "final")
	if byTag[final] == nil {
		return "", errors.New("native performance exit missing")
	}
	udpTag := final
	if byTag["udp-stack"] != nil {
		rules, _ := route["rules"].([]any)
		found := false
		for _, raw := range rules {
			rule, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if rule["network"] == "udp" && rule["action"] == "route" && rule["outbound"] == "udp-stack" && len(rule) == 3 {
				found = true
			}
		}
		if found {
			udpTag = "udp-stack"
		}
	}
	entryTag := ""
	for _, tag := range []string{"entry-wg", "routervpn-hop-entry"} {
		if byTag[tag] != nil {
			if entryTag != "" {
				return "", errors.New("multiple performance entry owners")
			}
			entryTag = tag
		}
	}
	if entryTag != "" && entryJumbo {
		return "", errors.New("Jumbo applies to the OS proxy TUN, not to a raw entry endpoint")
	}
	if jumbo {
		for _, tag := range []string{final, udpTag} {
			kind := text(byTag[tag], "type")
			if kind == "wireguard" || kind == "routervpn-amneziawg" {
				return "", errors.New("Jumbo is for compatible proxy TUNs, not raw WG/AWG packet endpoints")
			}
		}
		policy := text(pair.Exit, "mtu_policy")
		if policy == "manual" || policy == "fixed" {
			mtu, err := number(pair.Exit["manual_mtu"], 0)
			if err != nil || mtu != 9000 {
				return "", errors.New("Jumbo conflicts with the saved fixed MTU")
			}
		}
		tun["mtu"] = 9000
	}
	existing, valid := root["services"].([]any)
	if root["services"] != nil && !valid {
		return "", errors.New("invalid native service collection")
	}
	services := append([]any{}, existing...)
	profilesByRole := []struct {
		profile             map[string]any
		enabled             bool
		role, proof, packet string
	}{{pair.Exit, wantExit, "exit", final, udpTag}}
	if entryTag != "" {
		profilesByRole = append(profilesByRole, struct {
			profile             map[string]any
			enabled             bool
			role, proof, packet string
		}{pair.Entry, wantEntry, "entry", entryTag, entryTag})
	} else if wantEntry != wantExit {
		return "", errors.New("single-node performance policy cannot disagree with itself")
	}
	for _, item := range profilesByRole {
		if !item.enabled {
			continue
		}
		if kind := text(item.profile, "node_kind"); kind != "" && kind != "router-vpn" {
			return "", errors.New("cover traffic requires a paired Router VPN node")
		}
		if !encrypted(byTag, item.packet, map[string]bool{}) || !encrypted(byTag, item.proof, map[string]bool{}) {
			return "", errors.New("cover requires proved encrypted native legs")
		}
		host := text(item.profile, "daita_host")
		if host == "" {
			host = text(item.profile, "socks_host")
		}
		port, err := number(item.profile["daita_port"], CoverPort)
		if err != nil || port != CoverPort {
			return "", errors.New("cover uses only the paired private sink")
		}
		rate, err := number(item.profile["daita_rate_kbps"], MaxCoverKbps)
		if err != nil {
			return "", err
		}
		options := CoverOptions{NodeID: text(item.profile, "node_proof_id"), API: text(item.profile, "router_api"), Sink: host, RateKbps: rate, ProofTag: item.proof, PacketTag: item.packet}
		if err = options.Validate(); err != nil {
			return "", err
		}
		encoded, _ := json.Marshal(options)
		var service map[string]any
		_ = json.Unmarshal(encoded, &service)
		tag := "routervpn-cover-" + item.role
		requestedCoverTags[tag] = true
		service["type"] = CoverType
		service["tag"] = tag
		duplicate := false
		for _, raw := range existing {
			entry, ok := raw.(map[string]any)
			if !ok {
				return "", errors.New("invalid native service")
			}
			if text(entry, "tag") == tag {
				if !reflect.DeepEqual(entry, service) {
					return "", errors.New("cover service tag already belongs to a different policy")
				}
				duplicate = true
			}
		}
		if !duplicate {
			services = append(services, service)
		}
	}
	for _, raw := range existing {
		value, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid native service")
		}
		if value["type"] == CoverType && !requestedCoverTags[text(value, "tag")] {
			return "", errors.New("imported cover service is not requested by the current node policy")
		}
	}
	if len(services) > 4 {
		return "", errors.New("native performance service budget exceeded")
	}
	if len(services) > 0 {
		root["services"] = services
	}
	result, err := json.Marshal(root)
	if err != nil || len(result) > 4*1024*1024 {
		return "", errors.New("performance graph exceeds its bound")
	}
	return string(result), nil
}
func encrypted(tags map[string]map[string]any, tag string, seen map[string]bool) bool {
	if seen[tag] || len(seen) > 12 {
		return false
	}
	seen[tag] = true
	value := tags[tag]
	if value == nil {
		return false
	}
	switch text(value, "type") {
	case "wireguard", "routervpn-amneziawg", "shadowsocks", "hysteria2", "routervpn-aes-xor", "routervpn-xray":
		return true
	case "socks":
		detour := text(value, "detour")
		return detour != "" && encrypted(tags, detour, seen)
	default:
		return false
	}
}
