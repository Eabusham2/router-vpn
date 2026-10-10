package mobilemultihop

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
)

// ApplyMTUPolicy projects the two frozen node settings onto their OWN native
// endpoints and the one OS TUN. A saved effective_mtu is not a current-path
// measurement. Fixed values never silently clamp; default/Auto starts with a
// conservative configured bound, not a fabricated discovery result.
func ApplyMTUPolicy(config, profiles string) (string, error) {
	var pair struct {
		Entry map[string]any `json:"entry"`
		Exit  map[string]any `json:"exit"`
	}
	if exactJSON([]byte(profiles), &pair, 256*1024) != nil || pair.Entry == nil || pair.Exit == nil {
		return "", errors.New("two frozen node policies are required for multihop MTU")
	}
	entryFixed, err := fixedMTU(pair.Entry)
	if err != nil {
		return "", err
	}
	exitFixed, err := fixedMTU(pair.Exit)
	if err != nil {
		return "", err
	}
	var root map[string]any
	if exactJSON([]byte(config), &root, 4*1024*1024) != nil || root == nil {
		return "", errors.New("invalid bounded multihop MTU graph")
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return "", errors.New("MTU graph has no TUN")
	}
	var tun, entry, exit map[string]any
	for _, raw := range inbounds {
		value, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid MTU inbound")
		}
		if value["type"] == "tun" {
			if tun != nil {
				return "", errors.New("multiple MTU TUN owners")
			}
			tun = value
		}
	}
	endpoints := []any{}
	if raw, exists := root["endpoints"]; exists {
		var valid bool
		endpoints, valid = raw.([]any)
		if !valid {
			return "", errors.New("MTU graph has malformed endpoints")
		}
	}
	for _, raw := range endpoints {
		value, ok := raw.(map[string]any)
		if !ok || value["type"] != "wireguard" && value["type"] != AmneziaType {
			return "", errors.New("unowned MTU endpoint")
		}
		switch value["tag"] {
		case "entry-wg", "routervpn-hop-entry":
			if entry != nil {
				return "", errors.New("multiple MTU entry owners")
			}
			entry = value
		case "proxy":
			if exit != nil {
				return "", errors.New("multiple MTU exit owners")
			}
			exit = value
		default:
			return "", errors.New("unowned MTU endpoint tag")
		}
	}
	proxyEntry := false
	outbounds, ok := root["outbounds"].([]any)
	if !ok {
		return "", errors.New("MTU graph has malformed outbounds")
	}
	for _, raw := range outbounds {
		value, valid := raw.(map[string]any)
		if !valid {
			return "", errors.New("invalid MTU outbound")
		}
		if value["tag"] != "entry-wg" && value["tag"] != "routervpn-hop-entry" {
			continue
		}
		mode := proxyModeForOutbound(value)
		if entry != nil || !ProxyEntryMode(mode) {
			return "", errors.New("MTU entry is ambiguous or in the wrong manager")
		}
		if err := validateProxyEntry(value, mode); err != nil {
			return "", err
		}
		entry, proxyEntry = value, true
	}
	if tun == nil || entry == nil || tun["auto_route"] != true || tun["strict_route"] != true {
		return "", errors.New("MTU requires exactly one full-device TUN and native entry")
	}
	entryMTU := 0
	if proxyEntry {
		// A proxy owns no IP interface. Its fixed setting therefore constrains
		// the one OS TUN, not an invented WireGuard-sized packet envelope.
		if entryFixed != 0 {
			if exitFixed != 0 && entryFixed != exitFixed {
				return "", errors.New("proxy entry and exit fixed MTUs disagree for the one shared TUN")
			}
			exitFixed = entryFixed
		}
	} else {
		entryMTU, err = mtuNumber(entry["mtu"])
		if err != nil {
			return "", err
		}
		if entryFixed != 0 {
			entryMTU = entryFixed
		}
		entry["mtu"] = entryMTU
	}
	tunMTU, err := mtuNumber(tun["mtu"])
	if err != nil {
		return "", err
	}
	if exitFixed != 0 {
		tunMTU = exitFixed
	}
	if exit != nil {
		if exit["detour"] != entry["tag"] {
			return "", errors.New("nested MTU exit lost its entry dialer")
		}
		peers, ok := exit["peers"].([]any)
		if !ok || len(peers) != 1 {
			return "", errors.New("nested MTU requires one exit peer")
		}
		peer, ok := peers[0].(map[string]any)
		if !ok {
			return "", errors.New("invalid nested MTU peer")
		}
		host, ok := peer["address"].(string)
		if !ok || !wireGuardServerIP(host) {
			return "", errors.New("nested MTU requires a literal exit endpoint")
		}
		overhead := 60
		if strings.Contains(host, ":") {
			overhead = 80
		}
		if exit["type"] == AmneziaType {
			encoded, marshalErr := json.Marshal(exit)
			if marshalErr != nil {
				return "", marshalErr
			}
			native, validationErr := AmneziaRuntimeConfig(string(encoded))
			if validationErr != nil {
				return "", validationErr
			}
			// S4 is wire padding outside the encrypted inner IP packet. Do not
			// calculate a WG-sized envelope then silently fragment AWG packets.
			overhead += native.TransportPadding
		}
		limit := 9000
		if !proxyEntry {
			limit = (entryMTU - overhead) / 16 * 16
		}
		if limit < 1280 {
			return "", errors.New("entry MTU cannot carry a dual-stack nested WireGuard packet")
		}
		exitMTU, err := mtuNumber(exit["mtu"])
		if err != nil {
			return "", err
		}
		if exitFixed != 0 {
			exitMTU = exitFixed
		} else if exitMTU > limit {
			exitMTU = limit
		}
		if exitMTU > limit {
			return "", errors.New("fixed exit MTU does not fit inside the entry; policy was not silently clamped")
		}
		exit["mtu"] = exitMTU
		if exitFixed == 0 && tunMTU > exitMTU {
			tunMTU = exitMTU
		}
	}
	tun["mtu"] = tunMTU
	route, ok := root["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return "", errors.New("MTU policy lost the owned exit route")
	}
	ipv6Off := false
	for _, profile := range []map[string]any{pair.Entry, pair.Exit} {
		if value, exists := profile["ipv6_mode"]; exists {
			mode, valid := value.(string)
			if !valid {
				return "", errors.New("IPv6 policy must be on or off")
			}
			switch mode {
			case "on", "":
			case "off":
				ipv6Off = true
			default:
				return "", errors.New("unsupported frozen IPv6 policy")
			}
		}
	}
	if ipv6Off {
		tag, ok := tun["tag"].(string)
		if !ok || !exactID.MatchString(tag) {
			return "", errors.New("IPv6 rejection requires an owned TUN tag")
		}
		rules := []any{}
		if raw, exists := route["rules"]; exists {
			var valid bool
			rules, valid = raw.([]any)
			if !valid {
				return "", errors.New("invalid frozen route rules")
			}
		}
		// Capture IPv6 in the TUN and reject client traffic there. Omitting its
		// OS route would leak it. Private native proof and DNS dialers stay owned.
		route["rules"] = append([]any{map[string]any{"inbound": []string{tag}, "ip_version": 6, "action": "reject"}}, rules...)
		dns, ok := root["dns"].(map[string]any)
		if !ok {
			return "", errors.New("IPv6 policy requires owned exit DNS")
		}
		dns["strategy"] = "ipv4_only"
	}
	encoded, err := json.Marshal(root)
	return string(encoded), err
}

// MultihopMTUProfile freezes the effective exit-side optimizer policy. A proxy
// entry's fixed value must not be overwritten later by the exit's Auto worker.
// Packet entries retain their separate inner interface setting as before.
func MultihopMTUProfile(config, profiles string) (string, error) {
	checked, err := ApplyMTUPolicy(config, profiles)
	if err != nil {
		return "", err
	}
	var pair struct {
		Entry map[string]any `json:"entry"`
		Exit  map[string]any `json:"exit"`
	}
	if err = exactJSON([]byte(profiles), &pair, 256*1024); err != nil {
		return "", err
	}
	var graph map[string]any
	if err = json.Unmarshal([]byte(checked), &graph); err != nil {
		return "", err
	}
	for _, raw := range graph["outbounds"].([]any) {
		out := raw.(map[string]any)
		if out["tag"] != "entry-wg" && out["tag"] != "routervpn-hop-entry" {
			continue
		}
		if mtu, err := fixedMTU(pair.Entry); err != nil {
			return "", err
		} else if mtu != 0 {
			pair.Exit["mtu_policy"], pair.Exit["manual_mtu"] = "fixed", mtu
		}
	}
	encoded, err := json.Marshal(pair.Exit)
	return string(encoded), err
}

func fixedMTU(profile map[string]any) (int, error) {
	mode := "auto"
	if value, exists := profile["mtu_policy"]; exists {
		var ok bool
		mode, ok = value.(string)
		if !ok {
			return 0, errors.New("MTU policy must be a string")
		}
		mode = strings.ToLower(strings.TrimSpace(mode))
	}
	switch mode {
	case "", "auto", "default":
		return 0, nil
	case "manual", "fixed":
		return mtuNumber(profile["manual_mtu"])
	default:
		return 0, errors.New("unknown MTU policy")
	}
}
func mtuNumber(value any) (int, error) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < 1280 || number > 9000 {
		return 0, errors.New("dual-stack MTU must be an integer from 1280 through 9000")
	}
	return int(number), nil
}
