package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
)

const legacyDNSProofAddress = "198.18.0.53:53"

func legacyDNSProofRoute() map[string]any {
	return map[string]any{"inbound": []any{"standard-exit-proof"}, "network": "tcp", "ip_cidr": []any{"198.18.0.53/32"}, "port": float64(53), "action": "hijack-dns"}
}

func legacyDNSProofSelection() map[string]any {
	return map[string]any{"inbound": []any{"standard-exit-proof"}, "action": "route", "server": "selected-dns", "disable_cache": true}
}

// Only the retained direct Linux stock command consumes this proof channel.
// Modern native graphs keep their existing DNS router proof and ownership.
func prepareLegacyStandardDNSGraph(graph map[string]any, direct bool, exit standardExit) error {
	if runtime.GOOS != "linux" || !direct || exit.Protocol == "amneziawg" || exit.Protocol == "openvpn" || exit.StartLayer != nil {
		return nil
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok || dns["rules"] != nil || dns["final"] != "selected-dns" {
		return errors.New("legacy DNS proof cannot replace another DNS router")
	}
	route, ok := graph["route"].(map[string]any)
	if !ok {
		return errors.New("legacy DNS proof has no captured route")
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return errors.New("legacy DNS proof has no captured rules")
	}
	route["rules"] = append([]any{legacyDNSProofRoute()}, rules...)
	dns["rules"] = []any{legacyDNSProofSelection()}
	return nil
}

func validateLegacyStandardDNSGraph(raw []byte, selected dnsSelection) error {
	if err := verifySingBoxDNSConfigBytes(raw, selected); err != nil {
		return err
	}
	var graph map[string]any
	if err := json.Unmarshal(raw, &graph); err != nil {
		return err
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok || !reflect.DeepEqual(dns["rules"], []any{legacyDNSProofSelection()}) || dns["final"] != "selected-dns" {
		return errors.New("legacy DNS proof lost its uncached selected resolver")
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) != 1 {
		return errors.New("legacy DNS proof cannot adopt a fallback resolver")
	}
	server, ok := servers[0].(map[string]any)
	if !ok || server["tag"] != "selected-dns" || server["detour"] != "custom-exit" {
		return errors.New("legacy DNS proof lost its captured direct exit detour")
	}
	route, ok := graph["route"].(map[string]any)
	if !ok {
		return errors.New("legacy DNS proof has no runtime route")
	}
	rules, ok := route["rules"].([]any)
	if !ok || len(rules) == 0 || !reflect.DeepEqual(rules[0], legacyDNSProofRoute()) {
		return errors.New("legacy DNS proof lost its narrow inbound DNS interception")
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok {
		return errors.New("legacy DNS proof has no runtime listener")
	}
	count := 0
	for _, value := range inbounds {
		in, ok := value.(map[string]any)
		if !ok {
			return errors.New("legacy DNS proof has an invalid inbound")
		}
		if in["tag"] == "standard-exit-proof" {
			count++
			if !reflect.DeepEqual(in, map[string]any{"type": "mixed", "tag": "standard-exit-proof", "listen": "127.0.0.1", "listen_port": float64(1099)}) {
				return errors.New("legacy DNS proof listener changed")
			}
		}
	}
	if count != 1 {
		return errors.New("legacy DNS proof requires its sole captured listener")
	}
	return nil
}
