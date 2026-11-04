package standardengine

import (
	"encoding/json"
	"errors"
)

type TUN struct {
	Tag, Name string
	MTU       int
}

// Configuration remains byte-for-byte the captured stock graph. This gate
// limits the new command to the six shipping direct protocols; the exact
// pinned Box parser remains responsible for every original option.
func Config(raw []byte, mode string) (TUN, error) {
	bad := errors.New("standard engine graph escaped its captured direct protocol")
	var graph map[string]json.RawMessage
	if len(raw) == 0 || len(raw) > MaxConfig || json.Unmarshal(raw, &graph) != nil {
		return TUN{}, bad
	}
	for _, key := range []string{"services", "certificate", "experimental"} {
		if _, present := graph[key]; present {
			return TUN{}, bad
		}
	}
	var inbounds []struct {
		Type string `json:"type"`
		Tag  string `json:"tag"`
		Name string `json:"interface_name"`
		MTU  int    `json:"mtu"`
	}
	if json.Unmarshal(graph["inbounds"], &inbounds) != nil {
		return TUN{}, bad
	}
	var tun TUN
	for _, inbound := range inbounds {
		switch inbound.Type {
		case "tun":
			if tun.Tag != "" || inbound.Tag == "" || inbound.Name != "router-vpn" || inbound.MTU < 1280 || inbound.MTU > 9000 {
				return TUN{}, bad
			}
			tun = TUN{inbound.Tag, inbound.Name, inbound.MTU}
		case "direct", "mixed", "socks":
		default:
			return TUN{}, bad
		}
	}
	if tun.Tag == "" {
		return TUN{}, bad
	}
	want := map[string]string{"standard-wireguard": "wireguard", "standard-socks5": "socks", "standard-http-connect": "http", "standard-https-connect": "http", "standard-shadowsocks": "shadowsocks", "standard-hysteria2": "hysteria2"}[mode]
	if want == "" {
		return TUN{}, bad
	}
	count := 0
	for _, family := range []string{"outbounds", "endpoints"} {
		if len(graph[family]) == 0 {
			continue
		}
		var nodes []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if json.Unmarshal(graph[family], &nodes) != nil {
			return TUN{}, bad
		}
		for _, node := range nodes {
			if node.Type == "direct" && family == "outbounds" {
				continue
			}
			if node.Type != want || node.Tag != "custom-exit" || (family == "endpoints") != (want == "wireguard") {
				return TUN{}, bad
			}
			count++
		}
	}
	if count != 1 {
		return TUN{}, bad
	}
	return tun, nil
}
