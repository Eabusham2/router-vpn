package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"router-vpn/internal/applexray"
	"router-vpn/internal/mobileperf"
	"router-vpn/internal/multihoprelay"
)

// NodeProfile is one complete, private, single-system-TUN configuration. It is
// shared by desktop launch and predecessor composition so an operating-system
// adapter cannot silently substitute a simpler transport for the saved mode.
// Compilation performs no I/O and never establishes connection readiness.
type NodeProfile struct {
	config, source, metadata string
	mode                     string
	profile                  map[string]any
}

func (p *NodeProfile) Config() string       { return p.config }
func (p *NodeProfile) SourceSHA256() string { return p.source }
func (p *NodeProfile) Metadata() string     { return p.metadata }

func NodeProfileMode(mode string) bool {
	return mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" ||
		IsPQMode(mode) || MAXMode(mode) || CompositeMode(mode) || ProxyEntryMode(mode)
}

// NewNodeProfile consumes the exact selected node, its generated base64 asset
// map, and (when selected) that same node's AES asset map. Endpoint bootstrap
// must already have frozen the outer addresses; application/DNS hostnames are
// never resolved through an ambient resolver by this compiler.
func NewNodeProfile(mode, files, profileJSON, start, dnsBootstrap string) (*NodeProfile, error) {
	if !NodeProfileMode(mode) {
		return nil, errors.New("native node profile requires an exact raw mode")
	}
	var profile map[string]any
	if exactJSON([]byte(profileJSON), &profile, 256<<10) != nil || profile == nil || profile["node_kind"] != "router-vpn" {
		return nil, errors.New("native node profile requires the complete captured Router VPN node")
	}
	if _, err := externalProfileIdentity(profile); err != nil {
		return nil, err
	}
	node := predecessorText(profile, "node_proof_id")
	if !proofID.MatchString(node) {
		return nil, errors.New("native node profile has no paired node identity")
	}
	api := predecessorText(profile, "router_api")
	if _, err := privateAPI(api); err != nil {
		return nil, err
	}
	layer, err := externalOptionalString(profile, "start_layer")
	if err != nil {
		return nil, err
	}
	if layer == "off" {
		layer = ""
	}
	if layer != "" && !multihoprelay.ValidLayerMode(layer) {
		return nil, errors.New("native Start Layer requires authenticated AES, with optional ciphertext whitening")
	}
	if (layer == "" || MAXMode(mode) || mode == "shadowsocks") && start != "" {
		return nil, errors.New("native node profile contains an unused Start Layer owner")
	}
	assets, err := nodeProfileAssets(files)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, data := range assets {
			clear(data)
		}
	}()
	policy, _ := json.Marshal(map[string]any{"mode": layer, "raw_mode": mode, "node_kind": "router-vpn", "router_api": api})
	var aes []byte
	if start != "" {
		captured, err := nodeProfileAssets(start)
		if err != nil || len(captured) != 1 || len(captured["sing-box.json"]) == 0 {
			return nil, errors.New("native Start Layer requires its one exact AES source")
		}
		aes = captured["sing-box.json"]
		defer clear(aes)
	} else if layer != "" && !MAXMode(mode) && mode != "shadowsocks" {
		return nil, errors.New("selected Start Layer source is missing")
	}
	var source string
	switch {
	case MAXMode(mode):
		metadata, _ := json.Marshal(map[string]any{"node_id": node, "node_kind": "router-vpn", "router_api": api, "endpoint": profile["endpoint"], "start_layer": layer})
		source, err = CompileMAXProfile(mode, files, string(metadata))
	case CompositeMode(mode):
		metadata, _ := json.Marshal(map[string]any{"node_id": node, "node_kind": "router-vpn", "router_api": api, "start_layer": layer})
		source, err = CompileCompositeProfile(mode, files, string(metadata), start)
	case IsPQMode(mode):
		source, err = CompilePQProfile(mode, files, node)
		if err == nil && layer != "" {
			source, err = ComposeNativeBaseStartLayer(source, string(aes), string(policy))
		}
	case mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong":
		base, baseErr := NativeBaseSourceForEndpoint(mode, assets, predecessorText(profile, "endpoint"))
		if baseErr != nil {
			return nil, baseErr
		}
		if mode == "wg" {
			source, err = WireGuardExitConfig(string(base), node)
		} else {
			source, err = AmneziaExitConfig(string(base), node)
		}
		if err == nil && layer != "" {
			source, err = ComposeNativeBaseStartLayer(source, string(aes), string(policy))
		}
	case XrayEntryMode(mode):
		source, err = compileNodeProxy(mode, files, "", "")
		if err == nil && layer != "" {
			var compiled []byte
			compiled, err = applexray.ComposeStartLayer(mode, []byte(source), assets["xray.json"], aes, policy)
			source = string(compiled)
		}
	default:
		source, err = compileNodeProxy(mode, files, start, layer)
	}
	if err != nil {
		return nil, err
	}
	var graph map[string]any
	if exactJSON([]byte(source), &graph, 4<<20) != nil {
		return nil, errors.New("native node compiler returned an invalid graph")
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) != 1 {
		return nil, errors.New("native node must retain one system TUN")
	}
	tun, ok := ins[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return nil, errors.New("native node lost its full-device interface")
	}
	// A saved effective_mtu is history, never evidence about this connection.
	tun["mtu"] = float64(1280)
	if tun["tag"] == nil {
		tun["tag"] = "tun-in"
	}
	if tun["address"] == nil {
		tun["address"] = []any{"172.29.94.1/30", "fd29:94::1/126"}
	}
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return nil, errors.New("native node has no exact final transport")
	}
	var final map[string]any
	for _, family := range []string{"outbounds", "endpoints"} {
		rows, _ := graph[family].([]any)
		for _, raw := range rows {
			value, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("native node contains an invalid transport")
			}
			if value["tag"] == "proxy" {
				if final != nil {
					return nil, errors.New("native final transport is ambiguous")
				}
				final = value
			}
		}
	}
	if final == nil {
		return nil, errors.New("native final transport is missing")
	}
	mtu, err := fixedMTU(profile)
	if err != nil {
		return nil, err
	}
	if mtu != 0 {
		tun["mtu"] = float64(mtu)
		if final["type"] == "wireguard" || final["type"] == AmneziaType || final["type"] == PQType {
			final["mtu"] = float64(mtu)
		}
	}
	ipv6, blocked, err := externalDevicePolicy(profile)
	if err != nil {
		return nil, err
	}
	selection := externalPolicyCapture{Profile: profile, Entry: profile, EntryTag: "proxy"}
	if dnsBootstrap != "" {
		if exactJSON([]byte(dnsBootstrap), &selection.DNSBootstrap, 16384) != nil || selection.DNSBootstrap == nil {
			return nil, errors.New("native DNS bootstrap is invalid")
		}
		// The shared DNS validator owns this temporary tag; the returned DNS
		// transports are retagged once, before the final graph is validated.
		if selection.DNSBootstrap.Server["detour"] == "proxy" && profile["dns_mode"] != "home" && profile["dns_mode"] != nil && profile["dns_mode"] != "" {
			selection.DNSBootstrap.Server["detour"] = ExternalFinalTag
		}
	}
	dns, dnsMeta, err := externalSelectedDNS(selection, ipv6, true)
	if err != nil {
		return nil, err
	}
	for _, raw := range dns["servers"].([]any) {
		server := raw.(map[string]any)
		if server["detour"] == ExternalFinalTag {
			server["detour"] = "proxy"
		}
	}
	graph["dns"] = dns
	// The protocol compilers produce one final owner (including composite TCP
	// and UDP lanes). Policy routing is generated from the captured preference;
	// arbitrary source routes have already been rejected by those compilers.
	rules := []any{}
	tag := tun["tag"]
	if ipv6 == "off" {
		tun["route_address"] = []any{"0.0.0.0/0", "::/0"}
		rules = append(rules, map[string]any{"inbound": []any{tag}, "ip_version": float64(6), "action": "reject"})
	}
	rules = append(rules, map[string]any{"inbound": []any{tag}, "protocol": "dns", "action": "hijack-dns"}, map[string]any{"inbound": []any{tag}, "port": float64(53), "action": "hijack-dns"})
	if len(blocked) != 0 {
		rules = append(rules, map[string]any{"inbound": []any{tag}, "ip_cidr": blocked, "action": "reject"})
	}
	route["rules"], route["auto_detect_interface"] = rules, true
	delete(route, "default_domain_resolver")
	encoded, _ := json.Marshal(graph)
	pair, _ := json.Marshal(map[string]any{"entry": profile, "exit": profile})
	configured, err := mobileperf.Apply(string(encoded), string(pair))
	if err != nil {
		return nil, err
	}
	// This shared validator checks the complete transport closure, mandatory PQ,
	// both composite lanes, retained Start Layer, DNS and performance ownership.
	checked, err := newExternalPredecessor(externalPolicyCapture{Entry: profile, EntryTag: externalEntryTag, Profile: map[string]any{"multihop_entry_mode": mode}, PredecessorConfig: configured})
	if err != nil {
		return nil, err
	}
	encoded, err = json.Marshal(checked.graph)
	if err != nil {
		return nil, err
	}
	capture, _ := json.Marshal([]string{"routervpn-node-profile-v1", mode, files, profileJSON, start, dnsBootstrap})
	sourceSHA := externalDigest(capture)
	clear(capture)
	metadata, err := json.Marshal(map[string]any{"schema": 1, "source_sha256": sourceSHA, "config_sha256": externalDigest(encoded), "profile_id": profile["id"], "node_id": node, "mode": mode, "start_layer": layer, "dns_mode": dnsMeta.mode, "dns_protocol": dnsMeta.protocol, "dns_server": dnsMeta.host, "configured_mtu": checked.tun["mtu"], "measurement": "pending-live-proof"})
	if err != nil {
		return nil, err
	}
	return &NodeProfile{config: string(encoded), source: sourceSHA, metadata: string(metadata), mode: mode, profile: profile}, nil
}

func nodeProfileAssets(raw string) (map[string][]byte, error) {
	var encoded map[string]string
	if exactJSON([]byte(raw), &encoded, 16<<20) != nil || len(encoded) == 0 || len(encoded) > 32 {
		return nil, errors.New("native profile assets are invalid")
	}
	result := map[string][]byte{}
	total := 0
	for name, value := range encoded {
		if !exactID.MatchString(name) || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
			return nil, errors.New("native profile asset name is invalid")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(data) == 0 || len(data) > 4<<20 || base64.StdEncoding.EncodeToString(data) != value {
			return nil, errors.New("native profile asset encoding is invalid")
		}
		total += len(data)
		if total > 12<<20 {
			return nil, errors.New("native profile assets exceed their bound")
		}
		result[name] = data
	}
	return result, nil
}

func compileNodeProxy(mode, files, start, layer string) (string, error) {
	raw, err := CompileProxyEntry(files, mode)
	if err != nil {
		return "", err
	}
	var out map[string]any
	if json.Unmarshal([]byte(raw), &out) != nil {
		return "", errors.New("native proxy output is invalid")
	}
	out["tag"] = "proxy"
	outs := []any{out}
	if layer != "" {
		outer := out
		if mode != "shadowsocks" {
			compiled, err := CompileProxyEntry(start, "shadowsocks")
			if err != nil {
				return "", err
			}
			outer = nil
			if json.Unmarshal([]byte(compiled), &outer) != nil {
				return "", errors.New("native AES source is invalid")
			}
			if out["server"] != outer["server"] {
				return "", errors.New("Start Layer and inner transport belong to different node endpoints")
			}
		}
		if outer["method"] != NativeStartLayerMethod {
			return "", errors.New("Start Layer requires exact SS2022 AES-256-GCM")
		}
		password, _ := outer["password"].(string)
		for _, key := range strings.Split(password, ":") {
			bytes, err := base64.StdEncoding.Strict().DecodeString(key)
			if err != nil || len(bytes) != 32 {
				return "", errors.New("Start Layer requires exact authenticated 256-bit keys")
			}
			clear(bytes)
		}
		if layer == "aes-256-gcm+xor-whitening" {
			outer["type"], outer["server_port"] = "routervpn-aes-xor", float64(8389)
		}
		if mode != "shadowsocks" {
			outer["tag"] = NativeStartLayerTag
			out["server"], out["detour"] = "127.0.0.1", NativeStartLayerTag
			outs = append(outs, outer)
		}
	}
	graph := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true, "stack": "system", "mtu": 1280, "address": []any{"172.29.94.1/30", "fd29:94::1/126"}}}, "outbounds": outs, "route": map[string]any{"final": "proxy", "auto_detect_interface": true}}
	result, err := json.Marshal(graph)
	if err != nil {
		return "", fmt.Errorf("compile native proxy: %w", err)
	}
	return string(result), nil
}
