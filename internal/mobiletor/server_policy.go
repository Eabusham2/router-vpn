package mobiletor

import (
	"encoding/json"
	"errors"
	"strconv"

	"router-vpn/internal/common"
)

const ServerTorUnderlayTag = "routervpn-tor-server-underlay"

// ServerTorPolicy is an immutable operator-owned source. It is not a desktop
// connection profile and has no TUN, device-policy, fixed-exit or measurement
// authority. The server registry and the lease independently pin its two
// digests before a native worker may use it.
type ServerTorPolicy struct {
	source, sourceSHA256, dnsSHA256 string
	id, entry, mode                 string
	dns                             SelectedDNS
	selected                        string
	bridges                         []string
}

func (p *ServerTorPolicy) Source() string          { return p.source }
func (p *ServerTorPolicy) SourceSHA256() string    { return p.sourceSHA256 }
func (p *ServerTorPolicy) DNSPolicySHA256() string { return p.dnsSHA256 }
func (p *ServerTorPolicy) ID() string              { return p.id }
func (p *ServerTorPolicy) EntryNodeID() string     { return p.entry }
func (p *ServerTorPolicy) Mode() string            { return p.mode }
func (p *ServerTorPolicy) DNS() SelectedDNS        { return p.dns }

func (p *ServerTorPolicy) Plan() (Plan, error) {
	if p == nil || p.mode != "tor-bridge" {
		return Plan{}, errors.New("plain Tor has no bridge plan")
	}
	return NewPlan(common.ExternalTorBridgeConfig{Transport: "custom", Bridges: append([]string(nil), p.bridges...)})
}

// NewServerTorPolicy accepts only a bounded data-only private registry entry.
// Home DNS authority is the exact local Router identity and its saved private
// AdGuard addresses. A caller cannot supply another Router's API credentials,
// a native graph, torrc, executable, SOCKS endpoint or successful proof here.
func NewServerTorPolicy(source, entryNodeID string) (*ServerTorPolicy, error) {
	bad := errors.New("invalid private server Tor source")
	object, err := profileObject(source, 64<<10)
	if err != nil || !capturedHex(entryNodeID, 32) ||
		!serverTorFields(object, []string{"schema", "id", "entry_node_id", "mode", "dns"}, []string{"tor_bridge", "adguard_ipv4", "adguard_ipv6"}) {
		return nil, bad
	}
	schema, err := profileInteger(object, "schema", 0)
	id, idOK := object["id"].(string)
	mode, modeOK := object["mode"].(string)
	if err != nil || schema != 1 || !idOK || !profileIdentifier.MatchString(id) || object["entry_node_id"] != entryNodeID || !modeOK || (mode != "tor" && mode != "tor-bridge") {
		return nil, bad
	}
	canonical := map[string]any{"schema": 1, "id": id, "entry_node_id": entryNodeID, "mode": mode}
	var bridges []string
	if mode == "tor-bridge" {
		bridge, ok := object["tor_bridge"].(map[string]any)
		if !ok || !serverTorFields(bridge, []string{"transport", "bridges"}, nil) {
			return nil, bad
		}
		raw, _ := json.Marshal(bridge)
		var configuration common.ExternalTorBridgeConfig
		if json.Unmarshal(raw, &configuration) != nil {
			return nil, bad
		}
		plan, err := NewPlan(configuration)
		if err != nil {
			return nil, bad
		}
		for _, bridge := range plan.Bridges {
			bridges = append(bridges, bridge.Line)
		}
		canonical["tor_bridge"] = map[string]any{"transport": "custom", "bridges": bridges}
	} else if _, exists := object["tor_bridge"]; exists {
		return nil, bad
	}
	dns, ok := object["dns"].(map[string]any)
	if !ok || !serverTorFields(dns, nil, []string{"mode", "transport", "address", "port", "server_name", "path"}) {
		return nil, bad
	}
	profile := map[string]any{}
	for sourceKey, profileKey := range map[string]string{"mode": "dns_mode", "transport": "dns_protocol", "address": "dns_host", "server_name": "dns_server_name", "path": "dns_path"} {
		if value, exists := dns[sourceKey]; exists {
			text, ok := value.(string)
			if !ok {
				return nil, bad
			}
			profile[profileKey] = text
		}
	}
	if profileString(profile, "dns_mode") == "" {
		profile["dns_mode"] = "home"
	}
	// This private schema uses three explicit modes. Transport aliases and
	// application-only Fastest selections must be resolved before registry save.
	if mode := profileString(profile, "dns_mode"); mode != "home" && mode != "custom" && mode != "rescue" {
		return nil, bad
	}
	if value, exists := dns["port"]; exists {
		profile["dns_port"] = value
	}
	home := map[string]any{"node_kind": "router-vpn"}
	for _, key := range []string{"adguard_ipv4", "adguard_ipv6"} {
		if value, exists := object[key]; exists {
			text, ok := value.(string)
			if !ok || text == "" || profileString(profile, "dns_mode") != "home" {
				return nil, bad
			}
			home[key], canonical[key] = text, text
		}
	}
	selected, _, err := torSelectedDNS(profile, home, false)
	if err != nil {
		return nil, bad
	}
	metadata, err := selectedDNSMetadata(profile, selected)
	if err != nil {
		return nil, bad
	}
	// Explicit fields cannot be silently ignored by defaults, aliases or the
	// rescue preset. The normalized result is what source and DNS digests bind.
	for key, actual := range map[string]string{"mode": metadata.Mode, "transport": metadata.Transport, "address": metadata.Address, "server_name": metadata.ServerName, "path": metadata.Path} {
		if value, exists := dns[key]; exists && value != "" && value != actual {
			return nil, bad
		}
	}
	if _, exists := dns["port"]; exists {
		port, err := profileInteger(dns, "port", 0)
		if err != nil || port != 0 && port != metadata.Port {
			return nil, bad
		}
	}
	canonical["dns"] = metadata
	dnsCapture := map[string]any{"dns": metadata}
	if metadata.Mode == "home" {
		dnsCapture["entry_node_id"] = entryNodeID
		for _, key := range []string{"adguard_ipv4", "adguard_ipv6"} {
			if value, exists := canonical[key]; exists {
				dnsCapture[key] = value
			}
		}
	}
	canonicalJSON, _ := json.Marshal(canonical)
	dnsJSON, _ := json.Marshal(dnsCapture)
	selectedJSON, _ := json.Marshal(selected)
	return &ServerTorPolicy{source: string(canonicalJSON), sourceSHA256: capturedDigest(canonicalJSON), dnsSHA256: capturedDigest(dnsJSON), id: id, entry: entryNodeID, mode: mode, dns: metadata, selected: string(selectedJSON), bridges: bridges}, nil
}

func serverTorFields(object map[string]any, required, optional []string) bool {
	allowed := map[string]bool{}
	for _, name := range required {
		if value, exists := object[name]; !exists || value == nil {
			return false
		}
		allowed[name] = true
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name, value := range object {
		if !allowed[name] || value == nil {
			return false
		}
	}
	return true
}

// NativeConfig is an exact no-TUN graph used only inside the leased worker.
// Application DNS uses the chosen Tor circuit, except Home which stays on the
// local server's captured private AdGuard path. Bootstrap uses the same chosen
// resolver on the server underlay. Neither lane inherits host-default DNS.
// A parsed graph grants no readiness: the front remains gated until live proof.
func (p *ServerTorPolicy) NativeConfig(socksPort int, username, password string) (string, error) {
	if p == nil || socksPort < 1024 || socksPort > 65535 || !capturedHex(username, 32) || !capturedHex(password, 32) || username == password {
		return "", errors.New("server Tor requires its captured private SOCKS isolation")
	}
	selected, err := profileObject(p.selected, 16<<10)
	if err != nil {
		return "", err
	}
	bootstrap, err := profileObject(p.selected, 16<<10)
	if err != nil {
		return "", err
	}
	selected["tag"], selected["detour"] = profileDNS, ProfileOutboundTag
	if p.dns.Mode == "home" {
		selected["detour"] = ServerTorUnderlayTag
	}
	bootstrap["tag"], bootstrap["detour"] = bootstrapDNS, ServerTorUnderlayTag
	graph := map[string]any{
		"log": map[string]any{"disabled": true},
		"dns": map[string]any{"servers": []any{bootstrap, selected}, "final": profileDNS, "independent_cache": true},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": ServerTorUnderlayTag, "domain_resolver": map[string]any{"server": bootstrapDNS}},
			map[string]any{"type": "socks", "tag": ProfileOutboundTag, "server": "127.0.0.1", "server_port": socksPort, "version": "5", "username": username, "password": password, "network": "tcp"},
		},
		"route": map[string]any{"auto_detect_interface": true, "default_domain_resolver": map[string]any{"server": profileDNS}, "final": ProfileOutboundTag},
	}
	raw, err := json.Marshal(graph)
	return string(raw), err
}

func (p *ServerTorPolicy) SocksAddress(port int) (string, error) {
	if p == nil || port < 1024 || port > 65535 {
		return "", errors.New("invalid captured server Tor SOCKS port")
	}
	return "127.0.0.1:" + strconv.Itoa(port), nil
}
