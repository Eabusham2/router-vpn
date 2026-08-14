package common

import (
	"encoding/json"
	"fmt"
	"strings"
)

type routerProfileWire RouterProfile
type routerProfileStoreWire RouterProfileStore

func ValidNodeProofID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 { return false }
	for _, r := range value { if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) { return false } }
	return true
}

func normalizeExternalNode(ext *ExternalNodeConfig) error {
	if ext == nil { return fmt.Errorf("external node requires protocol configuration") }
	ext.Protocol = strings.ToLower(strings.TrimSpace(ext.Protocol))
	blocks := 0
	if ext.WireGuard != nil { blocks++ }; if ext.OpenVPN != nil { blocks++ }; if ext.Shadowsocks != nil { blocks++ }; if ext.SOCKS5 != nil { blocks++ }
	if blocks != 1 { return fmt.Errorf("external node requires exactly one protocol block") }
	switch ext.Protocol {
	case "wireguard":
		if ext.WireGuard == nil || ext.OpenVPN != nil || ext.Shadowsocks != nil || ext.SOCKS5 != nil { return fmt.Errorf("external wireguard node requires only the wireguard block") }
		w := ext.WireGuard
		w.PrivateKey = strings.TrimSpace(w.PrivateKey); w.PeerPublicKey = strings.TrimSpace(w.PeerPublicKey); w.PresharedKey = strings.TrimSpace(w.PresharedKey); w.Endpoint = strings.TrimSpace(w.Endpoint)
		if w.PrivateKey == "" || w.PeerPublicKey == "" || w.Endpoint == "" || len(w.Addresses) == 0 || len(w.AllowedIPs) == 0 { return fmt.Errorf("external wireguard requires private key, address, peer public key, endpoint and allowed IPs") }
		for i := range w.Addresses { w.Addresses[i] = strings.TrimSpace(w.Addresses[i]); if w.Addresses[i] == "" { return fmt.Errorf("external wireguard address is empty") } }
		for i := range w.AllowedIPs { w.AllowedIPs[i] = strings.TrimSpace(w.AllowedIPs[i]); if w.AllowedIPs[i] == "" { return fmt.Errorf("external wireguard allowed IP is empty") } }
		for i := range w.DNS { w.DNS[i] = strings.TrimSpace(w.DNS[i]); if w.DNS[i] == "" { return fmt.Errorf("external wireguard DNS entry is empty") } }
		if w.MTU != 0 && (w.MTU < 576 || w.MTU > 9000) { return fmt.Errorf("external wireguard MTU %d is outside 576..9000", w.MTU) }
	case "openvpn":
		if ext.OpenVPN == nil || ext.WireGuard != nil || ext.Shadowsocks != nil || ext.SOCKS5 != nil { return fmt.Errorf("external openvpn node requires only the openvpn block") }
		o := ext.OpenVPN; o.Config = strings.TrimSpace(o.Config); o.Username = strings.TrimSpace(o.Username)
		if o.Config == "" { return fmt.Errorf("external openvpn config is empty") }
		if len(o.Config) > 512*1024 { return fmt.Errorf("external openvpn config exceeds 512 KiB") }
		if strings.IndexByte(o.Config, 0) >= 0 { return fmt.Errorf("external openvpn config contains NUL") }
		if (o.Username == "") != (o.Password == "") { return fmt.Errorf("external openvpn username/password must be supplied together") }
	case "shadowsocks":
		if ext.Shadowsocks == nil || ext.WireGuard != nil || ext.OpenVPN != nil || ext.SOCKS5 != nil { return fmt.Errorf("external shadowsocks node requires only the shadowsocks block") }
		s := ext.Shadowsocks; s.Server = strings.TrimSpace(s.Server); s.Method = strings.TrimSpace(s.Method)
		if s.Server == "" || s.Port < 1 || s.Port > 65535 || s.Method == "" || s.Password == "" { return fmt.Errorf("external shadowsocks requires server, valid port, method and password") }
	case "socks5":
		if ext.SOCKS5 == nil || ext.WireGuard != nil || ext.OpenVPN != nil || ext.Shadowsocks != nil { return fmt.Errorf("external socks5 node requires only the socks5 block") }
		s := ext.SOCKS5; s.Host = strings.TrimSpace(s.Host); s.Username = strings.TrimSpace(s.Username)
		if s.Host == "" || s.Port < 1 || s.Port > 65535 { return fmt.Errorf("external socks5 requires host and valid port") }
		if (s.Username == "") != (s.Password == "") { return fmt.Errorf("external socks5 username/password must be supplied together") }
	default:
		return fmt.Errorf("unsupported external protocol %q", ext.Protocol)
	}
	return nil
}

func externalNodeEndpoint(ext *ExternalNodeConfig) string {
	if ext == nil { return "" }
	switch ext.Protocol {
	case "wireguard":
		if ext.WireGuard != nil { value := strings.TrimSpace(ext.WireGuard.Endpoint); if i := strings.LastIndex(value, ":"); i > 0 { return strings.Trim(strings.TrimSpace(value[:i]), "[]") }; return strings.Trim(value, "[]") }
	case "shadowsocks":
		if ext.Shadowsocks != nil { return strings.TrimSpace(ext.Shadowsocks.Server) }
	case "socks5":
		if ext.SOCKS5 != nil { return strings.TrimSpace(ext.SOCKS5.Host) }
	case "openvpn":
		if ext.OpenVPN != nil {
			for _, line := range strings.Split(ext.OpenVPN.Config, "\n") {
				fields := strings.Fields(strings.TrimSpace(line)); if len(fields) >= 2 && strings.EqualFold(fields[0], "remote") { return strings.Trim(fields[1], "[]") }
			}
		}
	}
	return ""
}

func stripInjectedRouterDefaultsFromExternal(p *RouterProfile) error {
	if strings.TrimSpace(p.NodeProofID) != "" || strings.TrimSpace(p.APIToken) != "" { return fmt.Errorf("external node cannot contain Router VPN proof/admin credentials") }
	if v := strings.TrimSpace(p.RouterAPI); v != "" && v != "http://10.77.0.1:8787" { return fmt.Errorf("external node cannot contain Router VPN proof/admin credentials") }
	p.RouterAPI = ""; p.NodeProofID = ""; p.APIToken = ""
	p.AdGuardIPv4 = ""; p.AdGuardIPv6 = ""; p.SocksHost = ""; p.SocksPort = 0; p.SocksUsername = ""; p.SocksPassword = ""
	p.DAITAHost = ""; p.DAITAPort = 0; p.DAITARateKbps = 0; p.BaseTunnel = ""; p.BaseFallback = false; p.CustomLayers = nil
	if p.PathProbeURL == "http://10.77.0.1:8787/health" { p.PathProbeURL = "" }
	if p.DNSMode == "home" { p.DNSMode = ""; if p.DNSHost == "10.77.0.1" { p.DNSHost = "" } }
	if p.DNSMode == "" { p.DNSProtocol = ""; p.DNSPort = 0; p.DNSServerName = ""; p.DNSPath = "" }
	return nil
}

// NormalizeRouterProfile upgrades policy defaults and validates configuration
// intent. Runtime capability remains a separate live-tested concern: a valid
// external profile or multihop selection does not claim a runtime exists.
func NormalizeRouterProfile(p *RouterProfile) error {
	if p.SchemaVersion > RouterProfileSchemaVersion { return fmt.Errorf("router profile schema %d is newer than supported schema %d", p.SchemaVersion, RouterProfileSchemaVersion) }
	p.SchemaVersion = RouterProfileSchemaVersion
	p.NodeKind = strings.ToLower(strings.TrimSpace(p.NodeKind)); if p.NodeKind == "" { p.NodeKind = "router-vpn" }
	switch p.NodeKind {
	case "router-vpn":
		if p.External != nil { return fmt.Errorf("router-vpn node cannot contain external protocol configuration") }
	case "external":
		if err := normalizeExternalNode(p.External); err != nil { return err }
		if p.Endpoint = strings.TrimSpace(p.Endpoint); p.Endpoint == "" { p.Endpoint = externalNodeEndpoint(p.External) }
		if p.Endpoint == "" { return fmt.Errorf("external node has no usable endpoint") }
		if err := stripInjectedRouterDefaultsFromExternal(p); err != nil { return err }
	default:
		return fmt.Errorf("invalid node kind %q", p.NodeKind)
	}

	p.NodeProofID = strings.TrimSpace(p.NodeProofID)
	if p.NodeProofID != "" && !ValidNodeProofID(p.NodeProofID) { return fmt.Errorf("invalid node proof id") }
	p.KillSwitchPolicy = strings.ToLower(strings.TrimSpace(p.KillSwitchPolicy)); if p.KillSwitchPolicy == "" { if p.KillSwitch { p.KillSwitchPolicy = "on-connect" } else { p.KillSwitchPolicy = "off" } }
	switch p.KillSwitchPolicy { case "off", "on-connect", "always": default: return fmt.Errorf("invalid kill switch policy %q", p.KillSwitchPolicy) }; p.KillSwitch = p.KillSwitchPolicy != "off"
	p.StartupMode = strings.ToLower(strings.TrimSpace(p.StartupMode)); if p.StartupMode == "" { p.StartupMode = "manual" }; switch p.StartupMode { case "manual", "auto", "smart-auto", "last": default: return fmt.Errorf("invalid startup mode %q", p.StartupMode) }
	p.IPv6Mode = strings.ToLower(strings.TrimSpace(p.IPv6Mode)); if p.IPv6Mode == "" { p.IPv6Mode = "auto" }; switch p.IPv6Mode { case "auto", "on", "off": default: return fmt.Errorf("invalid IPv6 mode %q", p.IPv6Mode) }
	p.MTUPolicy = strings.ToLower(strings.TrimSpace(p.MTUPolicy)); if p.MTUPolicy == "" { p.MTUPolicy = "default" }; switch p.MTUPolicy { case "default", "auto": p.ManualMTU = 0; case "manual": if p.ManualMTU < 576 || p.ManualMTU > 9000 { return fmt.Errorf("manual MTU %d is outside 576..9000", p.ManualMTU) }; default: return fmt.Errorf("invalid MTU policy %q", p.MTUPolicy) }
	if p.DiagnosticsRetentionDays == 0 { p.DiagnosticsRetentionDays = 7 }; if p.DiagnosticsRetentionDays < 1 || p.DiagnosticsRetentionDays > 365 { return fmt.Errorf("diagnostics retention must be between 1 and 365 days") }
	p.MultihopEntryID = strings.TrimSpace(p.MultihopEntryID); p.MultihopExitID = strings.TrimSpace(p.MultihopExitID)
	if p.MultihopEnabled { if p.MultihopEntryID == "" || p.MultihopExitID == "" { return fmt.Errorf("multihop requires both an entry node and an exit node") }; if p.MultihopEntryID == p.MultihopExitID { return fmt.Errorf("multihop entry and exit nodes must be different") } }
	return nil
}

func NormalizeRouterProfileStore(s *RouterProfileStore) error {
	if s.SchemaVersion > RouterProfileStoreVersion { return fmt.Errorf("router profile store schema %d is newer than supported schema %d", s.SchemaVersion, RouterProfileStoreVersion) }
	s.SchemaVersion = RouterProfileStoreVersion; seen := map[string]bool{}
	for i := range s.Profiles { if err := NormalizeRouterProfile(&s.Profiles[i]); err != nil { return fmt.Errorf("profile %q: %w", s.Profiles[i].ID, err) }; id := strings.TrimSpace(s.Profiles[i].ID); if id == "" { return fmt.Errorf("profile id is empty") }; if seen[id] { return fmt.Errorf("duplicate profile id %q", id) }; seen[id] = true }
	if s.SelectedID == "" && len(s.Profiles) > 0 { s.SelectedID = s.Profiles[0].ID }; if s.SelectedID != "" && !seen[s.SelectedID] { return fmt.Errorf("selected profile %q is not present", s.SelectedID) }
	return nil
}

func (p *RouterProfile) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage; if err := json.Unmarshal(data, &raw); err != nil { return err }
	var decoded routerProfileWire; if err := json.Unmarshal(data, &decoded); err != nil { return err }; *p = RouterProfile(decoded)
	if _, present := raw["home_lan_access"]; !present { p.HomeLANAccess = true }
	return NormalizeRouterProfile(p)
}

func (p RouterProfile) MarshalJSON() ([]byte, error) {
	clone := p; if err := NormalizeRouterProfile(&clone); err != nil { return nil, err }
	base, err := json.Marshal(routerProfileWire(clone)); if err != nil { return nil, err }; var raw map[string]json.RawMessage; if err := json.Unmarshal(base, &raw); err != nil { return nil, err }
	raw["home_lan_access"], _ = json.Marshal(clone.HomeLANAccess); raw["schema_version"], _ = json.Marshal(RouterProfileSchemaVersion); return json.Marshal(raw)
}

func (s *RouterProfileStore) UnmarshalJSON(data []byte) error { var decoded routerProfileStoreWire; if err := json.Unmarshal(data, &decoded); err != nil { return err }; *s = RouterProfileStore(decoded); return NormalizeRouterProfileStore(s) }
func (s RouterProfileStore) MarshalJSON() ([]byte, error) { clone := s; if err := NormalizeRouterProfileStore(&clone); err != nil { return nil, err }; return json.Marshal(routerProfileStoreWire(clone)) }
