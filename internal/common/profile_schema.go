package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

type routerProfileWire RouterProfile
type routerProfileStoreWire RouterProfileStore

const (
	DAITALikeMinRateKbps = 32
	DAITALikeMaxRateKbps = 192
)

func ValidNodeProofID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 { return false }
	for _, r := range value { if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) { return false } }
	return true
}

func validExternalWGKey(value, label string, optional bool) error {
	value = strings.TrimSpace(value)
	if value == "" && optional { return nil }
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 { return fmt.Errorf("%s must be a 32-byte base64 WireGuard key", label) }
	return nil
}

func validExternalCIDRs(values []string, label string, required bool) error {
	if required && len(values) == 0 { return fmt.Errorf("%s is required", label) }
	if len(values) > 32 { return fmt.Errorf("%s has too many entries", label) }
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
		if _, _, err := net.ParseCIDR(values[i]); err != nil { return fmt.Errorf("invalid %s %q", label, values[i]) }
	}
	return nil
}

// NormalizeExpectedPublicIP accepts only an address that can truthfully identify
// an Internet exit. Documentation/test unicast ranges remain valid test fixtures,
// while private, loopback, link-local, multicast, unspecified, and CGNAT space do
// not qualify as a public VPN exit proof target.
func NormalizeExpectedPublicIP(value string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", fmt.Errorf("expected public exit IP must be a public unicast address")
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return "", fmt.Errorf("expected public exit IP cannot use carrier-grade NAT space")
	}
	return ip.String(), nil
}

func normalizeExternalHTTPConnect(c *ExternalHTTPConnectConfig, tls bool) error {
	if c == nil { return fmt.Errorf("external CONNECT proxy configuration is missing") }
	c.Host = strings.Trim(strings.TrimSpace(c.Host), "[]")
	c.Username = strings.TrimSpace(c.Username)
	c.TLSServerName = strings.TrimSpace(c.TLSServerName)
	if c.Host == "" || strings.ContainsAny(c.Host, " /\\?#@") { return fmt.Errorf("external CONNECT proxy requires a safe host") }
	if c.Port < 1 || c.Port > 65535 { return fmt.Errorf("external CONNECT proxy requires a valid port") }
	if (c.Username == "") != (c.Password == "") { return fmt.Errorf("external CONNECT proxy username/password must be supplied together") }
	if len(c.Username) > 4096 || len(c.Password) > 4096 || len(c.TLSServerName) > 4096 { return fmt.Errorf("external CONNECT proxy credential/TLS field is too long") }
	if tls {
		if c.TLSServerName == "" || strings.ContainsAny(c.TLSServerName, " /\\?#@") { return fmt.Errorf("external HTTPS CONNECT requires a safe TLS server name") }
	} else if c.TLSServerName != "" {
		return fmt.Errorf("external HTTP CONNECT cannot specify a TLS server name; choose https-connect instead")
	}
	return nil
}

func normalizeExternalNode(ext *ExternalNodeConfig) error {
	if ext == nil { return fmt.Errorf("external node requires protocol configuration") }
	ext.Protocol = strings.ToLower(strings.TrimSpace(ext.Protocol))
	switch ext.Protocol {
	case "http", "http_connect", "http-connect": ext.Protocol = "http-connect"
	case "https", "https_connect", "https-connect": ext.Protocol = "https-connect"
	case "tor", "tor_bridge", "tor-bridge": ext.Protocol = "tor-bridge"
	}
	ext.ExpectedPublicIP = strings.TrimSpace(ext.ExpectedPublicIP)
	if ext.Protocol == "tor-bridge" {
		if ext.ExpectedPublicIP != "" { return fmt.Errorf("Tor bridge has a dynamic circuit exit; expected_public_ip must be empty and the runtime must prove/observe the live Tor exit") }
	} else {
		normalized, err := NormalizeExpectedPublicIP(ext.ExpectedPublicIP)
		if err != nil {
			return fmt.Errorf("external node expected_public_ip must be the public address expected after traffic really exits through this node: %w", err)
		}
		ext.ExpectedPublicIP = normalized
	}

	blocks := 0
	if ext.WireGuard != nil { blocks++ }
	if ext.OpenVPN != nil { blocks++ }
	if ext.Shadowsocks != nil { blocks++ }
	if ext.SOCKS5 != nil { blocks++ }
	if ext.HTTPConnect != nil { blocks++ }
	if ext.HTTPSConnect != nil { blocks++ }
	if ext.Hysteria2 != nil { blocks++ }
	if ext.TorBridge != nil { blocks++ }
	if blocks != 1 { return fmt.Errorf("external node requires exactly one protocol block") }
	noHTTP := ext.HTTPConnect == nil && ext.HTTPSConnect == nil
	switch ext.Protocol {
	case "wireguard":
		if ext.WireGuard == nil || ext.OpenVPN != nil || ext.Shadowsocks != nil || ext.SOCKS5 != nil || !noHTTP || ext.Hysteria2 != nil { return fmt.Errorf("external wireguard node requires only the wireguard block") }
		w := ext.WireGuard
		w.PrivateKey = strings.TrimSpace(w.PrivateKey); w.PeerPublicKey = strings.TrimSpace(w.PeerPublicKey); w.PresharedKey = strings.TrimSpace(w.PresharedKey); w.Endpoint = strings.TrimSpace(w.Endpoint)
		if w.Endpoint == "" { return fmt.Errorf("external wireguard endpoint is empty") }
		if err := validExternalWGKey(w.PrivateKey, "external WireGuard private key", false); err != nil { return err }
		if err := validExternalWGKey(w.PeerPublicKey, "external WireGuard peer public key", false); err != nil { return err }
		if err := validExternalWGKey(w.PresharedKey, "external WireGuard preshared key", true); err != nil { return err }
		if err := validExternalCIDRs(w.Addresses, "external WireGuard interface addresses", true); err != nil { return err }
		if err := validExternalCIDRs(w.AllowedIPs, "external WireGuard allowed IPs", true); err != nil { return err }
		for i := range w.DNS { w.DNS[i] = strings.TrimSpace(w.DNS[i]); if net.ParseIP(strings.Trim(w.DNS[i], "[]")) == nil { return fmt.Errorf("external WireGuard DNS entry %q is not a literal IP address", w.DNS[i]) } }
		if w.MTU != 0 && (w.MTU < 1280 || w.MTU > 9000) { return fmt.Errorf("external WireGuard MTU %d is outside 1280..9000", w.MTU) }
	case "openvpn":
		if ext.OpenVPN == nil || ext.WireGuard != nil || ext.Shadowsocks != nil || ext.SOCKS5 != nil || !noHTTP || ext.Hysteria2 != nil { return fmt.Errorf("external openvpn node requires only the openvpn block") }
		o := ext.OpenVPN; o.Config = strings.TrimSpace(o.Config); o.Username = strings.TrimSpace(o.Username)
		if o.Config == "" { return fmt.Errorf("external openvpn config is empty") }
		if len(o.Config) > 256*1024 { return fmt.Errorf("external openvpn config exceeds 256 KiB") }
		if strings.IndexByte(o.Config, 0) >= 0 { return fmt.Errorf("external openvpn config contains NUL") }
		if (o.Username == "") != (o.Password == "") { return fmt.Errorf("external openvpn username/password must be supplied together") }
	case "shadowsocks":
		if ext.Shadowsocks == nil || ext.WireGuard != nil || ext.OpenVPN != nil || ext.SOCKS5 != nil || !noHTTP || ext.Hysteria2 != nil { return fmt.Errorf("external shadowsocks node requires only the shadowsocks block") }
		s := ext.Shadowsocks; s.Server = strings.TrimSpace(s.Server); s.Method = strings.ToLower(strings.TrimSpace(s.Method))
		allowed := map[string]bool{"2022-blake3-aes-128-gcm":true,"2022-blake3-aes-256-gcm":true,"2022-blake3-chacha20-poly1305":true,"aes-128-gcm":true,"aes-256-gcm":true,"chacha20-ietf-poly1305":true}
		if s.Server == "" || s.Port < 1 || s.Port > 65535 || !allowed[s.Method] || s.Password == "" { return fmt.Errorf("external shadowsocks requires server, valid port, supported method and password") }
	case "socks5":
		if ext.SOCKS5 == nil || ext.WireGuard != nil || ext.OpenVPN != nil || ext.Shadowsocks != nil || !noHTTP || ext.Hysteria2 != nil { return fmt.Errorf("external socks5 requires host and valid port") }
		s := ext.SOCKS5; s.Host = strings.TrimSpace(s.Host); s.Username = strings.TrimSpace(s.Username)
		if s.Host == "" || s.Port < 1 || s.Port > 65535 { return fmt.Errorf("external socks5 requires host and valid port") }
		if (s.Username == "") != (s.Password == "") { return fmt.Errorf("external socks5 username/password must be supplied together") }
	case "http-connect":
		if ext.HTTPConnect == nil || ext.HTTPSConnect != nil || ext.WireGuard != nil || ext.OpenVPN != nil || ext.Shadowsocks != nil || ext.SOCKS5 != nil || ext.Hysteria2 != nil { return fmt.Errorf("external HTTP CONNECT node requires only the http_connect block") }
		if err := normalizeExternalHTTPConnect(ext.HTTPConnect, false); err != nil { return err }
	case "https-connect":
		if ext.HTTPSConnect == nil || ext.HTTPConnect != nil || ext.WireGuard != nil || ext.OpenVPN != nil || ext.Shadowsocks != nil || ext.SOCKS5 != nil || ext.Hysteria2 != nil { return fmt.Errorf("external HTTPS CONNECT node requires only the https_connect block") }
		if err := normalizeExternalHTTPConnect(ext.HTTPSConnect, true); err != nil { return err }
	case "hysteria2":
		if ext.Hysteria2 == nil || ext.WireGuard != nil || ext.OpenVPN != nil || ext.Shadowsocks != nil || ext.SOCKS5 != nil || !noHTTP { return fmt.Errorf("external hysteria2 node requires only the hysteria2 block") }
		h := ext.Hysteria2; h.Server = strings.TrimSpace(h.Server); h.TLSServerName = strings.TrimSpace(h.TLSServerName)
		if h.Server == "" || h.Port < 1 || h.Port > 65535 || h.Password == "" || h.TLSServerName == "" || strings.ContainsAny(h.TLSServerName, " /\\?#@") { return fmt.Errorf("external hysteria2 requires server, valid port, password and safe TLS server name") }
	case "tor-bridge":
		if ext.TorBridge == nil { return fmt.Errorf("external Tor bridge requires the tor_bridge block") }
		if _, err := normalizeExternalTorBridge(ext.TorBridge); err != nil { return err }
	default:
		return fmt.Errorf("unsupported external protocol %q", ext.Protocol)
	}
	return nil
}

func externalNodeEndpoint(ext *ExternalNodeConfig) string {
	if ext == nil { return "" }
	switch ext.Protocol {
	case "wireguard":
		if ext.WireGuard != nil { value := strings.TrimSpace(ext.WireGuard.Endpoint); if h, _, err := net.SplitHostPort(value); err == nil { return strings.Trim(h, "[]") }; if i := strings.LastIndex(value, ":"); i > 0 { return strings.Trim(strings.TrimSpace(value[:i]), "[]") }; return strings.Trim(value, "[]") }
	case "shadowsocks":
		if ext.Shadowsocks != nil { return strings.TrimSpace(ext.Shadowsocks.Server) }
	case "socks5":
		if ext.SOCKS5 != nil { return strings.TrimSpace(ext.SOCKS5.Host) }
	case "http-connect":
		if ext.HTTPConnect != nil { return strings.TrimSpace(ext.HTTPConnect.Host) }
	case "https-connect":
		if ext.HTTPSConnect != nil { return strings.TrimSpace(ext.HTTPSConnect.Host) }
	case "hysteria2":
		if ext.Hysteria2 != nil { return strings.TrimSpace(ext.Hysteria2.Server) }
	case "openvpn":
		if ext.OpenVPN != nil { for _, line := range strings.Split(ext.OpenVPN.Config, "\n") { fields := strings.Fields(strings.TrimSpace(line)); if len(fields) >= 2 && strings.EqualFold(fields[0], "remote") { return strings.Trim(fields[1], "[]") } } }
	case "tor-bridge":
		if ext.TorBridge != nil { if host, err := normalizeExternalTorBridge(ext.TorBridge); err == nil { return host } }
	}
	return ""
}

func stripInjectedRouterDefaultsFromExternal(p *RouterProfile) error {
	if strings.TrimSpace(p.NodeProofID) != "" || strings.TrimSpace(p.APIToken) != "" { return fmt.Errorf("external node cannot contain Router VPN proof/admin credentials") }
	if v := strings.TrimSpace(p.RouterAPI); v != "" && v != "http://10.77.0.1:8787" { return fmt.Errorf("external node cannot contain Router VPN proof/admin credentials") }
	p.RouterAPI = ""; p.NodeProofID = ""; p.APIToken = ""; p.AdGuardIPv4 = ""; p.AdGuardIPv6 = ""; p.SocksHost = ""; p.SocksPort = 0; p.SocksUsername = ""; p.SocksPassword = ""; p.DAITAHost = ""; p.DAITAPort = 0; p.DAITARateKbps = 0; p.BaseTunnel = ""; p.BaseFallback = false; p.CustomLayers = nil
	if p.PathProbeURL == "http://10.77.0.1:8787/health" { p.PathProbeURL = "" }
	if p.DNSMode == "home" { p.DNSMode = ""; if p.DNSHost == "10.77.0.1" { p.DNSHost = "" } }
	if p.DNSMode == "" { p.DNSProtocol = ""; p.DNSPort = 0; p.DNSServerName = ""; p.DNSPath = "" }
	return nil
}

func NormalizeRouterProfile(p *RouterProfile) error {
	if p.SchemaVersion > RouterProfileSchemaVersion { return fmt.Errorf("router profile schema %d is newer than supported schema %d", p.SchemaVersion, RouterProfileSchemaVersion) }
	p.SchemaVersion = RouterProfileSchemaVersion; p.NodeKind = strings.ToLower(strings.TrimSpace(p.NodeKind)); if p.NodeKind == "" { p.NodeKind = "router-vpn" }
	switch p.NodeKind {
	case "router-vpn": if p.External != nil { return fmt.Errorf("router-vpn node cannot contain external protocol configuration") }
	case "external":
		if err := normalizeExternalNode(p.External); err != nil { return err }
		if p.Endpoint = strings.TrimSpace(p.Endpoint); p.Endpoint == "" { p.Endpoint = externalNodeEndpoint(p.External) }; if p.Endpoint == "" { return fmt.Errorf("external node has no usable endpoint") }
		if err := stripInjectedRouterDefaultsFromExternal(p); err != nil { return err }
	default: return fmt.Errorf("invalid node kind %q", p.NodeKind)
	}
	p.NodeProofID = strings.TrimSpace(p.NodeProofID); if p.NodeProofID != "" && !ValidNodeProofID(p.NodeProofID) { return fmt.Errorf("invalid node proof id") }
	p.KillSwitchPolicy = strings.ToLower(strings.TrimSpace(p.KillSwitchPolicy)); if p.KillSwitchPolicy == "" { if p.KillSwitch { p.KillSwitchPolicy = "on-connect" } else { p.KillSwitchPolicy = "off" } }; switch p.KillSwitchPolicy { case "off", "on-connect", "always": default: return fmt.Errorf("invalid kill switch policy %q", p.KillSwitchPolicy) }; p.KillSwitch = p.KillSwitchPolicy != "off"
	p.StartupMode = strings.ToLower(strings.TrimSpace(p.StartupMode)); if p.StartupMode == "" { p.StartupMode = "smart-auto" }; switch p.StartupMode { case "manual", "auto", "smart-auto", "last": default: return fmt.Errorf("invalid startup mode %q", p.StartupMode) }
	p.IPv6Mode = strings.ToLower(strings.TrimSpace(p.IPv6Mode)); if p.IPv6Mode == "" { p.IPv6Mode = "on" }; switch p.IPv6Mode { case "auto", "on", "off": default: return fmt.Errorf("invalid IPv6 mode %q", p.IPv6Mode) }
	p.MTUPolicy = strings.ToLower(strings.TrimSpace(p.MTUPolicy)); if p.MTUPolicy == "" { p.MTUPolicy = "auto" }; switch p.MTUPolicy { case "default", "auto": p.ManualMTU = 0; case "manual": if p.ManualMTU < 576 || p.ManualMTU > 9000 { return fmt.Errorf("manual MTU %d is outside 576..9000", p.ManualMTU) }; default: return fmt.Errorf("invalid MTU policy %q", p.MTUPolicy) }
	if p.DAITARateKbps != 0 && (p.DAITARateKbps < DAITALikeMinRateKbps || p.DAITARateKbps > DAITALikeMaxRateKbps) { return fmt.Errorf("DAITA-like rate %d kbps is outside bounded %d..%d", p.DAITARateKbps, DAITALikeMinRateKbps, DAITALikeMaxRateKbps) }
	if p.DiagnosticsRetentionDays == 0 { p.DiagnosticsRetentionDays = 7 }; if p.DiagnosticsRetentionDays < 1 || p.DiagnosticsRetentionDays > 365 { return fmt.Errorf("diagnostics retention must be between 1 and 365 days") }
	p.MultihopEntryID = strings.TrimSpace(p.MultihopEntryID); p.MultihopExitID = strings.TrimSpace(p.MultihopExitID); if p.MultihopEnabled { if p.MultihopEntryID == "" || p.MultihopExitID == "" { return fmt.Errorf("multihop requires both an entry node and an exit node") }; if p.MultihopEntryID == p.MultihopExitID { return fmt.Errorf("multihop entry and exit nodes must be different") } }
	return nil
}

func NormalizeRouterProfileStore(s *RouterProfileStore) error {
	if s.SchemaVersion > RouterProfileStoreVersion { return fmt.Errorf("router profile store schema %d is newer than supported schema %d", s.SchemaVersion, RouterProfileStoreVersion) }
	s.SchemaVersion = RouterProfileStoreVersion; seen := map[string]bool{}
	for i := range s.Profiles { if err := NormalizeRouterProfile(&s.Profiles[i]); err != nil { return fmt.Errorf("profile %q: %w", s.Profiles[i].ID, err) }; id := strings.TrimSpace(s.Profiles[i].ID); if id == "" { return fmt.Errorf("profile id is empty") }; if seen[id] { return fmt.Errorf("duplicate profile id %q", id) }; seen[id] = true }
	if s.SelectedID == "" && len(s.Profiles) > 0 { s.SelectedID = s.Profiles[0].ID }; if s.SelectedID != "" && !seen[s.SelectedID] { return fmt.Errorf("selected profile %q is not present", s.SelectedID) }; return nil
}

func (p *RouterProfile) UnmarshalJSON(data []byte) error { var raw map[string]json.RawMessage; if err := json.Unmarshal(data, &raw); err != nil { return err }; var decoded routerProfileWire; if err := json.Unmarshal(data, &decoded); err != nil { return err }; *p = RouterProfile(decoded); if _, present := raw["home_lan_access"]; !present { p.HomeLANAccess = true }; return NormalizeRouterProfile(p) }
func (p RouterProfile) MarshalJSON() ([]byte, error) { clone := p; if err := NormalizeRouterProfile(&clone); err != nil { return nil, err }; base, err := json.Marshal(routerProfileWire(clone)); if err != nil { return nil, err }; var raw map[string]json.RawMessage; if err := json.Unmarshal(base, &raw); err != nil { return nil, err }; raw["home_lan_access"], _ = json.Marshal(clone.HomeLANAccess); raw["schema_version"], _ = json.Marshal(RouterProfileSchemaVersion); return json.Marshal(raw) }
func (s *RouterProfileStore) UnmarshalJSON(data []byte) error { var decoded routerProfileStoreWire; if err := json.Unmarshal(data, &decoded); err != nil { return err }; *s = RouterProfileStore(decoded); return NormalizeRouterProfileStore(s) }
func (s RouterProfileStore) MarshalJSON() ([]byte, error) { clone := s; if err := NormalizeRouterProfileStore(&clone); err != nil { return nil, err }; return json.Marshal(routerProfileStoreWire(clone)) }