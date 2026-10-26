package mobiletor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"router-vpn/internal/common"
)

// DesktopBridgePolicy describes one captured standalone Tor bridge connection.
// It opens no listener, launches no process and grants no connection proof. Its
// SOCKS outbound is usable only after the native owner authenticates its exact
// Tor child and binds the bridge plan to that owner's in-process PT listeners.
type DesktopBridgePolicy struct {
	config, source string
	metadata       DesktopBridgeMetadata
	bridges        []string
}

type DesktopBridgeDNS struct {
	Mode       string `json:"mode"`
	Transport  string `json:"transport"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"server_name,omitempty"`
	Path       string `json:"path,omitempty"`
}

// Metadata records requested policy, never a measured path MTU or successful
// DNS/Tor proof. Secrets remain exclusively in the private source/configuration.
type DesktopBridgeMetadata struct {
	Schema           int              `json:"schema"`
	NodeID           string           `json:"node_id"`
	SessionID        string           `json:"session_id"`
	SourceSHA256     string           `json:"source_sha256"`
	ConfigSHA256     string           `json:"config_sha256"`
	TargetOS         string           `json:"target_os"`
	FinalTag         string           `json:"final_tag"`
	TUNTag           string           `json:"tun_tag"`
	InterfaceName    string           `json:"interface_name,omitempty"`
	SocksPort        int              `json:"socks_port"`
	DNS              DesktopBridgeDNS `json:"dns"`
	BootstrapDNSTag  string           `json:"bootstrap_dns_tag"`
	IPv6Mode         string           `json:"ipv6_mode"`
	HomeLANAccess    bool             `json:"home_lan_access"`
	KillSwitchPolicy string           `json:"kill_switch_policy"`
	MTUPolicy        string           `json:"mtu_policy"`
	ConfiguredMTU    int              `json:"configured_mtu"`
	JumboTUN         bool             `json:"jumbo_tun"`
}

// DesktopBridgeProof is the native child receipt. A control bootstrap status
// alone cannot fill it: the native host must own the TUN readback and prove the
// exact selected DNS plus the public Tor path before setting Healthy.
type DesktopBridgeProof struct {
	Schema         int                       `json:"schema"`
	SessionID      string                    `json:"session_id"`
	SourceSHA256   string                    `json:"source_sha256"`
	ConfigSHA256   string                    `json:"config_sha256"`
	Policy         DesktopBridgeMetadata     `json:"policy"`
	Proof          Proof                     `json:"proof"`
	InterfaceName  string                    `json:"interface_name"`
	InterfaceIndex int                       `json:"interface_index"`
	EffectiveMTU   int                       `json:"effective_mtu"`
	Healthy        bool                      `json:"healthy"`
	HeartbeatAt    int64                     `json:"heartbeat_at"`
	MTUReadback    *DesktopBridgeMTUReadback `json:"mtu_readback,omitempty"`
}

// DesktopBridgeMTUReadback is authority from the same native connection's
// leased TUN transaction. Revision advances only when that lease adopts a new
// candidate or rollback reader; it does not reset for a later MTU request.
// It reports interface state, never Internet PMTU or a successful measurement.
type DesktopBridgeMTUReadback struct {
	Generation     uint64 `json:"generation"`
	RequestID      string `json:"request_id"`
	Revision       uint64 `json:"revision"`
	InterfaceName  string `json:"interface_name"`
	InterfaceIndex int    `json:"interface_index"`
	EffectiveMTU   int    `json:"effective_mtu"`
}

func (p *DesktopBridgePolicy) Config() string                  { return p.config }
func (p *DesktopBridgePolicy) SourceSHA256() string            { return p.metadata.SourceSHA256 }
func (p *DesktopBridgePolicy) Metadata() DesktopBridgeMetadata { return p.metadata }
func (p *DesktopBridgePolicy) Profile() string                 { return p.source }
func (p *DesktopBridgePolicy) Plan() (Plan, error) {
	return NewPlan(common.ExternalTorBridgeConfig{Transport: "custom", Bridges: append([]string(nil), p.bridges...)})
}

// ValidateDesktopBridgeProfile checks idle saved preferences, including a
// desktop-owned fixed SOCKS port. Unresolved Home may remain saved; it does not
// become runnable or acquire a substitute public resolver. No shipping desktop
// capability is enabled merely by passing this pure validation.
func ValidateDesktopBridgeProfile(source string) error {
	profile, _, _, err := desktopBridgeProfile(source)
	if err != nil {
		return err
	}
	if _, _, err := torSelectedDNS(profile, nil, true); err != nil {
		return err
	}
	root, tun, _, _ := torPredecessor("")
	root["dns"] = map[string]any{}
	if err := applyTorDevicePolicy(root, tun, profile); err != nil {
		return err
	}
	return applyDesktopTorJumboPolicy(tun, profile)
}

// The system TUN passes TCP streams to the captured standalone Tor SOCKS
// owner. Jumbo changes only that virtual interface's capacity; it does not
// advertise a measured transport PMTU or authorize larger underlay packets.
// Keep this desktop capability separate from the mobile host's TUN contract.
func applyDesktopTorJumboPolicy(tun, profile map[string]any) error {
	if profile["jumbo_tun"] != true {
		return nil
	}
	if policy := profileString(profile, "mtu_policy"); policy == "manual" || policy == "fixed" {
		mtu, err := profileInteger(profile, "manual_mtu", 0)
		if err != nil || mtu != 9000 {
			return errors.New("desktop Tor Jumbo requires a 9000-byte virtual interface and conflicts with the saved Fixed MTU")
		}
	}
	tun["mtu"] = 9000
	return nil
}

// NewDesktopBridgePolicy compiles the exact saved direct bridge selection. The
// same resolver is separately captured for PT bootstrap on the native physical
// underlay and for application DNS through Tor. Neither uses host-default DNS.
// Router-entry composition needs its own captured predecessor implementation.
func NewDesktopBridgePolicy(source, sessionID, isolationSecret, targetOS string) (*DesktopBridgePolicy, error) {
	if !desktopHex(sessionID, 16) || !desktopHex(isolationSecret, 32) {
		return nil, errors.New("desktop Tor requires fresh captured session and SOCKS isolation identities")
	}
	if targetOS != "linux" && targetOS != "darwin" && targetOS != "windows" {
		return nil, errors.New("desktop Tor requires an explicit supported native OS")
	}
	profile, plan, socksPort, err := desktopBridgeProfile(source)
	if err != nil {
		return nil, err
	}
	if profile["multihop_enabled"] == true {
		return nil, errors.New("desktop Tor requires its captured Router-entry runtime before multihop can run")
	}
	if profile["daita_enabled"] == true {
		return nil, errors.New("desktop Tor cannot discard a requested padding policy; its authenticated native implementation is still required")
	}
	selected, _, err := torSelectedDNS(profile, nil, false)
	if err != nil {
		return nil, err
	}
	root, tun, _, _ := torPredecessor("")
	if targetOS == "linux" {
		// The strict desktop forwarding helper already owns this exact native
		// alias. Do not widen its egress exception for a new Tor-only name.
		tun["interface_name"] = "router-vpn"
	} else if targetOS == "windows" {
		tun["interface_name"] = "router-vpn-tor"
	}
	selected["tag"], selected["detour"] = profileDNS, ProfileOutboundTag
	bootstrap := make(map[string]any, len(selected))
	for key, value := range selected {
		bootstrap[key] = value
	}
	bootstrap["tag"] = bootstrapDNS
	delete(bootstrap, "detour")
	root["dns"] = map[string]any{"servers": []any{selected, bootstrap}, "final": profileDNS, "independent_cache": true}
	root["outbounds"] = []any{map[string]any{
		"type": "socks", "tag": ProfileOutboundTag, "server": "127.0.0.1", "server_port": socksPort,
		"version": "5", "username": sessionID, "password": isolationSecret,
	}}
	route := root["route"].(map[string]any)
	route["final"] = ProfileOutboundTag
	route["default_domain_resolver"] = map[string]any{"server": bootstrapDNS}
	if err := applyTorDevicePolicy(root, tun, profile); err != nil {
		return nil, err
	}
	if err := applyDesktopTorJumboPolicy(tun, profile); err != nil {
		return nil, err
	}
	// Capture classic DNS before its first packet has been protocol-classified;
	// the UDP rejection must not turn selected DNS into a host-network fallback.
	rules := route["rules"].([]any)
	for i, raw := range rules {
		if raw.(map[string]any)["action"] == "hijack-dns" {
			added := map[string]any{"inbound": []any{tun["tag"]}, "port": 53, "action": "hijack-dns"}
			rules = append(rules[:i+1], append([]any{added}, rules[i+1:]...)...)
			break
		}
	}
	route["rules"] = rules
	sourceBytes, _ := json.Marshal([]string{"routervpn-desktop-tor-policy-v1", source, sessionID, isolationSecret, targetOS})
	sourceSHA := desktopDigest(sourceBytes)
	// This exact Box service retires the native physical/PT generation on
	// every network reset, including resets whose addresses are unchanged.
	root["services"] = []any{map[string]any{
		"type": "routervpn-desktop-tor-network", "tag": "routervpn-tor-physical",
		"session_id": sessionID, "source_sha256": sourceSHA,
	}}
	encoded, err := json.Marshal(root)
	if err != nil || len(encoded) > 4<<20 {
		return nil, errors.New("desktop Tor configuration exceeds its bound")
	}
	dnsPort := selected["server_port"].(int)
	dns := DesktopBridgeDNS{Mode: profileString(profile, "dns_mode"), Transport: profileString(selected, "type"), Address: profileString(selected, "server"), Port: dnsPort, Path: profileString(selected, "path")}
	if tls, ok := selected["tls"].(map[string]any); ok {
		dns.ServerName = profileString(tls, "server_name")
	}
	mtu := 1280
	if fixed, ok := tun["mtu"].(int); ok {
		mtu = fixed
	}
	mtuPolicy := profileString(profile, "mtu_policy")
	if mtuPolicy == "" {
		mtuPolicy = "auto"
	}
	ipv6 := profileString(profile, "ipv6_mode")
	if ipv6 == "" {
		ipv6 = "on"
	}
	lan, _ := profile["home_lan_access"].(bool)
	kill, _ := desktopBridgeKillPolicy(profile, plan)
	metadata := DesktopBridgeMetadata{
		Schema: 1, NodeID: profileString(profile, "id"), SessionID: sessionID, SourceSHA256: sourceSHA, ConfigSHA256: desktopDigest(encoded),
		TargetOS: targetOS, FinalTag: ProfileOutboundTag, TUNTag: profileString(tun, "tag"), InterfaceName: profileString(tun, "interface_name"), SocksPort: socksPort,
		DNS: dns, BootstrapDNSTag: bootstrapDNS, IPv6Mode: ipv6, HomeLANAccess: lan, KillSwitchPolicy: kill, MTUPolicy: mtuPolicy, ConfiguredMTU: mtu, JumboTUN: profile["jumbo_tun"] == true,
	}
	bridges := make([]string, len(plan.Bridges))
	for i, bridge := range plan.Bridges {
		bridges[i] = bridge.Line
	}
	return &DesktopBridgePolicy{source: source, config: string(encoded), metadata: metadata, bridges: bridges}, nil
}

func desktopBridgeProfile(source string) (map[string]any, Plan, int, error) {
	profile, err := profileObject(source, 256<<10)
	if err != nil {
		return nil, Plan{}, 0, err
	}
	external, ok := profile["external"].(map[string]any)
	if !ok || external["protocol"] != "tor-bridge" {
		return nil, Plan{}, 0, errors.New("desktop bridge policy requires its exact external Tor bridge profile")
	}
	block, ok := external["tor_bridge"].(map[string]any)
	if !ok {
		return nil, Plan{}, 0, errors.New("desktop Tor bridge selection is missing")
	}
	port, err := profileInteger(block, "socks_port", 0)
	if err != nil {
		return nil, Plan{}, 0, errors.New("desktop Tor SOCKS port requires an integer")
	}
	if port == 0 {
		port = common.ExternalTorDefaultSocksPort
	}
	if port < 1024 || port > 65535 || port == 1098 || port == 1099 || port == 8788 {
		return nil, Plan{}, 0, errors.New("desktop Tor SOCKS port is invalid or reserved")
	}
	// The mobile parser owns an automatic listener. Remove only that field from
	// this private decoded copy and retain the exact original source for identity.
	delete(block, "socks_port")
	normalized, _ := json.Marshal(profile)
	profile, bridges, err := capturedTorProfile(string(normalized))
	if err != nil {
		return nil, Plan{}, 0, err
	}
	for _, key := range []string{"kill_switch", "multihop_enabled", "jumbo_tun", "daita_enabled", "home_lan_access"} {
		if raw, exists := profile[key]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, Plan{}, 0, errors.New("desktop Tor device policy requires typed saved booleans")
			}
		}
	}
	// RouterProfile omits false on disk; absence must preserve that saved LAN-Off
	// selection rather than inheriting the mobile compiler's missing-key default.
	if _, exists := profile["home_lan_access"]; !exists {
		profile["home_lan_access"] = false
	}
	plan, err := NewPlan(common.ExternalTorBridgeConfig{Transport: "custom", Bridges: bridges})
	if err != nil {
		return nil, Plan{}, 0, err
	}
	if _, err := desktopBridgeKillPolicy(profile, plan); err != nil {
		return nil, Plan{}, 0, err
	}
	return profile, plan, port, nil
}

func desktopBridgeKillPolicy(profile map[string]any, plan Plan) (string, error) {
	policy, exists := profile["kill_switch_policy"]
	value, ok := policy.(string)
	if exists && !ok {
		return "", errors.New("desktop Tor kill switch policy requires a string")
	}
	if value == "" {
		value = "off"
		if profile["kill_switch"] == true {
			value = "on-connect"
		}
	}
	if value != "off" && value != "on-connect" && value != "always" {
		return "", errors.New("invalid desktop Tor kill switch policy")
	}
	if value != "off" && (len(plan.Bridges) != 1 || plan.Bridges[0].Transport != "obfs4") {
		return "", errors.New("strict desktop Tor protection requires one fixed obfs4 bridge until controlled dynamic PT egress is implemented")
	}
	return value, nil
}

func desktopHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes && hex.EncodeToString(decoded) == value
}

func desktopDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
