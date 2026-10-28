package mobiletor

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/common"
)

// DesktopBridgePolicy describes one captured plain Tor or Tor bridge connection.
// It opens no listener, launches no process and grants no connection proof. Its
// SOCKS outbound is usable only after the native owner authenticates its exact
// Tor child and binds the selected guard proxy or in-process PT listeners.
type DesktopBridgePolicy struct {
	config, source string
	mode           string
	metadata       DesktopBridgeMetadata
	bridges        []string
	predecessor    *DesktopPredecessor
	server         *ServerTorPolicy
	isolation      string
}

// DesktopBridgeDNS preserves the desktop API for the shared selected resolver.
type DesktopBridgeDNS = SelectedDNS

// Metadata records requested policy, never a measured path MTU or successful
// DNS/Tor proof. Secrets remain exclusively in the private source/configuration.
type DesktopBridgeMetadata struct {
	Schema                int                  `json:"schema"`
	NodeID                string               `json:"node_id"`
	SessionID             string               `json:"session_id"`
	SourceSHA256          string               `json:"source_sha256"`
	ConfigSHA256          string               `json:"config_sha256"`
	TargetOS              string               `json:"target_os"`
	FinalTag              string               `json:"final_tag"`
	TUNTag                string               `json:"tun_tag"`
	InterfaceName         string               `json:"interface_name,omitempty"`
	SocksPort             int                  `json:"socks_port"`
	DNS                   DesktopBridgeDNS     `json:"dns"`
	BootstrapDNSTag       string               `json:"bootstrap_dns_tag"`
	IPv6Mode              string               `json:"ipv6_mode"`
	HomeLANAccess         bool                 `json:"home_lan_access"`
	KillSwitchPolicy      string               `json:"kill_switch_policy"`
	MTUPolicy             string               `json:"mtu_policy"`
	ConfiguredMTU         int                  `json:"configured_mtu"`
	JumboTUN              bool                 `json:"jumbo_tun"`
	Padding               TorPaddingPolicy     `json:"padding"`
	EntryID               string               `json:"entry_id,omitempty"`
	EntryMode             string               `json:"entry_mode,omitempty"`
	EntryTag              string               `json:"entry_tag,omitempty"`
	EntrySHA256           string               `json:"entry_sha256,omitempty"`
	EntryProofKind        PredecessorProofKind `json:"entry_proof_kind,omitempty"`
	EntryAssetsSHA256     string               `json:"entry_assets_sha256,omitempty"`
	EntryMTUPolicy        string               `json:"entry_mtu_policy,omitempty"`
	EntryFixedMTU         int                  `json:"entry_fixed_mtu,omitempty"`
	EntryJumboTUN         bool                 `json:"entry_jumbo_tun,omitempty"`
	DNSDetour             string               `json:"dns_detour,omitempty"`
	Execution             string               `json:"execution,omitempty"`
	ServerSourceSHA256    string               `json:"server_source_sha256,omitempty"`
	ServerDNSPolicySHA256 string               `json:"server_dns_policy_sha256,omitempty"`
}

// AllowMTUOptimization describes authority over the single interface, not a
// measurement result. Entry Fixed/Jumbo choices cannot be overwritten by an
// exit whose separately retained saved preference is Auto.
func (m DesktopBridgeMetadata) AllowMTUOptimization() bool {
	return m.MTUPolicy == "auto" && !m.JumboTUN && !m.EntryJumboTUN && m.EntryFixedMTU == 0
}

// DesktopBridgeProof is the native child receipt. A control bootstrap status
// alone cannot fill it: the native host must own the TUN readback and prove the
// exact selected DNS plus the public Tor path before setting Healthy.
type DesktopBridgeProof struct {
	Schema         int                        `json:"schema"`
	SessionID      string                     `json:"session_id"`
	SourceSHA256   string                     `json:"source_sha256"`
	ConfigSHA256   string                     `json:"config_sha256"`
	Policy         DesktopBridgeMetadata      `json:"policy"`
	Proof          Proof                      `json:"proof"`
	InterfaceName  string                     `json:"interface_name"`
	InterfaceIndex int                        `json:"interface_index"`
	EffectiveMTU   int                        `json:"effective_mtu"`
	Healthy        bool                       `json:"healthy"`
	HeartbeatAt    int64                      `json:"heartbeat_at"`
	MTUReadback    *DesktopBridgeMTUReadback  `json:"mtu_readback,omitempty"`
	EntryProof     *DesktopBridgeEntryProof   `json:"entry_proof,omitempty"`
	Padding        *PaddingReceipt            `json:"padding,omitempty"`
	PaddingProof   *DesktopBridgePaddingProof `json:"padding_proof,omitempty"`
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

func (p *DesktopBridgePolicy) Config() string                   { return p.config }
func (p *DesktopBridgePolicy) SourceSHA256() string             { return p.metadata.SourceSHA256 }
func (p *DesktopBridgePolicy) Metadata() DesktopBridgeMetadata  { return p.metadata }
func (p *DesktopBridgePolicy) Profile() string                  { return p.source }
func (p *DesktopBridgePolicy) Predecessor() *DesktopPredecessor { return p.predecessor }
func (p *DesktopBridgePolicy) ServerPolicy() *ServerTorPolicy   { return p.server }
func (p *DesktopBridgePolicy) Mode() string                     { return p.mode }
func (p *DesktopBridgePolicy) Plan() (Plan, error) {
	if p.mode != "tor-bridge" {
		return Plan{}, errors.New("plain desktop Tor has no bridge plan")
	}
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

// NewDesktopBridgePolicy compiles the exact saved direct Tor selection. The
// same resolver is separately captured for PT bootstrap on the native physical
// underlay and for application DNS through Tor. Neither uses host-default DNS.
func NewDesktopBridgePolicy(source, sessionID, isolationSecret, targetOS string) (*DesktopBridgePolicy, error) {
	return newDesktopBridgePolicy(source, sessionID, isolationSecret, targetOS, nil)
}

func newDesktopBridgePolicy(source, sessionID, isolationSecret, targetOS string, predecessor *DesktopPredecessor) (*DesktopBridgePolicy, error) {
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
	padding, _, err := capturedTorPaddingPolicy(profile)
	if err != nil {
		return nil, err
	}
	if profileString(profile, "multihop_execution") == "server" {
		return nil, errors.New("Tor Server requires its dedicated leased-server compiler")
	}
	if (profile["multihop_enabled"] == true) != (predecessor != nil) {
		return nil, errors.New("desktop Tor graph requires the exact captured Router-entry selection")
	}
	if predecessor != nil && predecessor.entryProof() == nil {
		return nil, errors.New("desktop Tor predecessor lost its typed proof authority")
	}
	// Saved entry identifiers are intent, not firewall authority. A protected
	// predecessor must retain its genuine typed proof and complete native
	// graph. Ordinary entries additionally require the exact physical socket
	// projection checked below; a public-address proof never grants private
	// Router, Home DNS or Server execution authority. The native PT owner
	// proves either typed entry before opening any transport listener.
	if kill, _ := desktopBridgeKillPolicy(profile, plan); kill != "off" && (predecessor != nil || !desktopBridgeDirectProtection(plan)) &&
		!predecessor.IsRouter() && !predecessor.IsExternal() {
		return nil, errors.New("strict desktop Tor protection has no captured typed predecessor")
	}
	if err := validateDesktopPhysicalEgress(profile, predecessor); err != nil {
		return nil, err
	}
	if profile["daita_enabled"] == true {
		return nil, errors.New("desktop Tor cannot discard a requested padding policy; its authenticated native implementation is still required")
	}
	var root, tun, selected map[string]any
	if predecessor == nil {
		selected, _, err = torSelectedDNS(profile, nil, false)
		if err != nil {
			return nil, err
		}
		root, tun, _, _ = torPredecessor("")
		selected["tag"], selected["detour"] = profileDNS, ProfileOutboundTag
		bootstrap := make(map[string]any, len(selected))
		for key, value := range selected {
			bootstrap[key] = value
		}
		bootstrap["tag"] = bootstrapDNS
		delete(bootstrap, "detour")
		root["dns"] = map[string]any{"servers": []any{selected, bootstrap}, "final": profileDNS, "independent_cache": true}
	} else {
		root, tun, selected, err = desktopPredecessorGraph(profile, sessionID, predecessor)
		if err != nil {
			return nil, err
		}
	}
	if targetOS == "linux" {
		// The strict desktop forwarding helper already owns this exact native
		// alias. Do not widen its egress exception for a new Tor-only name.
		tun["interface_name"] = "router-vpn"
	} else if targetOS == "windows" {
		tun["interface_name"] = "router-vpn-tor"
	} else {
		delete(tun, "interface_name")
	}
	socks := map[string]any{
		"type": "socks", "tag": ProfileOutboundTag, "server": "127.0.0.1", "server_port": socksPort,
		"version": "5", "username": sessionID, "password": isolationSecret,
	}
	if predecessor == nil {
		root["outbounds"] = []any{socks}
	} else {
		rows := root["outbounds"].([]any)
		replaced := 0
		for i, row := range rows {
			outbound := row.(map[string]any)
			if outbound["tag"] == ProfileOutboundTag {
				if outbound["type"] != "routervpn-tor" || outbound["detour"] != predecessor.tag || outbound["entry_sha256"] != predecessor.Fingerprint() {
					return nil, errors.New("desktop Tor Local compiler lost the exact predecessor")
				}
				rows[i] = socks
				replaced++
			}
		}
		if replaced != 1 {
			return nil, errors.New("desktop Tor Local graph requires exactly one isolated standalone owner")
		}
		root["outbounds"] = rows
	}
	route := root["route"].(map[string]any)
	route["final"] = ProfileOutboundTag
	if predecessor == nil {
		route["default_domain_resolver"] = map[string]any{"server": bootstrapDNS}
		if err := applyTorDevicePolicy(root, tun, profile); err != nil {
			return nil, err
		}
		if err := applyDesktopTorJumboPolicy(tun, profile); err != nil {
			return nil, err
		}
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
	if predecessor != nil {
		sourceBytes, _ = json.Marshal([]string{"routervpn-desktop-tor-predecessor-v1", source, sessionID, isolationSecret, targetOS,
			predecessor.mode, predecessor.profile, predecessor.config, predecessor.assets})
		if predecessor.IsExternal() {
			sourceBytes, _ = json.Marshal([]string{"routervpn-desktop-tor-external-predecessor-v2", source, sessionID, isolationSecret, targetOS,
				predecessor.mode, predecessor.profile, predecessor.external.source, predecessor.config, predecessor.assets, predecessor.Fingerprint()})
		}
	}
	sourceSHA := desktopDigest(sourceBytes)
	// This exact Box service retires the native physical/PT generation on
	// every network reset, including resets whose addresses are unchanged.
	services, _ := root["services"].([]any)
	root["services"] = append(services, map[string]any{
		"type": "routervpn-desktop-tor-network", "tag": "routervpn-tor-physical",
		"session_id": sessionID, "source_sha256": sourceSHA,
	})
	encoded, err := json.Marshal(root)
	if err != nil || len(encoded) > 4<<20 {
		return nil, errors.New("desktop Tor configuration exceeds its bound")
	}
	// Read the encoded graph's exact integers for both the direct compiler and
	// a parsed complete predecessor; neither historical MTU nor defaults can
	// stand in for the actual single configured interface.
	encodedGraph, err := profileObject(string(encoded), 4<<20)
	if err != nil {
		return nil, err
	}
	_, _, mtu, err := torMTUInterface(encodedGraph)
	if err != nil {
		return nil, err
	}
	dns, err := desktopBridgeDNSMetadata(profile, selected)
	if err != nil {
		return nil, err
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
		DNS: dns, BootstrapDNSTag: bootstrapDNS, IPv6Mode: ipv6, HomeLANAccess: lan, KillSwitchPolicy: kill, MTUPolicy: mtuPolicy, ConfiguredMTU: mtu, JumboTUN: profile["jumbo_tun"] == true, Padding: padding,
	}
	if predecessor != nil {
		metadata.EntryID, metadata.EntryMode, metadata.EntryTag = predecessor.ID(), predecessor.mode, predecessor.tag
		metadata.EntrySHA256, metadata.EntryAssetsSHA256 = predecessor.Fingerprint(), predecessor.assets
		mtu := predecessor.entryProof().capturedMTU()
		metadata.EntryMTUPolicy, metadata.EntryFixedMTU, metadata.EntryJumboTUN = mtu.policy, mtu.fixed, mtu.jumbo
		if predecessor.IsExternal() {
			metadata.EntryProofKind = ExternalPredecessorProofKind
		}
		metadata.DNSDetour = profileString(selected, "detour")
	}
	bridges := make([]string, len(plan.Bridges))
	for i, bridge := range plan.Bridges {
		bridges[i] = bridge.Line
	}
	return &DesktopBridgePolicy{source: source, config: string(encoded), mode: profile["external"].(map[string]any)["protocol"].(string), metadata: metadata, bridges: bridges, predecessor: predecessor, isolation: isolationSecret}, nil
}

func desktopBridgeProfile(source string) (map[string]any, Plan, int, error) {
	profile, err := profileObject(source, 256<<10)
	if err != nil {
		return nil, Plan{}, 0, err
	}
	external, ok := profile["external"].(map[string]any)
	if !ok || external["protocol"] != "tor-bridge" && external["protocol"] != "tor" {
		return nil, Plan{}, 0, errors.New("desktop Tor policy requires its exact external Tor profile")
	}
	port := common.ExternalTorDefaultSocksPort
	if external["protocol"] == "tor-bridge" {
		block, ok := external["tor_bridge"].(map[string]any)
		if !ok {
			return nil, Plan{}, 0, errors.New("desktop Tor bridge selection is missing")
		}
		port, err = profileInteger(block, "socks_port", 0)
		if err != nil {
			return nil, Plan{}, 0, errors.New("desktop Tor SOCKS port requires an integer")
		}
		if port == 0 {
			port = common.ExternalTorDefaultSocksPort
		}
		// The mobile parser owns an automatic listener. Remove only that field
		// from this copy and retain the original source for exact identity.
		delete(block, "socks_port")
	}
	if port < 1024 || port > 65535 || port == 1098 || port == 1099 || port == 8788 {
		return nil, Plan{}, 0, errors.New("desktop Tor SOCKS port is invalid or reserved")
	}
	normalized, _ := json.Marshal(profile)
	var bridges []string
	if profileString(profile, "multihop_execution") == "server" && desktopBridgeSavedRouterSelection(profile) {
		// Idle validation and DNS selection may retain Server cover intent.
		// Only the dedicated Server factory can build this execution; it binds
		// the full private predecessor and actual bounded cover receipts.
		profile, bridges, err = capturedTorProfileValues(string(normalized))
	} else {
		profile, bridges, err = capturedTorProfile(string(normalized))
	}
	if err != nil {
		return nil, Plan{}, 0, err
	}
	if profileString(profile, "multihop_execution") == "server" && !desktopBridgeSavedRouterSelection(profile) {
		return nil, Plan{}, 0, errors.New("saved Tor Server requires its explicit private entry and Tor exit selection")
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
	plan := Plan{}
	if external["protocol"] == "tor-bridge" {
		plan, err = NewPlan(common.ExternalTorBridgeConfig{Transport: "custom", Bridges: bridges})
		if err != nil {
			return nil, Plan{}, 0, err
		}
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
	if value != "off" && !desktopBridgeDirectProtection(plan) && !desktopBridgeSavedRouterSelection(profile) {
		return "", errors.New("strict desktop Tor protection requires one fixed obfs4 bridge or its exact captured eligible predecessor")
	}
	return value, nil
}

func desktopBridgeDirectProtection(plan Plan) bool {
	return len(plan.Bridges) == 1 && plan.Bridges[0].Transport == "obfs4"
}

// Idle editors can retain a Local or Server Router choice without a connection.
// This shape check is never a proof: the compiler requires the actual complete
// predecessor, and the native owner requires its authenticated entry receipt.
func desktopBridgeSavedRouterSelection(profile map[string]any) bool {
	entry, exit, id := profileString(profile, "multihop_entry_id"), profileString(profile, "multihop_exit_id"), profileString(profile, "id")
	execution := profileString(profile, "multihop_execution")
	external, ok := profile["external"].(map[string]any)
	if !ok || external["protocol"] != "tor" && external["protocol"] != "tor-bridge" {
		return false
	}
	return profile["multihop_enabled"] == true && profileIdentifier.MatchString(entry) &&
		entry != id && exit == id && (execution == "" || execution == "local" || execution == "server" &&
		profileIdentifier.MatchString(profileString(profile, "multihop_entry_mode")) && profile["multihop_exit_mode"] == external["protocol"])
}

func desktopHex(value string, bytes int) bool { return capturedHex(value, bytes) }

func desktopDigest(value []byte) string { return capturedDigest(value) }
