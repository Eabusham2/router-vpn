package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"router-vpn/internal/common"
)

// Keep legacy connection-profile stores from being silently canonized as v4
// before their saved non-secret policy is proven valid. Methods may live in a
// separate file; encoding/json invokes this whenever a preferences object is
// decoded as part of connectionProfileStore.
type connectionProfilePreferencesWire connectionProfilePreferences

var connectionProfilePreferenceKeys = map[string]struct{}{
	"home_lan_access": {}, "kill_switch_policy": {}, "ipv6_mode": {},
	"home_lan_cidrs": {}, "startup_mode": {}, "auto_connect": {},
	"auto_require_encrypted": {}, "auto_require_obfuscation": {},
	"base_tunnel": {}, "base_fallback": {}, "start_layer": {}, "mtu_policy": {}, "manual_mtu": {},
	"daita_enabled": {}, "daita_rate_kbps": {}, "jumbo_tun": {}, "socks_enabled": {},
	"dns_mode": {}, "dns_protocol": {}, "dns_host": {}, "dns_port": {},
	"dns_server_name": {}, "dns_path": {}, "home_dns_captured": {}, "multihop_enabled": {},
	"multihop_entry_id": {}, "multihop_exit_id": {}, "multihop_entry_mode": {}, "custom_layers": {},
}

func (p *connectionProfilePreferences) UnmarshalJSON(data []byte) error {
	if p == nil {
		return errors.New("connection profile preferences target is nil")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("invalid connection profile preferences: %w", err)
	}
	for key := range raw {
		if _, ok := connectionProfilePreferenceKeys[key]; !ok {
			return fmt.Errorf("connection profile preferences contain unsupported field %q", key)
		}
	}
	for _, key := range []string{"home_lan_cidrs", "startup_mode", "auto_connect", "home_dns_captured", "multihop_entry_mode", "daita_rate_kbps"} {
		if value, ok := raw[key]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("saved connection policy cannot be null")
		}
	}
	var decoded connectionProfilePreferencesWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("invalid connection profile preference value type: %w", err)
	}
	*p = connectionProfilePreferences(decoded)

	// Unified defaults for fields that did not exist in older snapshots. A
	// present false/empty value is never confused with an absent legacy field.
	if _, ok := raw["home_lan_access"]; !ok {
		p.HomeLANAccess = true
	}
	if _, ok := raw["kill_switch_policy"]; !ok {
		p.KillSwitchPolicy = "off"
	}
	if _, ok := raw["ipv6_mode"]; !ok {
		p.IPv6Mode = "on"
	}
	if _, ok := raw["base_tunnel"]; !ok {
		p.BaseTunnel = "auto"
	}
	if _, ok := raw["start_layer"]; !ok {
		p.StartLayer = common.StartLayerOff
	}
	if _, ok := raw["mtu_policy"]; !ok {
		p.MTUPolicy = "auto"
	}

	layers, err := normalizeConnectionProfileLayers(p.CustomLayers)
	if err != nil {
		return err
	}
	p.CustomLayers = layers

	// Reuse the live Settings normalizer for every persistent non-DNS policy
	// field instead of maintaining a second set of enums/ranges here.
	seed := common.RouterProfile{
		ID: "connection-profile-validation", NodeKind: "router-vpn", StartupMode: "smart-auto",
		HomeLANAccess: p.HomeLANAccess, KillSwitchPolicy: p.KillSwitchPolicy, IPv6Mode: p.IPv6Mode,
		AutoRequireEncrypted: p.AutoRequireEncrypted, AutoRequireObfuscation: p.AutoRequireObfuscation,
		BaseTunnel: p.BaseTunnel, BaseFallback: p.BaseFallback, StartLayer: p.StartLayer,
		MTUPolicy: p.MTUPolicy, ManualMTU: p.ManualMTU,
		DAITAEnabled: p.DAITAEnabled, JumboTUN: p.JumboTUN, SocksEnabled: p.SocksEnabled,
	}
	if p.DAITARateKbps != nil {
		seed.DAITARateKbps = *p.DAITARateKbps
	}
	settings := profileSettingsRequest{
		HomeLANAccess: &p.HomeLANAccess, KillSwitchPolicy: &p.KillSwitchPolicy, IPv6Mode: &p.IPv6Mode,
		StartupMode: p.StartupMode, AutoConnect: p.AutoConnect,
		AutoRequireEncrypted: &p.AutoRequireEncrypted, AutoRequireObfuscation: &p.AutoRequireObfuscation,
		BaseTunnel: &p.BaseTunnel, BaseFallback: &p.BaseFallback, StartLayer: &p.StartLayer,
		MTUPolicy: &p.MTUPolicy, ManualMTU: &p.ManualMTU,
		DAITAEnabled: &p.DAITAEnabled, JumboTUN: &p.JumboTUN, SocksEnabled: &p.SocksEnabled,
	}
	normalized, err := applyProfileSettings(seed, settings)
	if err != nil {
		return fmt.Errorf("invalid saved Router VPN settings: %w", err)
	}
	p.KillSwitchPolicy = normalized.KillSwitchPolicy
	p.IPv6Mode = normalized.IPv6Mode
	p.BaseTunnel = normalized.BaseTunnel
	p.StartLayer = normalized.StartLayer
	p.MTUPolicy = normalized.MTUPolicy
	p.ManualMTU = normalized.ManualMTU
	if p.StartupMode != nil {
		*p.StartupMode = normalized.StartupMode
	}
	if p.HomeLANCIDRs != nil {
		if len(*p.HomeLANCIDRs) > 64 {
			return errors.New("saved LAN policy is oversized")
		}
		for _, cidr := range *p.HomeLANCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return errors.New("saved LAN policy contains an invalid network")
			}
		}
	}

	if err := normalizeSavedConnectionDNS(p); err != nil {
		return err
	}
	if _, err := normalizeConnectionProfileEntryMode(p.MultihopEntryMode); err != nil {
		return err
	}
	if p.MultihopEnabled {
		entryID := strings.TrimSpace(p.MultihopEntryID)
		exitID := strings.TrimSpace(p.MultihopExitID)
		if !validProfileID(entryID) || !validProfileID(exitID) || entryID == exitID {
			return errors.New("saved multihop profile has invalid entry/exit node ids")
		}
		p.MultihopEntryID, p.MultihopExitID = entryID, exitID
	} else {
		// Disabled multihop owns no hop identity. Clear stale IDs from old or
		// hand-edited snapshots so a later load/toggle cannot revive a graph that
		// was not explicitly saved as enabled.
		p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = "", "", ""
	}
	return nil
}

func normalizeSavedConnectionDNS(p *connectionProfilePreferences) error {
	mode := strings.ToLower(strings.TrimSpace(p.DNSMode))
	if p.HomeDNSCaptured {
		if mode != "home" {
			return errors.New("a captured Home DNS policy must retain Home mode")
		}
		request, err := normalizeHomeDNSTransport(dnsPolicyRequest{Mode: "home", Protocol: p.DNSProtocol, Host: p.DNSHost, Port: p.DNSPort, ServerName: p.DNSServerName, Path: p.DNSPath})
		if err != nil {
			return fmt.Errorf("invalid captured Home DNS policy: %w", err)
		}
		p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "home", request.Protocol, request.Host, request.Port
		p.DNSServerName, p.DNSPath = request.ServerName, request.Path
		return nil
	}
	if mode == "" {
		// Legacy profile with no DNS snapshot: leave the linked node's current DNS
		// untouched when this connection profile is loaded.
		return nil
	}
	probe := common.RouterProfile{AdGuardIPv4: "10.77.0.1", FastestDNSHost: "1.1.1.1"}
	request := dnsPolicyRequest{
		Mode: mode, Protocol: p.DNSProtocol, Host: p.DNSHost, Port: p.DNSPort,
		ServerName: p.DNSServerName, Path: p.DNSPath,
	}
	if mode == "home" || mode == "fastest" {
		// Legacy Router connection preferences reference a node-derived preset,
		// not the concrete resolver left in an older snapshot. Validate that
		// preset after discarding those stale transport/address fields. Explicit
		// custom and encrypted policies still pass every selected-field check.
		request = dnsPolicyRequest{Mode: mode}
	}
	validated, err := applyDNSPolicyToProfile(probe, request)
	if err != nil {
		return fmt.Errorf("invalid saved DNS policy: %w", err)
	}
	p.DNSMode = mode
	switch mode {
	case "home", "fastest":
		// These modes derive the concrete resolver from the linked node at runtime;
		// never carry a concrete host/SNI/path from an older saved snapshot into
		// the newly linked node.
		p.DNSProtocol, p.DNSHost, p.DNSPort, p.DNSServerName, p.DNSPath = "udp", "", 53, "", ""
	default:
		p.DNSProtocol, p.DNSHost, p.DNSPort = validated.DNSProtocol, validated.DNSHost, validated.DNSPort
		p.DNSServerName, p.DNSPath = validated.DNSServerName, validated.DNSPath
	}
	return nil
}
