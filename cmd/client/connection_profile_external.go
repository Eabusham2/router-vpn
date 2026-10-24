package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This is a non-secret policy snapshot. Credentials, certificates, bridge
// strings and historical path measurements remain in their linked node stores.
// A separate field preserves schema-v4 external records that were selection-only.
type connectionProfileExternalCapture struct {
	Protocol         string   `json:"protocol"`
	StartLayer       string   `json:"start_layer,omitempty"`
	ExpectedPublicIP string   `json:"expected_public_ip"`
	HomeLANAccess    bool     `json:"home_lan_access"`
	HomeLANCIDRs     []string `json:"home_lan_cidrs"`
	KillSwitchPolicy string   `json:"kill_switch_policy"`
	IPv6Mode         string   `json:"ipv6_mode"`
	StartupMode      string   `json:"startup_mode"`
	AutoConnect      bool     `json:"auto_connect"`
	MTUPolicy        string   `json:"mtu_policy"`
	ManualMTU        int      `json:"manual_mtu"`
	DAITAEnabled     bool     `json:"daita_enabled"`
	JumboTUN         bool     `json:"jumbo_tun"`
	SocksEnabled     bool     `json:"socks_enabled"`
	DNSMode          string   `json:"dns_mode"`
	DNSProtocol      string   `json:"dns_protocol"`
	DNSHost          string   `json:"dns_host"`
	DNSPort          int      `json:"dns_port"`
	DNSServerName    string   `json:"dns_server_name"`
	DNSPath          string   `json:"dns_path"`
	FastestDNSHost   string   `json:"fastest_dns_host"`
	MultihopEnabled  bool     `json:"multihop_enabled"`
	MultihopEntryID  string   `json:"multihop_entry_id"`
	MultihopExitID   string   `json:"multihop_exit_id"`
	MultihopExecution string `json:"multihop_execution,omitempty"`
	MultihopEntryMode string `json:"multihop_entry_mode,omitempty"`
}

type connectionProfileExternalWire connectionProfileExternalCapture

func (p *connectionProfileExternalCapture) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	// New captures are complete, unlike legacy records with no external_policy.
	encoded, _ := json.Marshal(connectionProfileExternalWire{})
	var required map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &required)
	for key := range required {
		value, ok := fields[key]
		if !ok || (bytes.Equal(bytes.TrimSpace(value), []byte("null")) && key != "home_lan_cidrs") {
			return errors.New("saved external policy is incomplete")
		}
	}
	var decoded connectionProfileExternalWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("saved external policy contains invalid or unsupported fields")
	}
	value := connectionProfileExternalCapture(decoded)
	if err := value.validate(); err != nil {
		return err
	}
	*p = value
	return nil
}

func (p connectionProfileExternalCapture) validate() error {
	if _, err := routeExecution(multihopConnectRequest{Execution: p.MultihopExecution}); err != nil { return err }
	if !p.MultihopEnabled && p.MultihopExecution != "" && p.MultihopExecution != "local" { return errors.New("direct external profile cannot request server execution") }
	if p.MultihopEntryMode != "" && (!p.MultihopEnabled || !mobilemultihop.NodeProfileMode(p.MultihopEntryMode)) { return errors.New("saved external entry requires an exact supported Router VPN mode") }
	if mode, err := common.NormalizeStartLayerMode(p.StartLayer); err != nil || p.StartLayer != "" && mode != p.StartLayer {
		return errors.New("saved external Start Layer selection is invalid")
	}
	switch p.Protocol {
	case "wireguard", "amneziawg", "openvpn", "shadowsocks", "socks5", "http-connect", "https-connect", "hysteria2", "tor-bridge":
	default:
		return errors.New("saved external protocol is unsupported")
	}
	if p.Protocol != "tor-bridge" && net.ParseIP(p.ExpectedPublicIP) == nil {
		return errors.New("saved external public identity is invalid")
	}
	if p.ExpectedPublicIP != "" && net.ParseIP(p.ExpectedPublicIP) == nil {
		return errors.New("saved external public identity is invalid")
	}
	if len(p.HomeLANCIDRs) > 64 {
		return errors.New("saved LAN policy is oversized")
	}
	for _, cidr := range p.HomeLANCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return errors.New("saved LAN policy contains an invalid network")
		}
	}
	seed := common.RouterProfile{NodeKind: "router-vpn", KillSwitchPolicy: p.KillSwitchPolicy, IPv6Mode: p.IPv6Mode, StartupMode: p.StartupMode, AutoConnect: p.AutoConnect, MTUPolicy: p.MTUPolicy, ManualMTU: p.ManualMTU}
	if err := common.NormalizeRouterProfile(&seed); err != nil {
		return errors.New("saved external device policy is invalid")
	}
	if seed.AutoConnect && seed.StartupMode == "manual" {
		return errors.New("saved manual startup cannot autoconnect")
	}
	for _, value := range []string{p.DNSHost, p.DNSProtocol, p.DNSMode, p.DNSServerName, p.DNSPath, p.FastestDNSHost} {
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("saved DNS policy contains invalid text")
		}
	}
	if p.DNSMode == "" {
		return errors.New("saved external DNS policy is missing")
	}
	if p.DNSPort < 0 || p.DNSPort > 65535 {
		return errors.New("saved DNS port is invalid")
	}
	dns := p.policy()
	// Unmeasured Fastest and node-derived Home remain choices, not fabricated
	// current measurements. The running graph still requires the actual resolver.
	if p.DNSMode == "fastest" && dns.FastestDNSHost == "" {
		dns.FastestDNSHost = "192.0.2.1"
	}
	if p.DNSMode == "home" && dns.DNSHost == "" {
		dns.AdGuardIPv4 = "192.0.2.1"
	}
	if _, err := selectedStandardExitDNS(dns, false); err != nil {
		return err
	}
	if p.MultihopEnabled {
		if !validProfileID(p.MultihopEntryID) || !validProfileID(p.MultihopExitID) || p.MultihopEntryID == p.MultihopExitID {
			return errors.New("saved external graph has invalid node references")
		}
	} else if p.MultihopEntryID != "" || p.MultihopExitID != "" {
		return errors.New("disabled external graph retains hop references")
	}
	return nil
}

func (p connectionProfileExternalCapture) policy() common.RouterProfile {
	return common.RouterProfile{HomeLANAccess: p.HomeLANAccess, HomeLANCIDRs: cloneStrings(p.HomeLANCIDRs), KillSwitchPolicy: p.KillSwitchPolicy, IPv6Mode: p.IPv6Mode, StartupMode: p.StartupMode, AutoConnect: p.AutoConnect, MTUPolicy: p.MTUPolicy, ManualMTU: p.ManualMTU, DAITAEnabled: p.DAITAEnabled, JumboTUN: p.JumboTUN, SocksEnabled: p.SocksEnabled, DNSMode: p.DNSMode, DNSProtocol: p.DNSProtocol, DNSHost: p.DNSHost, DNSPort: p.DNSPort, DNSServerName: p.DNSServerName, DNSPath: p.DNSPath, FastestDNSHost: p.FastestDNSHost, MultihopEnabled: p.MultihopEnabled, MultihopEntryID: p.MultihopEntryID, MultihopExitID: p.MultihopExitID, MultihopExecution: p.MultihopExecution, MultihopEntryMode: p.MultihopEntryMode}
}

func snapshotExternalConnectionPolicy(node common.RouterProfile) (*connectionProfileExternalCapture, error) {
	p, err := externalRuntimePolicy(cloneRouterProfile(node))
	if err != nil {
		return nil, err
	}
	if !p.MultihopEnabled {
		p.MultihopEntryID, p.MultihopExitID = "", ""
		p.MultihopEntryMode = ""
	}
	c := &connectionProfileExternalCapture{Protocol: p.External.Protocol, ExpectedPublicIP: p.External.ExpectedPublicIP, HomeLANAccess: p.HomeLANAccess, HomeLANCIDRs: cloneStrings(p.HomeLANCIDRs), KillSwitchPolicy: p.KillSwitchPolicy, IPv6Mode: p.IPv6Mode, StartupMode: p.StartupMode, AutoConnect: p.AutoConnect, MTUPolicy: p.MTUPolicy, ManualMTU: p.ManualMTU, DAITAEnabled: p.DAITAEnabled, JumboTUN: p.JumboTUN, SocksEnabled: p.SocksEnabled, DNSMode: p.DNSMode, DNSProtocol: p.DNSProtocol, DNSHost: p.DNSHost, DNSPort: p.DNSPort, DNSServerName: p.DNSServerName, DNSPath: p.DNSPath, FastestDNSHost: p.FastestDNSHost, MultihopEnabled: p.MultihopEnabled, MultihopEntryID: p.MultihopEntryID, MultihopExitID: p.MultihopExitID, MultihopExecution: p.MultihopExecution, MultihopEntryMode: p.MultihopEntryMode}
	c.StartLayer = p.StartLayer
	c.MultihopExecution = p.MultihopExecution
	c.MultihopEntryMode = p.MultihopEntryMode
	if c.MultihopExecution == "" { c.MultihopExecution = "local" }
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (p connectionProfileExternalCapture) apply(node common.RouterProfile) (common.RouterProfile, error) {
	if err := p.validate(); err != nil {
		return node, err
	}
	updated := cloneRouterProfile(node)
	if updated.NodeKind != "external" || updated.External == nil || updated.External.Protocol != p.Protocol || updated.External.ExpectedPublicIP != p.ExpectedPublicIP {
		return node, errors.New("linked external protocol or public identity changed; update the saved connection profile")
	}
	c := p.policy()
	updated.MultihopExecution = p.MultihopExecution
	updated.MultihopEntryMode = p.MultihopEntryMode
	if updated.MultihopExecution == "" { updated.MultihopExecution = "local" }
	if p.StartLayer != "" {
		updated.StartLayer = p.StartLayer
	}
	updated.HomeLANAccess, updated.HomeLANCIDRs = c.HomeLANAccess, c.HomeLANCIDRs
	updated.KillSwitchPolicy, updated.IPv6Mode = c.KillSwitchPolicy, c.IPv6Mode
	updated.StartupMode, updated.AutoConnect = c.StartupMode, c.AutoConnect
	updated.MTUPolicy, updated.ManualMTU = c.MTUPolicy, c.ManualMTU
	updated.DAITAEnabled, updated.JumboTUN, updated.SocksEnabled = c.DAITAEnabled, c.JumboTUN, c.SocksEnabled
	updated.DNSMode, updated.DNSProtocol, updated.DNSHost, updated.DNSPort = c.DNSMode, c.DNSProtocol, c.DNSHost, c.DNSPort
	updated.DNSServerName, updated.DNSPath, updated.FastestDNSHost = c.DNSServerName, c.DNSPath, c.FastestDNSHost
	updated.MultihopEnabled, updated.MultihopEntryID, updated.MultihopExitID = c.MultihopEnabled, c.MultihopEntryID, c.MultihopExitID
	if err := common.NormalizeRouterProfile(&updated); err != nil {
		return node, err
	}
	return updated, nil
}

type connectionProfileHopCapture struct {
	NodeID      string                            `json:"node_id"`
	NodeProofID string                            `json:"node_proof_id,omitempty"`
	Preferences *connectionProfilePreferences     `json:"preferences,omitempty"`
	External    *connectionProfileExternalCapture `json:"external_policy,omitempty"`
}

type connectionProfileHopWire connectionProfileHopCapture

func (h *connectionProfileHopCapture) UnmarshalJSON(data []byte) error {
	var value connectionProfileHopWire
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return errors.New("invalid saved hop policy")
	}
	if !validProfileID(value.NodeID) || (value.Preferences == nil) == (value.External == nil) {
		return errors.New("saved hop has no unambiguous node policy")
	}
	if value.NodeProofID != "" && !common.ValidNodeProofID(value.NodeProofID) {
		return errors.New("saved hop proof identity is invalid")
	}
	*h = connectionProfileHopCapture(value)
	return nil
}

func validateConnectionPathCapture(record connectionProfileRecord) error {
	if record.NodeProofID != "" && !common.ValidNodeProofID(record.NodeProofID) {
		return errors.New("saved Router proof identity is invalid")
	}
	if record.External != nil {
		if record.Mode != "external" || record.Prefs != nil {
			return errors.New("external policy cannot be applied to a Router connection profile")
		}
		if err := record.External.validate(); err != nil {
			return err
		}
		if record.External.MultihopEnabled && record.External.MultihopExitID != record.NodeID {
			return errors.New("saved external graph no longer ends at its captured node")
		}
	}
	if len(record.Hops) > 2 {
		return errors.New("saved connection profile has too many hop policies")
	}
	seen := map[string]bool{}
	for _, hop := range record.Hops {
		if !validProfileID(hop.NodeID) || hop.NodeID == record.NodeID || seen[hop.NodeID] || (hop.Preferences == nil) == (hop.External == nil) {
			return errors.New("saved hop policies are invalid or conflicting")
		}
		seen[hop.NodeID] = true
	}
	return nil
}

func (a *app) snapshotConnectionPathLocked(node common.RouterProfile) (*connectionProfileExternalCapture, []connectionProfileHopCapture, error) {
	var external *connectionProfileExternalCapture
	var err error
	if node.NodeKind == "external" || node.External != nil {
		external, err = snapshotExternalConnectionPolicy(node)
		if err != nil {
			return nil, nil, err
		}
	}
	if !node.MultihopEnabled {
		return external, nil, nil
	}
	var hops []connectionProfileHopCapture
	for _, id := range []string{node.MultihopEntryID, node.MultihopExitID} {
		if id == node.ID {
			continue
		}
		hop, ok := a.profileByIDLocked(id)
		if !ok {
			return nil, nil, errors.New("saved connection graph references a missing node")
		}
		capture := connectionProfileHopCapture{NodeID: id, NodeProofID: hop.NodeProofID}
		if hop.NodeKind == "external" || hop.External != nil {
			capture.External, err = snapshotExternalConnectionPolicy(hop)
		} else {
			capture.Preferences, err = snapshotConnectionPreferences(hop, hop.CustomLayers)
		}
		if err != nil {
			return nil, nil, err
		}
		hops = append(hops, capture)
	}
	return external, hops, nil
}

func applySavedRouterConnectionPolicy(node common.RouterProfile, p *connectionProfilePreferences) (common.RouterProfile, error) {
	updated, err := applyProfileSettings(cloneRouterProfile(node), profileSettingsRequest{HomeLANAccess: &p.HomeLANAccess, KillSwitchPolicy: &p.KillSwitchPolicy, IPv6Mode: &p.IPv6Mode, StartupMode: p.StartupMode, AutoConnect: p.AutoConnect, AutoRequireEncrypted: &p.AutoRequireEncrypted, AutoRequireObfuscation: &p.AutoRequireObfuscation, BaseTunnel: &p.BaseTunnel, BaseFallback: &p.BaseFallback, StartLayer: &p.StartLayer, MTUPolicy: &p.MTUPolicy, ManualMTU: &p.ManualMTU, DAITAEnabled: &p.DAITAEnabled, JumboTUN: &p.JumboTUN, SocksEnabled: &p.SocksEnabled})
	if err != nil {
		return node, err
	}
	if p.DNSMode != "" {
		updated.DNSMode, updated.DNSProtocol, updated.DNSHost, updated.DNSPort, updated.DNSServerName, updated.DNSPath = p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort, p.DNSServerName, p.DNSPath
	}
	if p.HomeLANCIDRs != nil {
		updated.HomeLANCIDRs = cloneStrings(*p.HomeLANCIDRs)
	}
	updated.CustomLayers = cloneStrings(p.CustomLayers)
	updated.MultihopEnabled, updated.MultihopEntryID, updated.MultihopExitID = p.MultihopEnabled, p.MultihopEntryID, p.MultihopExitID
	if err := common.NormalizeRouterProfile(&updated); err != nil {
		return node, err
	}
	return updated, nil
}

func (a *app) restoreConnectionHopPoliciesLocked(saved connectionProfileRecord, selected common.RouterProfile) (map[string]common.RouterProfile, error) {
	updates := map[string]common.RouterProfile{}
	for _, capture := range saved.Hops {
		if !selected.MultihopEnabled || (capture.NodeID != selected.MultihopEntryID && capture.NodeID != selected.MultihopExitID) {
			return nil, errors.New("saved hop policy is not owned by the selected graph")
		}
		hop, ok := a.profileByIDLocked(capture.NodeID)
		if !ok {
			return nil, errors.New("saved hop is no longer linked")
		}
		var updated common.RouterProfile
		var err error
		if capture.External != nil {
			updated, err = capture.External.apply(hop)
		} else {
			if hop.NodeKind == "external" || hop.External != nil || capture.NodeProofID != hop.NodeProofID {
				return nil, errors.New("linked Router hop identity changed")
			}
			updated, err = applySavedRouterConnectionPolicy(hop, capture.Preferences)
		}
		if err != nil {
			return nil, err
		}
		updates[hop.ID] = updated
	}
	if selected.MultihopEnabled {
		for _, id := range []string{selected.MultihopEntryID, selected.MultihopExitID} {
			if _, ok := a.profileByIDLocked(id); !ok {
				return nil, errors.New("saved graph references an unlinked node")
			}
		}
		if saved.External != nil {
			if selected.MultihopExitID != selected.ID {
				return nil, errors.New("saved external graph has a different final node")
			}
			if _, ok := updates[selected.MultihopEntryID]; !ok {
				return nil, errors.New("saved external path lost its captured entry policy")
			}
		}
	}
	return updates, nil
}
