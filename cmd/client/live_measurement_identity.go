package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"router-vpn/internal/common"
)

// Freeze credentials, node identity and all dataplane-affecting policy, not
// just node IDs and DNS text. Measurements/display metadata stay out so two
// independent live probes do not invalidate one another when either persists.
// Hash the canonical JSON rather than returning tokens/passwords to callers.
func liveMeasurementProfileToken(p common.RouterProfile) string {
	identity := common.RouterProfile{
		ID: p.ID, NodeKind: p.NodeKind, External: p.External, NodeProofID: p.NodeProofID,
		Endpoint: p.Endpoint, RouterAPI: p.RouterAPI, APIToken: p.APIToken, PathProbeURL: p.PathProbeURL,
		AdGuardIPv4: p.AdGuardIPv4, AdGuardIPv6: p.AdGuardIPv6,
		DNSMode: p.DNSMode, DNSProtocol: p.DNSProtocol, DNSHost: p.DNSHost,
		DNSPort: p.DNSPort, DNSServerName: p.DNSServerName, DNSPath: p.DNSPath,
		BaseTunnel: p.BaseTunnel, BaseFallback: p.BaseFallback, CustomLayers: p.CustomLayers, StartLayer: p.StartLayer,
		HomeLANAccess: p.HomeLANAccess, HomeLANCIDRs: p.HomeLANCIDRs,
		KillSwitch: p.KillSwitch, KillSwitchPolicy: p.KillSwitchPolicy, IPv6Mode: p.IPv6Mode,
		StartupMode: p.StartupMode, AutoRequireEncrypted: p.AutoRequireEncrypted, AutoRequireObfuscation: p.AutoRequireObfuscation,
		MTUPolicy: p.MTUPolicy, ManualMTU: p.ManualMTU, EffectiveMTU: p.EffectiveMTU, JumboTUN: p.JumboTUN,
		DAITAEnabled: p.DAITAEnabled, DAITAHost: p.DAITAHost, DAITAPort: p.DAITAPort, DAITARateKbps: p.DAITARateKbps,
		SocksEnabled: p.SocksEnabled, SocksHost: p.SocksHost, SocksPort: p.SocksPort,
		SocksUsername: p.SocksUsername, SocksPassword: p.SocksPassword,
		MultihopEnabled: p.MultihopEnabled, MultihopEntryID: p.MultihopEntryID, MultihopExitID: p.MultihopExitID,
	}
	// The selected fields and external configuration consist only of JSON-safe
	// strings, integers, booleans and slices. Measured floating-point data is
	// deliberately excluded from this projection.
	// Do not invoke RouterProfile.MarshalJSON: it normalizes policy and can
	// erase distinctions (or mutate referenced external settings) while merely
	// checking freshness. A wire alias freezes the exact in-memory values.
	type profileIdentityWire common.RouterProfile
	encoded, _ := json.Marshal(profileIdentityWire(identity))
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
