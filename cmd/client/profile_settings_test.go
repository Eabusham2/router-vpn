package main

import (
	"testing"

	"router-vpn/internal/common"
)

func settingsTestProfile() common.RouterProfile {
	return common.RouterProfile{
		ID: "home", Name: "Home", NodeKind: "router-vpn", Endpoint: "vpn.example.test",
		RouterAPI: "http://10.77.0.1:8787", APIToken: "secret-token",
		NodeProofID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AdGuardIPv4: "10.77.0.1", DNSMode: "home", DNSProtocol: "udp", DNSHost: "10.77.0.1", DNSPort: 53,
		HomeLANAccess: true, KillSwitchPolicy: "off", IPv6Mode: "auto", StartupMode: "manual",
		BaseTunnel: "auto", MTUPolicy: "default", EffectiveMTU: 1370, EffectiveMTUSource: "auto",
		EffectiveMTUPathKey: "path-key", FastestDNSHost: "9.9.9.9", FastestDNSLatencyMs: 8.2,
	}
}

func strptr(v string) *string { return &v }
func boolptr(v bool) *bool { return &v }
func intptr(v int) *int { return &v }

func TestProfileSettingsMutateOnlyAllowedPolicyFields(t *testing.T) {
	before := settingsTestProfile()
	updated, err := applyProfileSettings(before, profileSettingsRequest{
		HomeLANAccess: boolptr(false), KillSwitchPolicy: strptr("always"), IPv6Mode: strptr("off"),
		StartupMode: strptr("smart-auto"), AutoConnect: boolptr(true), BaseTunnel: strptr("awg"), BaseFallback: boolptr(true),
		MTUPolicy: strptr("manual"), ManualMTU: intptr(1320), DAITAEnabled: boolptr(true), JumboTUN: boolptr(true), SocksEnabled: boolptr(true),
	})
	if err != nil { t.Fatal(err) }
	if updated.HomeLANAccess || updated.KillSwitchPolicy != "always" || !updated.KillSwitch || updated.IPv6Mode != "off" || updated.StartupMode != "smart-auto" || !updated.AutoConnect || updated.BaseTunnel != "awg" || !updated.BaseFallback || updated.MTUPolicy != "manual" || updated.ManualMTU != 1320 || !updated.DAITAEnabled || !updated.JumboTUN || !updated.SocksEnabled {
		t.Fatalf("allowed policy fields were not updated: %+v", updated)
	}
	if updated.Endpoint != before.Endpoint || updated.RouterAPI != before.RouterAPI || updated.APIToken != before.APIToken || updated.NodeProofID != before.NodeProofID || updated.DNSMode != before.DNSMode || updated.DNSHost != before.DNSHost || updated.FastestDNSHost != before.FastestDNSHost || updated.EffectiveMTU != before.EffectiveMTU || updated.EffectiveMTUSource != before.EffectiveMTUSource || updated.EffectiveMTUPathKey != before.EffectiveMTUPathKey {
		t.Fatalf("settings mutation changed protected/non-policy state: before=%+v after=%+v", before, updated)
	}
}

func TestProfileSettingsValidation(t *testing.T) {
	base := settingsTestProfile()
	bad := []profileSettingsRequest{
		{KillSwitchPolicy: strptr("strict")},
		{IPv6Mode: strptr("maybe")},
		{StartupMode: strptr("boot-random")},
		{BaseTunnel: strptr("openvpn")},
		{MTUPolicy: strptr("manual"), ManualMTU: intptr(500)},
		{MTUPolicy: strptr("nonsense")},
	}
	for _, q := range bad {
		if _, err := applyProfileSettings(base, q); err == nil { t.Fatalf("expected rejection for %+v", q) }
	}
}

func TestProfileSettingsDefaultAndAutoMTUClearManualValue(t *testing.T) {
	base := settingsTestProfile(); base.MTUPolicy = "manual"; base.ManualMTU = 1320
	for _, policy := range []string{"default", "auto"} {
		updated, err := applyProfileSettings(base, profileSettingsRequest{MTUPolicy: strptr(policy)})
		if err != nil { t.Fatal(err) }
		if updated.MTUPolicy != policy || updated.ManualMTU != 0 { t.Fatalf("%s did not clear manual MTU: %+v", policy, updated) }
	}
}
