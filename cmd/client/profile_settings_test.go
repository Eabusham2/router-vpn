package main

import (
	"testing"

	"router-vpn/internal/common"
)

func settingsTestProfileV2() common.RouterProfile {
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

func settingsStringPtrV2(v string) *string { return &v }
func settingsBoolPtrV2(v bool) *bool { return &v }
func settingsIntPtrV2(v int) *int { return &v }

func TestProfileSettingsV2MutateOnlyAllowedPolicyFields(t *testing.T) {
	before := settingsTestProfileV2()
	updated, err := applyProfileSettings(before, profileSettingsRequest{
		HomeLANAccess: settingsBoolPtrV2(false), KillSwitchPolicy: settingsStringPtrV2("always"), IPv6Mode: settingsStringPtrV2("off"),
		StartupMode: settingsStringPtrV2("smart-auto"), AutoConnect: settingsBoolPtrV2(true), BaseTunnel: settingsStringPtrV2("awg"), BaseFallback: settingsBoolPtrV2(true),
		MTUPolicy: settingsStringPtrV2("manual"), ManualMTU: settingsIntPtrV2(1320), DAITAEnabled: settingsBoolPtrV2(true), JumboTUN: settingsBoolPtrV2(true), SocksEnabled: settingsBoolPtrV2(true),
	})
	if err != nil { t.Fatal(err) }
	if updated.HomeLANAccess || updated.KillSwitchPolicy != "always" || !updated.KillSwitch || updated.IPv6Mode != "off" || updated.StartupMode != "smart-auto" || !updated.AutoConnect || updated.BaseTunnel != "awg" || !updated.BaseFallback || updated.MTUPolicy != "manual" || updated.ManualMTU != 1320 || !updated.DAITAEnabled || !updated.JumboTUN || !updated.SocksEnabled {
		t.Fatalf("allowed policy fields were not updated: %+v", updated)
	}
	if updated.Endpoint != before.Endpoint || updated.RouterAPI != before.RouterAPI || updated.APIToken != before.APIToken || updated.NodeProofID != before.NodeProofID || updated.DNSMode != before.DNSMode || updated.DNSHost != before.DNSHost || updated.FastestDNSHost != before.FastestDNSHost || updated.EffectiveMTU != before.EffectiveMTU || updated.EffectiveMTUSource != before.EffectiveMTUSource || updated.EffectiveMTUPathKey != before.EffectiveMTUPathKey {
		t.Fatalf("settings mutation changed protected/non-policy state: before=%+v after=%+v", before, updated)
	}
}

func TestProfileSettingsV2Validation(t *testing.T) {
	base := settingsTestProfileV2()
	bad := []profileSettingsRequest{
		{KillSwitchPolicy: settingsStringPtrV2("strict")},
		{IPv6Mode: settingsStringPtrV2("maybe")},
		{StartupMode: settingsStringPtrV2("boot-random")},
		{BaseTunnel: settingsStringPtrV2("openvpn")},
		{MTUPolicy: settingsStringPtrV2("manual"), ManualMTU: settingsIntPtrV2(500)},
		{MTUPolicy: settingsStringPtrV2("nonsense")},
	}
	for _, q := range bad {
		if _, err := applyProfileSettings(base, q); err == nil { t.Fatalf("expected rejection for %+v", q) }
	}
}

func TestProfileSettingsV2DefaultAndAutoMTUClearManualValue(t *testing.T) {
	base := settingsTestProfileV2(); base.MTUPolicy = "manual"; base.ManualMTU = 1320
	for _, policy := range []string{"default", "auto"} {
		updated, err := applyProfileSettings(base, profileSettingsRequest{MTUPolicy: settingsStringPtrV2(policy)})
		if err != nil { t.Fatal(err) }
		if updated.MTUPolicy != policy || updated.ManualMTU != 0 { t.Fatalf("%s did not clear manual MTU: %+v", policy, updated) }
	}
}
