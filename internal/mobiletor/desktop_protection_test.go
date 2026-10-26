package mobiletor

import (
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

const desktopProtectionSnowflakeBridge = "snowflake 192.0.2.3:80 1111111111111111111111111111111111111111 fingerprint=1111111111111111111111111111111111111111 url=https://broker.example/ front=front.example ice=stun:stun.example:3478"
const desktopProtectionWebTunnelBridge = "webtunnel 192.0.2.4:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://tunnel.example/owned ver=0.0.1"

func TestDesktopBridgeStrictDynamicProtectionRequiresCapturedRouter(t *testing.T) {
	plans := [][]string{{obfs4Bridge}, {meekBridge}, {desktopProtectionSnowflakeBridge}, {desktopProtectionWebTunnelBridge}, {obfs4Bridge, meekBridge, desktopProtectionSnowflakeBridge, desktopProtectionWebTunnelBridge}}
	for _, mode := range []string{"wg", "shadowsocks", "naive-h2"} {
		entry, _ := desktopEntryFixture(t, mode, "", nil)
		egress, err := mobilemultihop.NodePhysicalEgress(entry.Mode(), entry.Profile(), entry.Config())
		if err != nil {
			t.Fatal(err)
		}
		for _, bridges := range plans {
			for _, target := range []string{"linux", "darwin", "windows"} {
				for _, kill := range []string{"on-connect", "always"} {
					t.Run(mode+"/"+strings.Fields(bridges[len(bridges)-1])[0]+"/"+target+"/"+kill, func(t *testing.T) {
						profile := desktopEntryExit(entry)
						profile["kill_switch_policy"], profile["desktop_physical_egress"] = kill, egress
						block := profile["external"].(map[string]any)["tor_bridge"].(map[string]any)
						block["transport"], block["bridges"] = "custom", bridges
						source := torHostEncode(t, profile)
						if err := ValidateDesktopBridgeProfile(source); err != nil {
							t.Fatal("saved Local Router protection is not editable", err)
						}
						if policy, err := NewDesktopBridgePolicy(source, desktopSession, desktopIsolation, target); err == nil || policy != nil {
							t.Fatal("untrusted saved metadata admitted strict PT without a captured predecessor")
						}
						policy, err := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, target, entry)
						if err != nil {
							t.Fatal("captured Router PT policy failed", err)
						}
						meta := policy.Metadata()
						if meta.KillSwitchPolicy != kill || meta.EntryID != entry.ID() || meta.EntrySHA256 != entry.Proof().Fingerprint() ||
							meta.SourceSHA256 != policy.SourceSHA256() || policy.Profile() != source {
							t.Fatal("strict policy lost its exact source or Router proof owner")
						}
						parsed, err := profileObject(policy.Profile(), 256<<10)
						if err != nil || !reflect.DeepEqual(parsed["desktop_physical_egress"], mustProtectionObject(t, egress)) {
							t.Fatal("dynamic PT changed the captured physical whitelist", err)
						}
						actual, err := policy.Plan()
						if err != nil || len(actual.Bridges) != len(bridges) {
							t.Fatal("protected policy lost an exact PT selection", err)
						}
						for i, bridge := range actual.Bridges {
							if bridge.Line != bridges[i] {
								t.Fatal("protected policy substituted bridge arguments")
							}
						}
					})
				}
			}
		}
	}
}

func mustProtectionObject(t *testing.T, value any) any {
	t.Helper()
	object, err := profileObject(torHostEncode(t, map[string]any{"value": value}), 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	return object["value"]
}

func TestDesktopBridgeStrictDynamicProtectionRejectsUnownedSelection(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "shadowsocks", "", nil)
	for name, edit := range map[string]func(map[string]any){
		"direct":        func(p map[string]any) { p["multihop_enabled"] = false },
		"entry missing": func(p map[string]any) { delete(p, "multihop_entry_id") },
		"same node":     func(p map[string]any) { p["multihop_entry_id"] = p["id"] },
		"wrong exit":    func(p map[string]any) { p["multihop_exit_id"] = "other-tor" },
		"server":        func(p map[string]any) { p["multihop_execution"] = "server" },
		"compare":       func(p map[string]any) { p["multihop_execution"] = "auto" },
		"typed":         func(p map[string]any) { p["multihop_enabled"] = "true" },
	} {
		t.Run(name, func(t *testing.T) {
			p := desktopEntryExit(entry)
			block := p["external"].(map[string]any)["tor_bridge"].(map[string]any)
			block["transport"], block["bridges"] = "custom", []string{desktopProtectionSnowflakeBridge}
			edit(p)
			source := torHostEncode(t, p)
			if ValidateDesktopBridgeProfile(source) == nil {
				t.Fatal("unowned strict graph passed saved policy validation")
			}
			if policy, err := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, "linux", entry); err == nil || policy != nil {
				t.Fatal("unowned strict graph acquired a runtime policy")
			}
		})
	}
	profile := desktopEntryExit(entry)
	block := profile["external"].(map[string]any)["tor_bridge"].(map[string]any)
	block["transport"], block["bridges"] = "custom", []string{meekBridge}
	for _, kind := range []string{"missing-proof", "external-kind", "untyped-kind"} {
		t.Run(kind, func(t *testing.T) {
			forged := *entry
			switch kind {
			case "missing-proof":
				forged.proof = nil
			case "external-kind":
				forged.kind = ExternalPredecessorProofKind
			case "untyped-kind":
				forged.kind = ""
			}
			if policy, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, profile), desktopSession, desktopIsolation, "linux", &forged); err == nil || policy != nil {
				t.Fatal("untyped predecessor acquired Router-only strict protection")
			}
		})
	}
}
