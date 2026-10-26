package mobiletor

import (
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func TestDesktopPhysicalEgressReconstructsCapturedGraph(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "naive-h2", "naive-h3"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				entry, _ := desktopEntryFixture(t, mode, layer, nil)
				egress, err := mobilemultihop.NodePhysicalEgress(entry.Mode(), entry.Profile(), entry.Config())
				if err != nil {
					t.Fatal(err)
				}
				profile := desktopEntryExit(entry)
				profile["desktop_physical_egress"] = egress
				source := torHostEncode(t, profile)
				for _, target := range []string{"linux", "darwin", "windows"} {
					policy, err := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, target, entry)
					if err != nil || policy.Profile() != source || policy.Predecessor() != entry {
						t.Fatal("captured physical projection was not retained", target, err)
					}
				}
				if source != torHostEncode(t, profile) {
					t.Fatal("physical verification mutated the retained source")
				}
			})
		}
	}
}

func TestDesktopPhysicalEgressRejectsWidenedOrUnownedProjection(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "wg", "", nil)
	expected, err := mobilemultihop.NodePhysicalEgress(entry.Mode(), entry.Profile(), entry.Config())
	if err != nil || len(expected) == 0 {
		t.Fatal("entry has no actual physical transport", err)
	}
	base := desktopEntryExit(entry)
	base["desktop_physical_egress"] = expected
	source := torHostEncode(t, base)
	for _, target := range []string{"linux", "darwin", "windows"} {
		for name, alter := range map[string]func(map[string]any){
			"port":    func(p map[string]any) { p["desktop_physical_egress"].([]any)[0].(map[string]any)["port"] = 443 },
			"network": func(p map[string]any) { p["desktop_physical_egress"].([]any)[0].(map[string]any)["network"] = "tcp" },
			"host": func(p map[string]any) {
				p["desktop_physical_egress"].([]any)[0].(map[string]any)["host"] = "198.51.100.99"
			},
			"port-string": func(p map[string]any) { p["desktop_physical_egress"].([]any)[0].(map[string]any)["port"] = "51820" },
			"port-bool":   func(p map[string]any) { p["desktop_physical_egress"].([]any)[0].(map[string]any)["port"] = true },
			"unknown":     func(p map[string]any) { p["desktop_physical_egress"].([]any)[0].(map[string]any)["allow_all"] = true },
			"duplicate": func(p map[string]any) {
				p["desktop_physical_egress"] = append(p["desktop_physical_egress"].([]any), p["desktop_physical_egress"].([]any)[0])
			},
			"missing":     func(p map[string]any) { p["desktop_physical_egress"] = []any{} },
			"null":        func(p map[string]any) { p["desktop_physical_egress"] = nil },
			"object":      func(p map[string]any) { p["desktop_physical_egress"] = map[string]any{} },
			"wrong-owner": func(p map[string]any) { p["multihop_entry_id"] = "other-entry" },
		} {
			t.Run(target+"/"+name, func(t *testing.T) {
				profile, _ := profileObject(source, 256<<10)
				alter(profile)
				if _, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, profile), desktopSession, desktopIsolation, target, entry); err == nil {
					t.Fatal("changed physical access was accepted", name)
				}
			})
		}
	}
	duplicate := strings.Replace(source, `"desktop_physical_egress":`, `"desktop_physical_egress":[],"desktop_physical_egress":`, 1)
	if _, err := NewDesktopBridgePolicyWithPredecessor(duplicate, desktopSession, desktopIsolation, "linux", entry); err == nil {
		t.Fatal("duplicate projection member was accepted")
	}
	direct := desktopProfile()
	direct["desktop_physical_egress"] = expected
	if _, err := NewDesktopBridgePolicy(torHostEncode(t, direct), desktopSession, desktopIsolation, "linux"); err == nil {
		t.Fatal("direct Tor borrowed a Router physical projection")
	}
	// The field is runtime-only and does not change the existing pure compiler
	// contract. Native host launch wrappers enforce its required presence.
	delete(base, "desktop_physical_egress")
	if _, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, base), desktopSession, desktopIsolation, "linux", entry); err != nil {
		t.Fatal("pure compiler lost its existing captured-predecessor contract", err)
	}
}
