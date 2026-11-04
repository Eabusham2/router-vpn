package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func TestDesktopExternalDarwinWireGuardEntryOwnsFirstRootAndCompletePolicy(t *testing.T) {
	for _, kill := range []string{"on-connect", "always"} {
		for _, ipv6 := range []string{"on", "off"} {
			for _, lan := range []bool{false, true} {
				graph, capture := externalTestFixture(t, "shadowsocks", "wireguard")
				profile := capture["profile"].(map[string]any)
				profile["kill_switch_policy"], profile["ipv6_mode"], profile["home_lan_access"] = kill, ipv6, lan
				profile["mtu_policy"], profile["manual_mtu"] = "manual", 1360
				original := externalDesktopCompile(t, graph, capture)
				plan, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "darwin")
				if err != nil {
					t.Fatal(err)
				}
				actual, err := plan.Capture()
				if err != nil {
					t.Fatal(err)
				}
				meta := plan.Metadata()
				derived := externalTestRead(t, plan.Config())
				source := externalTestRead(t, original.Config())
				entry := externalTestFind(t, derived, "external-entry")
				exit := externalTestFind(t, derived, ExternalFinalTag)
				if actual.EntryID != "saved-entry" || actual.EntryTag != "external-entry" || len(actual.PhysicalRoots) != 1 || actual.PhysicalRoots[0].Tag != "external-entry" || meta.RootTag != "external-entry" || meta.RootType != "wireguard" || meta.Protocol != "shadowsocks" || meta.SOCKSUDPAssociationRequired || entry["detour"] != DesktopExternalPhysicalTag || exit["detour"] != "external-entry" || !reflect.DeepEqual(exit, externalTestFind(t, source, ExternalFinalTag)) || actual.SelectedDNS.Detour != ExternalFinalTag || actual.SelectedDNS.Physical || actual.ConfiguredMTU != 1360 || actual.KillSwitchPolicy != kill || actual.IPv6Mode != ipv6 || actual.HomeLANAccess != lan {
					t.Fatal("entry lost exact root, final graph or device policy")
				}
				for _, tuple := range actual.PhysicalRoots[0].Destinations {
					if tuple.Network != "udp" || tuple.Port != 8443 || tuple.Host != "198.51.100.20" {
						t.Fatal("final exit borrowed physical permission", tuple)
					}
				}
				if plan.OriginalPolicy() != original || original.SourceSHA256() != meta.OriginalSourceSHA256 {
					t.Fatal("original two-hop proof was relabelled")
				}
				for _, target := range []string{"linux", "windows"} {
					if p, e := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), target); e == nil || p != nil {
						t.Fatal("another native host acquired unimplemented entry", target)
					}
				}
			}
		}
	}
}

func TestDesktopExternalDarwinWireGuardEntryPreservesOtherGraphBoundaries(t *testing.T) {
	for _, entry := range []string{"router-wg", "shadowsocks", "socks5", "hysteria2", "http-connect", "https-connect"} {
		graph, capture := externalTestFixture(t, "shadowsocks", entry)
		capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
		original := externalDesktopCompile(t, graph, capture)
		if plan, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "darwin"); err == nil || plan != nil {
			t.Fatal("unimplemented first root admitted", entry)
		}
	}
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "hysteria2"} {
		graph, capture := externalTestFixture(t, protocol, "wireguard")
		capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
		original := externalDesktopCompile(t, graph, capture)
		if plan, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "darwin"); err == nil || plan != nil {
			t.Fatal("unimplemented final graph admitted", protocol)
		}
	}
}
