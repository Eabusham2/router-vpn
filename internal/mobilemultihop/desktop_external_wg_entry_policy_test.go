package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func TestDesktopExternalDarwinWireGuardEntryOwnsFirstRootAndCompletePolicy(t *testing.T) {
	desktopExternalPacketEntryOwnsPolicy(t, "wireguard")
}
func TestDesktopExternalDarwinAmneziaEntryOwnsFirstRootAndCompletePolicy(t *testing.T) {
	for _, variant := range []string{"fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryOwnsPolicy(t, variant) })
	}
}
func desktopExternalPacketEntryOwnsPolicy(t *testing.T, variant string) {
	for _, kill := range []string{"on-connect", "always"} {
		for _, ipv6 := range []string{"on", "off"} {
			for _, lan := range []bool{false, true} {
				graph, capture := externalTestFixture(t, "shadowsocks", "wireguard")
				rootType := "wireguard"
				if variant != "wireguard" {
					rootType = AmneziaType
					parameters := map[string]any{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
					if variant == "fast" {
						parameters["jc"], parameters["jmin"], parameters["jmax"], parameters["s4"] = "0", "20", "40", "8"
					}
					endpoint := externalTestFind(t, graph, "external-entry")
					endpoint["type"], endpoint["amnezia"] = rootType, parameters
					external := capture["entry"].(map[string]any)["external"].(map[string]any)
					imported := external["wireguard"].(map[string]any)
					imported["parameters"] = parameters
					external["protocol"], external["amneziawg"] = "amneziawg", imported
					delete(external, "wireguard")
				}
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
				retained := externalTestRead(t, externalTestJSON(t, entry))
				delete(retained, "detour")
				if !reflect.DeepEqual(retained, externalTestFind(t, source, "external-entry")) {
					t.Fatal("entry changed its exact keys, all eleven AWG parameters or MTU")
				}
				if actual.EntryID != "saved-entry" || actual.EntryTag != "external-entry" || len(actual.PhysicalRoots) != 1 || actual.PhysicalRoots[0].Tag != "external-entry" || meta.RootTag != "external-entry" || meta.RootType != rootType || meta.Protocol != "shadowsocks" || meta.SOCKSUDPAssociationRequired || entry["detour"] != DesktopExternalPhysicalTag || exit["detour"] != "external-entry" || !reflect.DeepEqual(exit, externalTestFind(t, source, ExternalFinalTag)) || actual.SelectedDNS.Detour != ExternalFinalTag || actual.SelectedDNS.Physical || actual.ConfiguredMTU != 1360 || actual.KillSwitchPolicy != kill || actual.IPv6Mode != ipv6 || actual.HomeLANAccess != lan {
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
