package mobilemultihop

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

var desktopSS2022Methods = []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}

func desktopSSEntryInput(t *testing.T, entryMethod, finalMethod string) (map[string]any, map[string]any) {
	t.Helper()
	graph, capture := externalTestFixture(t, "shadowsocks", "shadowsocks")
	for i, method := range []string{entryMethod, finalMethod} {
		field, tag, seed := "entry", "external-entry", "i"
		if i == 1 {
			field, tag, seed = "profile", ExternalFinalTag, "e"
		}
		size := 32
		if method == desktopSS2022Methods[0] {
			size = 16
		}
		key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(seed, size)))
		row := externalTestFind(t, graph, tag)
		row["method"], row["password"] = method, key
		source := capture[field].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
		source["method"], source["password"] = method, key
	}
	return graph, capture
}
func TestDesktopExternalDarwinSSEntryOwnsTwoOriginalSourcesAndPolicy(t *testing.T) {
	for _, entryMethod := range desktopSS2022Methods {
		for _, finalMethod := range desktopSS2022Methods {
			for _, kill := range []string{"on-connect", "always"} {
				for _, dns := range []string{"tcp", "udp"} {
					for _, ipv6 := range []string{"on", "off"} {
						for _, lan := range []bool{true, false} {
							graph, capture := desktopSSEntryInput(t, entryMethod, finalMethod)
							profile := capture["profile"].(map[string]any)
							profile["kill_switch_policy"], profile["mtu_policy"], profile["manual_mtu"] = kill, "manual", 1360
							profile["ipv6_mode"], profile["home_lan_access"] = ipv6, lan
							profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", dns, "203.0.113.53", 5353
							original := externalDesktopCompile(t, graph, capture)
							plan, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, "darwin")
							if err != nil {
								t.Fatal(err)
							}
							actual, err := plan.Capture()
							if err != nil {
								t.Fatal(err)
							}
							derived := externalTestRead(t, plan.Config())
							old := externalTestRead(t, original.Config())
							entry := externalTestFind(t, derived, "external-entry")
							final := externalTestFind(t, derived, ExternalFinalTag)
							if len(derived["outbounds"].([]any)) != 3 || len(derived["endpoints"].([]any)) != 0 || entry["detour"] != DesktopExternalPhysicalTag || final["detour"] != "external-entry" || !reflect.DeepEqual(final, externalTestFind(t, old, ExternalFinalTag)) {
								t.Fatal("SS entry graph bypassed an original owner")
							}
							delete(entry, "detour")
							if !reflect.DeepEqual(entry, externalTestFind(t, old, "external-entry")) {
								t.Fatal("SS entry changed its original credentials")
							}
							if actual.EntryID != "saved-entry" || len(actual.PhysicalRoots) != 1 || actual.PhysicalRoots[0].Family != "outbounds" || actual.PhysicalRoots[0].Type != "shadowsocks" || actual.PhysicalRoots[0].Tag != "external-entry" || len(actual.PhysicalRoots[0].Destinations) != 2 || actual.SelectedDNS.Physical || actual.SelectedDNS.Detour != ExternalFinalTag || actual.SelectedDNS.Type != dns || actual.ConfiguredMTU != 1360 || actual.IPv6Mode != ipv6 || actual.HomeLANAccess != lan || actual.KillSwitchPolicy != kill {
								t.Fatal("SS entry lost captured policy")
							}
							for _, dest := range actual.PhysicalRoots[0].Destinations {
								if dest.Host != "198.51.100.20" || dest.Port != 8443 || dest.Network != "tcp" && dest.Network != "udp" {
									t.Fatal("final acquired physical authority")
								}
							}
							for _, target := range []string{"linux", "windows"} {
								if p, e := NewDesktopExternalPolicy(original, desktopExternalTestSession, target); e == nil || p != nil {
									t.Fatal("SS entry widened another retained host")
								}
							}
						}
					}
				}
			}
		}
	}
}
func TestDesktopExternalDarwinSSEntryRejectsUncapturedGraphAndMethods(t *testing.T) {
	for _, fault := range []string{"legacy-entry", "legacy-final", "entry-layer", "final-layer", "final-family", "foreign-root", "extra-outbound", "direct-final"} {
		t.Run(fault, func(t *testing.T) {
			graph, capture := desktopSSEntryInput(t, desktopSS2022Methods[1], desktopSS2022Methods[1])
			capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
			switch fault {
			case "legacy-entry", "legacy-final":
				field, tag := "entry", "external-entry"
				if fault == "legacy-final" {
					field, tag = "profile", ExternalFinalTag
				}
				externalTestFind(t, graph, tag)["method"] = "aes-256-gcm"
				capture[field].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)["method"] = "aes-256-gcm"
			case "entry-layer":
				capture["entry"].(map[string]any)["start_layer"] = "aes-256-gcm"
			case "final-layer":
				capture["profile"].(map[string]any)["start_layer"] = "aes-256-gcm"
			case "final-family":
				graph, capture = externalTestFixture(t, "hysteria2", "shadowsocks")
				capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
			case "foreign-root":
				externalTestFind(t, graph, "external-entry")["server"] = "192.0.2.88"
			case "extra-outbound":
				graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": "unowned"})
			case "direct-final":
				delete(externalTestFind(t, graph, ExternalFinalTag), "detour")
			}
			original, e := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
			if e != nil {
				return
			}
			if next, e := NewDesktopExternalPolicy(original, desktopExternalTestSession, "darwin"); e == nil || next != nil {
				t.Fatal("unsupported SS graph admitted", fault)
			}
		})
	}
}
