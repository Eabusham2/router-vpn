package mobilemultihop

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func desktopSSCONNECTInput(t *testing.T, method, protocol string) (map[string]any, map[string]any) {
	t.Helper()
	graph, capture := externalTestFixture(t, protocol, "shadowsocks")
	size := 32
	if method == desktopSS2022Methods[0] {
		size = 16
	}
	password := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", size)))
	row := externalTestFind(t, graph, "external-entry")
	row["method"], row["password"] = method, password
	source := capture["entry"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
	source["method"], source["password"] = method, password
	p := capture["profile"].(map[string]any)
	p["kill_switch_policy"], p["dns_mode"], p["dns_protocol"], p["dns_host"], p["dns_port"] = "always", "custom", "tcp", "203.0.113.53", 5353
	return graph, capture
}
func TestDesktopExternalDarwinSSCONNECTKeepsOriginalSourcesAndTCPDNS(t *testing.T) {
	for _, method := range desktopSS2022Methods {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, kill := range []string{"on-connect", "always"} {
				for _, ipv6 := range []string{"on", "off"} {
					for _, lan := range []bool{false, true} {
						graph, capture := desktopSSCONNECTInput(t, method, protocol)
						p := capture["profile"].(map[string]any)
						p["kill_switch_policy"], p["ipv6_mode"], p["home_lan_access"], p["mtu_policy"], p["manual_mtu"] = kill, ipv6, lan, "manual", 1360
						original := externalDesktopCompile(t, graph, capture)
						plan, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, "darwin")
						if err != nil {
							t.Fatal(err)
						}
						actual, err := plan.Capture()
						if err != nil {
							t.Fatal(err)
						}
						derived, old := externalTestRead(t, plan.Config()), externalTestRead(t, original.Config())
						entry, final := externalTestFind(t, derived, "external-entry"), externalTestFind(t, derived, ExternalFinalTag)
						if len(derived["outbounds"].([]any)) != 3 || len(derived["endpoints"].([]any)) != 0 || entry["detour"] != DesktopExternalPhysicalTag || final["detour"] != "external-entry" || !reflect.DeepEqual(final, externalTestFind(t, old, ExternalFinalTag)) {
							t.Fatal("CONNECT changed original final credentials/TLS or escaped SS entry")
						}
						delete(entry, "detour")
						if !reflect.DeepEqual(entry, externalTestFind(t, old, "external-entry")) {
							t.Fatal("CONNECT replaced original SS source")
						}
						if actual.Protocol != protocol || actual.UDPAvailable || actual.SelectedDNS.Type != "tcp" || actual.SelectedDNS.Detour != ExternalFinalTag || actual.SelectedDNS.Physical || actual.ConfiguredMTU != 1360 || actual.IPv6Mode != ipv6 || actual.HomeLANAccess != lan || actual.KillSwitchPolicy != kill || len(actual.PhysicalRoots) != 1 || actual.PhysicalRoots[0].Tag != "external-entry" || len(actual.PhysicalRoots[0].Destinations) != 1 {
							t.Fatal("CONNECT lost captured device/DNS/firstroot policy", actual.Protocol, actual.UDPAvailable, actual.SelectedDNS.Type, actual.SelectedDNS.Detour, actual.ConfiguredMTU, actual.PhysicalRoots)
						}
						for _, d := range actual.PhysicalRoots[0].Destinations {
							if d.Host != "198.51.100.20" || d.Port != 8443 || d.Network != "tcp" {
								t.Fatal("CONNECT obtained physical final authority")
							}
						}
						linux, e := NewDesktopExternalPolicy(original, desktopExternalTestSession, "linux")
						if e != nil || linux == nil || linux.OriginalPolicy() != original || linux.Metadata().TargetOS != "linux" {
							t.Fatal("Linux CONNECT lost original policy", e)
						}
						linuxCapture, e := linux.Capture()
						linuxGraph := externalTestRead(t, linux.Config())
						if e != nil || !reflect.DeepEqual(linuxCapture, actual) || !reflect.DeepEqual(externalTestFind(t, linuxGraph, ExternalFinalTag), externalTestFind(t, derived, ExternalFinalTag)) || !reflect.DeepEqual(linuxGraph["dns"], derived["dns"]) || !reflect.DeepEqual(linuxGraph["route"], derived["route"]) {
							t.Fatal("Linux CONNECT replaced captured graph or final DNS", e)
						}
						for _, target := range []string{"windows"} {
							if next, e := NewDesktopExternalPolicy(original, desktopExternalTestSession, target); e == nil || next != nil {
								t.Fatal("CONNECT widened another retained host")
							}
						}
					}
				}
			}
		}
	}
}
func TestDesktopExternalDarwinSSCONNECTRejectsUnavailableDNSAndGraph(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, fault := range []string{"udp-dns", "entry-layer", "final-layer", "foreign-auth", "foreign-root", "direct-final"} {
			t.Run(protocol+"/"+fault, func(t *testing.T) {
				graph, capture := desktopSSCONNECTInput(t, desktopSS2022Methods[1], protocol)
				switch fault {
				case "udp-dns":
					capture["profile"].(map[string]any)["dns_protocol"] = "udp"
				case "entry-layer":
					capture["entry"].(map[string]any)["start_layer"] = "aes-256-gcm"
				case "final-layer":
					capture["profile"].(map[string]any)["start_layer"] = "aes-256-gcm"
				case "foreign-auth":
					externalTestFind(t, graph, ExternalFinalTag)["username"] = "foreign-username"
				case "foreign-root":
					externalTestFind(t, graph, "external-entry")["server"] = "192.0.2.88"
				case "direct-final":
					delete(externalTestFind(t, graph, ExternalFinalTag), "detour")
				}
				original, e := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
				if fault == "udp-dns" {
					if e == nil || !strings.Contains(e.Error(), "selected UDP DNS cannot traverse") {
						t.Fatal("CONNECT silently replaced or admitted UDP DNS", e)
					}
					return
				}
				if e != nil {
					return
				}
				for _, target := range []string{"darwin", "linux"} {
					if next, e := NewDesktopExternalPolicy(original, desktopExternalTestSession, target); e == nil || next != nil {
						t.Fatal("uncaptured SS CONNECT graph admitted", target, fault)
					}
				}
			})
		}
	}
}
