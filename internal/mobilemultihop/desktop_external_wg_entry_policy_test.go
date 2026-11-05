package mobilemultihop

import (
	"encoding/base64"
	"reflect"
	"router-vpn/internal/multihoprelay"
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
	desktopExternalPacketEntryExitOwnsPolicy(t, variant, "shadowsocks")
}
func TestDesktopExternalDarwinPacketEntryCONNECTRetainsCompletePolicy(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			t.Run(variant+"/"+protocol, func(t *testing.T) { desktopExternalPacketEntryExitOwnsPolicy(t, variant, protocol) })
		}
	}
}
func TestDesktopExternalDarwinPacketEntryHysteriaRetainsCompletePolicy(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitOwnsPolicy(t, variant, "hysteria2") })
	}
}
func TestDesktopExternalDarwinPacketEntrySOCKSRetainsCompletePolicy(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitOwnsPolicy(t, variant, "socks5") })
	}
}
func TestDesktopExternalDarwinPacketEntryHysteriaLayersRetainCompletePolicy(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(variant+"/"+layer, func(t *testing.T) { desktopExternalPacketEntryLayerOwnsPolicy(t, variant, "hysteria2", layer) })
		}
	}
}
func desktopExternalPacketEntryExitOwnsPolicy(t *testing.T, variant, protocol string) {
	desktopExternalPacketEntryLayerOwnsPolicy(t, variant, protocol, "")
}
func desktopExternalPacketEntryLayerOwnsPolicy(t *testing.T, variant, protocol, layer string, finalVariants ...string) {
	for _, kill := range []string{"on-connect", "always"} {
		for _, ipv6 := range []string{"on", "off"} {
			for _, lan := range []bool{false, true} {
				finalVariant := "strong"
				if len(finalVariants) != 0 {
					finalVariant = finalVariants[0]
				}
				graph, capture := desktopExternalInputFixture(t, protocol, "wireguard", finalVariant)
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
				if protocol == "openvpn" {
					externalTestFind(t, graph, "external-entry")["mtu"] = float64(1440)
					entry := capture["entry"].(map[string]any)
					imported := entry["external"].(map[string]any)
					field := "wireguard"
					if variant != "wireguard" {
						field = "amneziawg"
					}
					imported[field].(map[string]any)["mtu"] = float64(1440)
				}
				profile := capture["profile"].(map[string]any)
				profile["kill_switch_policy"], profile["ipv6_mode"], profile["home_lan_access"] = kill, ipv6, lan
				mtu := 1360
				if protocol == "openvpn" {
					mtu = 1280
				}
				if protocol == "amneziawg" {
					mtu = 1328
				}
				profile["mtu_policy"], profile["manual_mtu"] = "manual", mtu
				if layer != "" {
					externalTestAddLayer(profile, layer, "203.0.113.20", "10.93.0.1", "e")
				}
				original := externalDesktopCompile(t, graph, capture)
				plan, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "darwin")
				if err != nil {
					t.Fatal(err)
				}
				if layer != "" {
					for _, foreign := range []string{"linux", "windows"} {
						if foreign == "linux" && variant == "wireguard" && protocol == "hysteria2" {
							continue // Exact complete Linux graph is asserted below.
						}
						if unsupported, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), foreign); err == nil || unsupported != nil {
							t.Fatal("Darwin layered entry expanded another host", foreign)
						}
					}
				}
				actual, err := plan.Capture()
				if err != nil {
					t.Fatal(err)
				}
				meta := plan.Metadata()
				finalDetour := "external-entry"
				if layer != "" {
					finalDetour = multihoprelay.ExitStartLayerTag
				}
				derived := externalTestRead(t, plan.Config())
				source := externalTestRead(t, original.Config())
				entry := externalTestFind(t, derived, "external-entry")
				exit := externalTestFind(t, derived, ExternalFinalTag)
				retained := externalTestRead(t, externalTestJSON(t, entry))
				delete(retained, "detour")
				if !reflect.DeepEqual(retained, externalTestFind(t, source, "external-entry")) {
					t.Fatal("entry changed its exact keys, all eleven AWG parameters or MTU")
				}
				if protocol == "socks5" {
					if exit["type"] != DesktopExternalSOCKSType || exit["session_id"] != meta.SessionID || exit["source_sha256"] != meta.SourceSHA256 {
						t.Fatal("tunneled SOCKS lost original association owner")
					}
					exit["type"] = "socks"
					delete(exit, "session_id")
					delete(exit, "source_sha256")
				}
				if actual.EntryID != "saved-entry" || actual.EntryTag != "external-entry" || len(actual.PhysicalRoots) != 1 || actual.PhysicalRoots[0].Tag != "external-entry" || meta.RootTag != "external-entry" || meta.RootType != rootType || meta.Protocol != protocol || meta.SOCKSUDPAssociationRequired != (protocol == "socks5") || meta.SOCKSUDPAssociationTunneled != (protocol == "socks5") || actual.PhysicalRoots[0].DynamicSOCKSUDP || entry["detour"] != DesktopExternalPhysicalTag || actual.StartLayer != layer || exit["detour"] != finalDetour || !reflect.DeepEqual(exit, externalTestFind(t, source, ExternalFinalTag)) || actual.SelectedDNS.Detour != ExternalFinalTag || actual.SelectedDNS.Physical || actual.ConfiguredMTU != mtu || actual.KillSwitchPolicy != kill || actual.IPv6Mode != ipv6 || actual.HomeLANAccess != lan {
					t.Fatal("entry lost exact root, final graph or device policy")
				}
				if protocol == "wireguard" || protocol == "amneziawg" || protocol == "openvpn" {
					finalType := protocol
					if protocol == "openvpn" {
						finalType = "openvpn-client"
					}
					if protocol == "amneziawg" {
						finalType = AmneziaType
					}
					if len(derived["endpoints"].([]any)) != 2 || len(derived["outbounds"].([]any)) != 1 || exit["type"] != finalType {
						t.Fatal("packet final lost its two distinct endpoints or acquired another physical outbound")
					}
				}
				if layer != "" {
					outer := externalTestFind(t, derived, multihoprelay.ExitStartLayerTag)
					if !reflect.DeepEqual(outer, externalTestFind(t, source, multihoprelay.ExitStartLayerTag)) || outer["detour"] != "external-entry" || exit["server"] != "10.93.0.1" || len(derived["outbounds"].([]any)) != 3 {
						t.Fatal("exit layer changed its captured key/private transport or bypassed original packet entry")
					}
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
					p, e := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), target)
					if target == "linux" && variant == "wireguard" && (protocol == "shadowsocks" || protocol == "http-connect" || protocol == "https-connect" || protocol == "hysteria2") && (layer == "" || protocol == "hysteria2") {
						if e != nil || p == nil || p.Validate() != nil {
							t.Fatal("Linux lost its exact imported WG/final pair", e)
						}
						linux := externalTestRead(t, p.Config())
						if p.Metadata().TargetOS != "linux" || p.OriginalPolicy() != original ||
							!reflect.DeepEqual(externalTestFind(t, linux, "external-entry"), entry) ||
							!reflect.DeepEqual(externalTestFind(t, linux, ExternalFinalTag), exit) ||
							!reflect.DeepEqual(linux["dns"], derived["dns"]) ||
							layer != "" && !reflect.DeepEqual(externalTestFind(t, linux, multihoprelay.ExitStartLayerTag), externalTestFind(t, derived, multihoprelay.ExitStartLayerTag)) {
							t.Fatal("Linux changed captured entry keys, final credentials/TLS or selected DNS")
						}
					} else if e == nil || p != nil {
						t.Fatal("another native host acquired unimplemented entry", target)
					}
				}
			}
		}
	}
}

func TestDesktopExternalDarwinWireGuardEntryPreservesOtherGraphBoundaries(t *testing.T) {
	for _, entry := range []string{"router-wg", "shadowsocks", "socks5", "hysteria2", "http-connect", "https-connect"} {
		final := "shadowsocks"
		if entry == "shadowsocks" {
			// Only the separate captured SS2022 -> SS2022 unit is admitted.
			final = "hysteria2"
		}
		graph, capture := externalTestFixture(t, final, entry)
		capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
		original := externalDesktopCompile(t, graph, capture)
		if plan, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "darwin"); err == nil || plan != nil {
			t.Fatal("unimplemented first root admitted", entry)
		}
	}
	for _, protocol := range []string{"openvpn"} {
		graph, capture := externalTestFixture(t, "wireguard", "wireguard")
		externalOpenVPNReplace(t, graph, capture, false, "tcp")
		capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
		original := externalDesktopCompile(t, graph, capture)
		if plan, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "windows"); err == nil || plan != nil {
			t.Fatal("unimplemented host/final graph admitted", protocol)
		}
	}
}

func TestDesktopExternalDarwinPacketEntryWireGuardRetainsCompletePolicy(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitOwnsPolicy(t, variant, "wireguard") })
	}
}

func TestDesktopExternalDarwinPacketEntryAmneziaRetainsCompletePolicy(t *testing.T) {
	for _, entry := range []string{"wireguard", "fast", "strong"} {
		for _, final := range []string{"fast", "strong"} {
			t.Run(entry+"/"+final, func(t *testing.T) { desktopExternalPacketEntryLayerOwnsPolicy(t, entry, "amneziawg", "", final) })
		}
	}
}

func TestDesktopExternalDarwinPacketEntryOpenVPNRetainsCompletePolicy(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitOwnsPolicy(t, variant, "openvpn") })
	}
}

func TestDesktopExternalLinuxWireGuardEntryKeepsCapturedSS2022Methods(t *testing.T) {
	for _, method := range append(append([]string(nil), desktopSS2022Methods...), "aes-256-gcm") {
		t.Run(method, func(t *testing.T) {
			graph, capture := desktopExternalInputFixture(t, "shadowsocks", "wireguard", "strong")
			capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
			key := strings.Repeat("e", 32)
			if method == "2022-blake3-aes-128-gcm" {
				key = strings.Repeat("e", 16)
			}
			// The ordinary parser retains the independently captured final source;
			// the Linux adapter additionally keeps this tranche's SS2022 boundary.
			password := base64.StdEncoding.EncodeToString([]byte(key))
			row := externalTestFind(t, graph, ExternalFinalTag)
			row["method"], row["password"] = method, password
			source := capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
			source["method"], source["password"] = method, password
			original := externalDesktopCompile(t, graph, capture)
			plan, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "linux")
			if method == "aes-256-gcm" {
				if err == nil || plan != nil {
					t.Fatal("Linux adopted an uncaptured legacy cipher family")
				}
				return
			}
			if err != nil || plan.Validate() != nil {
				t.Fatal("Linux lost a complete SS2022 source", err)
			}
		})
	}
}
