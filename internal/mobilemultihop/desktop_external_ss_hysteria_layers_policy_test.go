package mobilemultihop

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

func TestDesktopExternalSSHysteriaIndependentLayersKeepPhysicalEntry(t *testing.T) {
	modes := []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}
	for a, entryMethod := range desktopSS2022Methods {
		for b, finalMethod := range []string{"hysteria2"} {
			for i, entryMode := range modes {
				for j, finalMode := range modes {
					t.Run(fmt.Sprintf("method%d-method%d/layer%d-layer%d", a, b, i, j), func(t *testing.T) {
						graph, capture := desktopSSHysteriaLayerInput(t, entryMethod, finalMethod)
						profile, entry := capture["profile"].(map[string]any), capture["entry"].(map[string]any)
						profile["kill_switch_policy"] = "always"
						if entryMode != "" {
							externalTestAddLayer(entry, entryMode, "198.51.100.20", "10.94.0.1", "i")
						}
						if finalMode != "" {
							externalTestAddLayer(profile, finalMode, "203.0.113.20", "10.93.0.1", "e")
						}
						original := externalDesktopCompile(t, graph, capture)
						expected := externalTestRead(t, original.Config())
						rootTag := "external-entry"
						rootKind := "shadowsocks"
						count := 3
						if entryMode != "" {
							rootTag = ExternalEntryStartLayerTag
							rootKind = desktopExternalLayerKind(entryMode)
							count++
						}
						if finalMode != "" {
							count++
						}
						for _, target := range []string{"linux", "darwin", "windows"} {
							plan, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target)
							if err != nil {
								t.Fatal(target, err)
							}
							actual, err := plan.Capture()
							if err != nil {
								t.Fatal(err)
							}
							derived := externalTestRead(t, plan.Config())
							if len(derived["outbounds"].([]any)) != count || plan.Metadata().RootTag != rootTag || plan.Metadata().RootType != rootKind || actual.EntryStartLayer != entryMode || actual.StartLayer != finalMode || actual.SelectedDNS.Physical || actual.SelectedDNS.Detour != ExternalFinalTag || len(actual.PhysicalRoots) != 1 || len(actual.PhysicalRoots[0].Destinations) != 2 {
								t.Fatal("independent layer ownership or routed DNS changed", target, actual)
							}
							for _, tag := range []string{"external-entry", ExternalFinalTag, ExternalEntryStartLayerTag, multihoprelay.ExitStartLayerTag} {
								if tag == ExternalEntryStartLayerTag && entryMode == "" || tag == multihoprelay.ExitStartLayerTag && finalMode == "" {
									continue
								}
								row := externalTestFind(t, derived, tag)
								if tag == rootTag {
									if row["detour"] != DesktopExternalPhysicalTag {
										t.Fatal("root lost physical owner")
									}
									delete(row, "detour")
								}
								if !reflect.DeepEqual(row, externalTestFind(t, expected, tag)) {
									t.Fatal("native adaptation changed captured credential or original detour", tag)
								}
							}
							for _, destination := range actual.PhysicalRoots[0].Destinations {
								if destination.Host != "198.51.100.20" || destination.Network != "tcp" && destination.Network != "udp" {
									t.Fatal("private/final layer gained physical exception", destination)
								}
							}
						}
					})
				}
			}
		}
	}
}

func TestDesktopExternalSSHysteriaLayerRowsRefuseChangedOwnership(t *testing.T) {
	for _, fault := range []string{"extra", "duplicate", "raw-entry-direct", "final-direct", "final-layer-direct", "entry-layer-detour", "cross-layer", "wrong-layer-cipher", "wrong-layer-type"} {
		t.Run(fault, func(t *testing.T) {
			graph, selected := desktopSSHysteriaLayerInput(t, desktopSS2022Methods[1], "hysteria2")
			profile, entry := selected["profile"].(map[string]any), selected["entry"].(map[string]any)
			profile["kill_switch_policy"] = "always"
			externalTestAddLayer(entry, "aes-256-gcm+xor-whitening", "198.51.100.20", "10.94.0.1", "i")
			externalTestAddLayer(profile, "aes-256-gcm", "203.0.113.20", "10.93.0.1", "e")
			original := externalDesktopCompile(t, graph, selected)
			capture, err := original.DesktopCapture()
			if err != nil {
				t.Fatal(err)
			}
			current := externalTestRead(t, original.Config())
			rows := current["outbounds"].([]any)
			switch fault {
			case "extra":
				rows = append(rows, map[string]any{"type": "direct", "tag": "foreign"})
			case "duplicate":
				rows[0] = rows[1]
			case "raw-entry-direct":
				delete(externalTestFind(t, current, "external-entry"), "detour")
			case "final-direct":
				delete(externalTestFind(t, current, ExternalFinalTag), "detour")
			case "final-layer-direct":
				delete(externalTestFind(t, current, multihoprelay.ExitStartLayerTag), "detour")
			case "entry-layer-detour":
				externalTestFind(t, current, ExternalEntryStartLayerTag)["detour"] = ExternalFinalTag
			case "cross-layer":
				externalTestFind(t, current, ExternalFinalTag)["detour"] = ExternalEntryStartLayerTag
			case "wrong-layer-cipher":
				externalTestFind(t, current, multihoprelay.ExitStartLayerTag)["method"] = "2022-blake3-chacha20-poly1305"
			case "wrong-layer-type":
				externalTestFind(t, current, multihoprelay.ExitStartLayerTag)["type"] = "routervpn-aes-xor"
			}
			if physical, err := desktopExternalSSRows(rows, capture, "hysteria2", capture.PhysicalRoots[0]); err == nil || physical != nil {
				t.Fatal("changed layer graph acquired physical owner")
			}
		})
	}
}

func desktopSSHysteriaLayerInput(t *testing.T, method, final string) (map[string]any, map[string]any) {
	t.Helper()
	graph, capture := externalTestFixture(t, "hysteria2", "shadowsocks")
	size := 32
	if method == desktopSS2022Methods[0] {
		size = 16
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", size)))
	row := externalTestFind(t, graph, "external-entry")
	row["method"], row["password"] = method, key
	source := capture["entry"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
	source["method"], source["password"] = method, key
	return graph, capture
}
