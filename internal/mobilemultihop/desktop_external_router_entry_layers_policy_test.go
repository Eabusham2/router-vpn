package mobilemultihop

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

// Each side comes from its own original captured source. The entry fixture
// uses the actual WG/base Start Layer composer and complete predecessor merge;
// no already-sealed runtime or metadata is edited to manufacture acceptance.
func desktopExternalRouterEntryLayerInput(t *testing.T, execution, entryLayer, finalLayer, dns string) (string, string) {
	t.Helper()
	source, raw := desktopExternalRouterLayerInput(t, execution, finalLayer, NativeStartLayerMethod, dns)
	capture := externalTestRead(t, raw)
	predecessor, entry := externalPredecessorFixture(t, "wg", entryLayer, false)
	entry["id"] = "saved-entry"
	capture["entry"], capture["predecessor_config"] = entry, predecessor
	return source, externalTestJSON(t, capture)
}

func TestDesktopWindowsExternalRouterEntryLayersPolicy(t *testing.T) {
	for _, execution := range []string{"local", "server", "auto"} {
		for _, entryLayer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, finalLayer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, dns := range []string{"home", "custom"} {
					t.Run(strings.Join([]string{execution, entryLayer, "final-" + finalLayer, dns}, "/"), func(t *testing.T) {
						source, raw := desktopExternalRouterEntryLayerInput(t, execution, entryLayer, finalLayer, dns)
						original := desktopExternalRouterLayerPolicy(t, source, raw, "")
						capture, err := original.DesktopCapture()
						if err != nil || capture.EntryStartLayer != entryLayer || capture.StartLayer != finalLayer {
							t.Fatal("captured Router entry Start Layer was omitted or conflated with the final", err)
						}
						policy, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "windows")
						if err != nil {
							t.Fatal("captured independent entry Start Layer refused", err)
						}
						before, after := externalTestRead(t, original.Config()), externalTestRead(t, policy.Config())
						rootTag := predecessorNamespace("node", NativeStartLayerTag)
						rootKind := desktopExternalLayerKind(entryLayer)
						root := externalTestFind(t, after, rootTag)
						if root["detour"] != DesktopExternalPhysicalTag || policy.Metadata().RootTag != rootTag || policy.Metadata().RootType != rootKind || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Family != "outbounds" || capture.PhysicalRoots[0].Tag != rootTag {
							t.Fatal("entry layer lost its own physical root")
						}
						delete(root, "detour")
						if !reflect.DeepEqual(root, externalTestFind(t, before, rootTag)) {
							t.Fatal("entry layer changed captured outer credentials")
						}
						for _, tag := range []string{externalEntryTag, LocalTag, ServerTag, ExternalFinalTag} {
							if !reflect.DeepEqual(externalTestFind(t, after, tag), externalTestFind(t, before, tag)) {
								t.Fatal("entry layer replaced an original inner owner", tag)
							}
						}
						if finalLayer != "" && !reflect.DeepEqual(externalTestFind(t, after, multihoprelay.ExitStartLayerTag), externalTestFind(t, before, multihoprelay.ExitStartLayerTag)) {
							t.Fatal("entry layer replaced the independent final wrapper")
						}
						meta := policy.Metadata()
						if meta.StartupEndpointTag != externalEntryTag || meta.StartupEndpointType != "wireguard" || meta.StartupEndpointSHA256 != desktopExternalObjectDigest(externalTestFind(t, before, externalEntryTag)) {
							t.Fatal("eager inner WG identity was confused with its outer physical root")
						}
						if eager, err := policy.StartupSocketRequired("windows"); err != nil || !eager {
							t.Fatal("captured inner WG lost its bounded startup requirement", err)
						}
						port := 8388
						if entryLayer == "aes-256-gcm+xor-whitening" {
							port = 8389
						}
						if !reflect.DeepEqual(capture.PhysicalRoots[0].Networks, []string{"udp"}) || !reflect.DeepEqual(capture.PhysicalRoots[0].Destinations, []PhysicalEgress{{Host: "192.0.2.44", Port: port, Network: "udp"}}) || capture.SelectedDNS.Physical {
							t.Fatal("entry layer promoted an inner WG, selected DNS or final tuple into physical egress")
						}
						for _, field := range []string{"dns", "route", "inbounds"} {
							if !reflect.DeepEqual(before[field], after[field]) {
								t.Fatal("entry layer changed captured DNS or device policy", field)
							}
						}
					})
				}
			}
		}
	}
}

func TestDesktopWindowsExternalRouterEntryLayersRestore(t *testing.T) {
	for _, entryLayer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, finalLayer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			source, raw := desktopExternalRouterEntryLayerInput(t, "auto", entryLayer, finalLayer, "home")
			original := desktopExternalRouterLayerPolicy(t, source, raw, "")
			for _, winner := range []string{"local", "server"} {
				t.Run(entryLayer+"/final-"+finalLayer+"/"+winner, func(t *testing.T) {
					restored := desktopExternalRouterLayerPolicy(t, source, raw, winner)
					policy, err := NewDesktopExternalPolicy(restored, strings.Repeat("b", 32), "windows")
					if err != nil {
						t.Fatal("captured independent entry did not restore", err)
					}
					capture, err := policy.Capture()
					if err != nil || capture.EntryStartLayer != entryLayer || capture.StartLayer != finalLayer || capture.Execution != winner || capture.ConfiguredMTU != 1360 ||
						restored.capture.Profile["multihop_execution"] != "auto" || restored.capture.Execution.Request.SessionID == original.capture.Execution.Request.SessionID || restored.capture.Execution.Request.Password == original.capture.Execution.Request.Password {
						t.Fatal("entry restoration lost its fixed choice, fresh lease or selected MTU", err)
					}
					if !reflect.DeepEqual(restored.capture.Entry, original.capture.Entry) || !reflect.DeepEqual(restored.capture.Profile, original.capture.Profile) || restored.capture.PredecessorConfig != original.capture.PredecessorConfig {
						t.Fatal("entry restoration replaced captured profiles or credential assets")
					}
					before, after := externalTestRead(t, original.Config()), externalTestRead(t, restored.Config())
					for _, tag := range []string{externalEntryTag, predecessorNamespace("node", NativeStartLayerTag), LocalTag} {
						if !reflect.DeepEqual(externalTestFind(t, before, tag), externalTestFind(t, after, tag)) {
							t.Fatal("entry restoration changed captured inner, outer or final credentials", tag)
						}
					}
					if finalLayer != "" && !reflect.DeepEqual(externalTestFind(t, before, multihoprelay.ExitStartLayerTag), externalTestFind(t, after, multihoprelay.ExitStartLayerTag)) {
						t.Fatal("entry restoration changed the independent final wrapper")
					}
					if !reflect.DeepEqual(before["dns"], after["dns"]) || !reflect.DeepEqual(before["inbounds"], after["inbounds"]) {
						t.Fatal("entry restoration changed selected DNS or interface policy")
					}
					for _, target := range []string{"linux", "darwin"} {
						if next, err := NewDesktopExternalPolicy(restored, strings.Repeat("c", 32), target); err == nil || next != nil {
							t.Fatal("paired entry layer broadened another native target", target)
						}
						if eager, err := policy.StartupSocketRequired(target); err == nil || eager {
							t.Fatal("Windows startup authority was borrowed by another target", target)
						}
					}
				})
			}
		}
	}
}

func TestDesktopWindowsExternalRouterEntryLayerRowsRejectSubstitution(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		source, raw := desktopExternalRouterEntryLayerInput(t, "server", layer, "aes-256-gcm+xor-whitening", "home")
		original := desktopExternalRouterLayerPolicy(t, source, raw, "")
		capture, err := original.DesktopCapture()
		if err != nil {
			t.Fatal(err)
		}
		for _, fault := range []string{"wg-key", "wg-peer", "wg-psk", "wg-service", "wg-port", "wg-mtu", "wg-bypass", "wg-final-detour", "wg-extra", "outer-key", "outer-host", "outer-port", "outer-method", "outer-type", "outer-bypass", "outer-extra", "outer-final-key", "outer-omitted"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				graph := externalTestRead(t, original.Config())
				endpoints, rows := graph["endpoints"].([]any), graph["outbounds"].([]any)
				if _, err := desktopExternalRouterEntryEndpoint(endpoints, original.capture, capture); err != nil || desktopExternalRouterServerRows(rows, original.capture, capture) != nil {
					t.Fatal("row control omitted a valid originally captured source", err)
				}
				inner, outer := externalTestFind(t, graph, externalEntryTag), externalTestFind(t, graph, predecessorNamespace("node", NativeStartLayerTag))
				peer := inner["peers"].([]any)[0].(map[string]any)
				key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
				switch fault {
				case "wg-key":
					inner["private_key"] = key
				case "wg-peer":
					peer["public_key"] = key
				case "wg-psk":
					peer["pre_shared_key"] = key
				case "wg-service":
					peer["address"] = "10.99.0.1"
				case "wg-port":
					peer["port"] = float64(51821)
				case "wg-mtu":
					inner["mtu"] = float64(1280)
				case "wg-bypass":
					delete(inner, "detour")
				case "wg-final-detour":
					inner["detour"] = multihoprelay.ExitStartLayerTag
				case "wg-extra":
					inner["bind_interface"] = "another-interface"
				case "outer-key":
					outer["password"] = key
				case "outer-host":
					outer["server"] = "203.0.113.99"
				case "outer-port":
					outer["server_port"] = float64(8390)
				case "outer-method":
					outer["method"] = "2022-blake3-chacha20-poly1305"
				case "outer-type":
					outer["type"] = "direct"
				case "outer-bypass":
					outer["detour"] = LocalTag
				case "outer-extra":
					outer["bind_interface"] = "another-interface"
				case "outer-final-key":
					outer["password"] = externalTestFind(t, graph, multihoprelay.ExitStartLayerTag)["password"]
				case "outer-omitted":
					kept := []any{}
					for _, row := range rows {
						if row.(map[string]any)["tag"] != outer["tag"] {
							kept = append(kept, row)
						}
					}
					rows = kept
				}
				if strings.HasPrefix(fault, "wg-") {
					if _, err := desktopExternalRouterEntryEndpoint(endpoints, original.capture, capture); err == nil {
						t.Fatal("candidate entry guard accepted substituted captured WG authority")
					}
				} else if desktopExternalRouterServerRows(rows, original.capture, capture) == nil {
					t.Fatal("candidate entry guard accepted substituted captured outer authority")
				}
				if _, err := original.DesktopCapture(); err != nil {
					t.Fatal("candidate-row control changed or resealed the original source", err)
				}
			})
		}
	}
}

func TestDesktopWindowsExternalRouterEntryStartupAuthorityIsImmutable(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		source, raw := desktopExternalRouterEntryLayerInput(t, "server", layer, "", "home")
		original := desktopExternalRouterLayerPolicy(t, source, raw, "")
		policy := desktopExternalPlan(t, original, desktopExternalTestSession, "windows")
		for _, field := range []string{"tag", "type", "digest", "partial", "physical-root"} {
			t.Run(layer+"/"+field, func(t *testing.T) {
				changed := *policy
				switch field {
				case "tag":
					changed.metadata.StartupEndpointTag = ExternalFinalTag
				case "type":
					changed.metadata.StartupEndpointType = "shadowsocks"
				case "digest":
					changed.metadata.StartupEndpointSHA256 = strings.Repeat("b", 64)
				case "partial":
					changed.metadata.StartupEndpointSHA256 = ""
				case "physical-root":
					changed.metadata.RootTag = externalEntryTag
				}
				// This is explicitly an immutable-source negative, not a claim
				// that the candidate-row comparator caused this rejection.
				if changed.Validate() == nil || changed.Config() != "" || changed.Metadata() != (DesktopExternalMetadata{}) {
					t.Fatal("changed startup description retained its original private seal")
				}
				if eager, err := changed.StartupSocketRequired("windows"); err == nil || eager {
					t.Fatal("changed startup description acquired early socket authority")
				}
				if policy.Validate() != nil {
					t.Fatal("immutable-source control modified the original policy")
				}
			})
		}
	}
	for _, lazy := range []bool{false, true} {
		t.Run(map[bool]string{false: "unlayered-wg", true: "ordinary-ss"}[lazy], func(t *testing.T) {
			original := desktopExternalRouterServerFixture(t, "server")
			if lazy {
				original = desktopExternalPolicyFixture(t, "shadowsocks", "always", "on", false)
			}
			policy := desktopExternalPlan(t, original, desktopExternalTestSession, "windows")
			meta := policy.Metadata()
			if meta.StartupEndpointTag != "" || meta.StartupEndpointType != "" || meta.StartupEndpointSHA256 != "" {
				t.Fatal("unlayered or ordinary source acquired a fabricated inner endpoint")
			}
			if eager, err := policy.StartupSocketRequired("windows"); err != nil || eager == lazy {
				t.Fatal("ordinary lazy transport or existing WG startup phase changed", err)
			}
		})
	}
}
