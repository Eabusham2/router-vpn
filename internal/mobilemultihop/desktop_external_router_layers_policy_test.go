package mobilemultihop

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

// Build a fresh paired capture from the original public entry and private final
// profiles. No already-compiled policy is edited or resealed by this fixture.
func desktopExternalRouterLayerInput(t *testing.T, execution, layer, method, dns string) (string, string) {
	t.Helper()
	_, raw := externalExecutionFixture(t, execution)
	graph, _ := externalTestFixture(t, "shadowsocks", "")
	capture := externalTestRead(t, raw)
	predecessor, entry := externalPredecessorFixture(t, "wg", "", false)
	entry["id"] = "saved-entry"
	capture["entry"], capture["entry_tag"], capture["predecessor_config"] = entry, externalEntryTag, predecessor
	profile := capture["profile"].(map[string]any)
	profile["multihop_entry_mode"], profile["kill_switch_policy"] = "wg", "always"
	profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1360)
	profile["dns_mode"] = dns
	if dns == "home" {
		profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "udp", "10.77.0.1", float64(53)
	} else {
		profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "tcp", "203.0.113.53", float64(5353)
	}
	ext := profile["external"].(map[string]any)
	size := 32
	if method == desktopSS2022Methods[0] {
		size = 16
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("f", size)))
	final := externalTestFind(t, graph, ExternalFinalTag)
	final["method"], final["password"] = method, key
	imported := ext["shadowsocks"].(map[string]any)
	imported["method"], imported["password"] = method, key
	if layer != "" {
		externalTestAddLayer(profile, layer, imported["server"].(string), "10.93.0.1", "l")
	}
	return externalTestJSON(t, graph), externalTestJSON(t, capture)
}

func desktopExternalRouterLayerPolicy(t *testing.T, source, capture, restored string) *ExternalPolicy {
	t.Helper()
	prepared, err := PrepareExternalPairedExecutionCapture(source, capture, restored)
	if err != nil {
		t.Fatal("original paired capture did not compile", err)
	}
	policy, err := NewExternalPolicy(source, prepared)
	if err != nil {
		t.Fatal("original paired policy did not compile", err)
	}
	return policy
}

func TestDesktopWindowsExternalRouterFinalLayersPolicy(t *testing.T) {
	for _, execution := range []string{"local", "server", "auto"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, method := range desktopSS2022Methods {
				for _, dns := range []string{"home", "custom"} {
					t.Run(strings.Join([]string{execution, layer, method, dns}, "/"), func(t *testing.T) {
						source, capture := desktopExternalRouterLayerInput(t, execution, layer, method, dns)
						original := desktopExternalRouterLayerPolicy(t, source, capture, "")
						policy, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "windows")
						if err != nil {
							t.Fatal("captured independent final Start Layer refused", err)
						}
						before, after := externalTestRead(t, original.Config()), externalTestRead(t, policy.Config())
						for _, tag := range []string{LocalTag, ServerTag, ExternalFinalTag, multihoprelay.ExitStartLayerTag} {
							if !reflect.DeepEqual(externalTestFind(t, before, tag), externalTestFind(t, after, tag)) {
								t.Fatal("Windows adoption replaced an original candidate or layer", tag)
							}
						}
						if !reflect.DeepEqual(before["dns"], after["dns"]) || !reflect.DeepEqual(before["route"], after["route"]) || !reflect.DeepEqual(before["inbounds"], after["inbounds"]) {
							t.Fatal("independent final layer replaced captured DNS or device policy")
						}
						root := externalTestFind(t, after, externalEntryTag)
						if root["detour"] != DesktopExternalPhysicalTag || policy.Metadata().RootType != "wireguard" {
							t.Fatal("final layer replaced the entry physical owner")
						}
						delete(root, "detour")
						if !reflect.DeepEqual(root, externalTestFind(t, before, externalEntryTag)) {
							t.Fatal("final layer changed captured entry credentials")
						}
						actual, err := policy.Capture()
						if err != nil || actual.StartLayer != layer || actual.EntryStartLayer != "" || actual.Execution != execution || actual.ConfiguredMTU != 1360 || actual.SelectedDNS.Physical || len(actual.PhysicalRoots) != 1 {
							t.Fatal("independent layer or selected policy identity changed", err)
						}
						if original.capture.Execution.Request.ExitStartLayer != layer || policy.OriginalPolicy() != original {
							t.Fatal("lease proposal lost its original final layer")
						}
					})
				}
			}
		}
	}
}

func TestDesktopWindowsExternalRouterFinalLayersRestore(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		source, capture := desktopExternalRouterLayerInput(t, "auto", layer, desktopSS2022Methods[1], "home")
		original := desktopExternalRouterLayerPolicy(t, source, capture, "")
		for _, winner := range []string{"local", "server"} {
			t.Run(layer+"/"+winner, func(t *testing.T) {
				restored := desktopExternalRouterLayerPolicy(t, source, capture, winner)
				policy, err := NewDesktopExternalPolicy(restored, strings.Repeat("b", 32), "windows")
				if err != nil {
					t.Fatal("restored independent final layer refused", err)
				}
				plan, before := restored.capture.Execution, original.capture.Execution
				if restored.capture.Profile["multihop_execution"] != "auto" || plan.Selection != winner || plan.Request.ExitStartLayer != layer ||
					plan.Request.SessionID == before.Request.SessionID || plan.Request.Password == before.Request.Password {
					t.Fatal("restoration replaced saved Compare, reran selection or reused its original lease")
				}
				if !reflect.DeepEqual(restored.capture.Profile, original.capture.Profile) || !reflect.DeepEqual(restored.capture.Entry, original.capture.Entry) || restored.capture.PredecessorConfig != original.capture.PredecessorConfig {
					t.Fatal("restoration changed the original node or layer source")
				}
				graph, prior := externalTestRead(t, policy.Config()), externalTestRead(t, original.Config())
				selected := LocalTag
				if winner == "server" {
					selected = ServerTag
				}
				if externalTestFind(t, graph, ExternalFinalTag)["default"] != selected {
					t.Fatal("restored winner was not fixed before runtime proof")
				}
				for _, tag := range []string{LocalTag, multihoprelay.ExitStartLayerTag} {
					if !reflect.DeepEqual(externalTestFind(t, graph, tag), externalTestFind(t, prior, tag)) {
						t.Fatal("restoration changed captured inner or outer final", tag)
					}
				}
				if !reflect.DeepEqual(graph["dns"], prior["dns"]) || !reflect.DeepEqual(graph["inbounds"], prior["inbounds"]) {
					t.Fatal("restoration replaced captured DNS or MTU")
				}
				for _, target := range []string{"linux", "darwin"} {
					if _, err := NewDesktopExternalPolicy(restored, strings.Repeat("c", 32), target); err == nil {
						t.Fatal("Windows paired final layer broadened another host", target)
					}
				}
			})
		}
	}
}

// These negatives deliberately retain a valid original policy and mutate only
// the candidate passed to the shipping row guard. The immutable-source seal is
// not the rejection witness, and no untrusted policy is resealed for the test.
func TestDesktopWindowsExternalRouterFinalLayerRowsRejectSubstitution(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		source, capture := desktopExternalRouterLayerInput(t, "auto", layer, desktopSS2022Methods[1], "custom")
		original := desktopExternalRouterLayerPolicy(t, source, capture, "")
		sealed, err := original.DesktopCapture()
		if err != nil {
			t.Fatal(err)
		}
		baseline := externalTestRead(t, original.Config())["outbounds"].([]any)
		if err := desktopExternalRouterServerRows(baseline, original.capture, sealed); err != nil {
			t.Fatal("row control did not begin with a valid original", err)
		}
		for _, fault := range []string{"inner-key", "inner-cipher", "inner-private-host", "inner-port", "inner-bypass", "inner-extra", "outer-key", "outer-server", "outer-port", "outer-type", "outer-bypass", "outer-extra", "cross-layer", "duplicate", "omitted-layer", "foreign-row", "relay-key", "selector"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				graph := externalTestRead(t, original.Config())
				inner, outer := externalTestFind(t, graph, LocalTag), externalTestFind(t, graph, multihoprelay.ExitStartLayerTag)
				rows := graph["outbounds"].([]any)
				switch fault {
				case "inner-key":
					inner["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				case "inner-cipher":
					inner["method"] = desktopSS2022Methods[2]
				case "inner-private-host":
					inner["server"] = "10.94.0.1"
				case "inner-port":
					inner["server_port"] = float64(9443)
				case "inner-bypass":
					inner["detour"] = externalEntryTag
				case "inner-extra":
					inner["udp_fragment"] = true
				case "outer-key":
					outer["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				case "outer-server":
					outer["server"] = "203.0.113.99"
				case "outer-port":
					outer["server_port"] = float64(9443)
				case "outer-type":
					outer["type"] = "shadowsocks"
					if layer == "aes-256-gcm" {
						outer["type"] = "routervpn-aes-xor"
					}
				case "outer-bypass":
					delete(outer, "detour")
				case "outer-extra":
					outer["network"] = "tcp"
				case "cross-layer":
					inner["detour"] = ExternalEntryStartLayerTag
				case "duplicate":
					rows[0] = rows[1]
				case "omitted-layer":
					rows = rows[:0]
					for _, row := range graph["outbounds"].([]any) {
						if row.(map[string]any)["tag"] != multihoprelay.ExitStartLayerTag {
							rows = append(rows, row)
						}
					}
				case "foreign-row":
					rows = append(rows, map[string]any{"type": "direct", "tag": "foreign"})
				case "relay-key":
					externalTestFind(t, graph, ServerTag)["password"] = "foreign-listener"
				case "selector":
					externalTestFind(t, graph, ExternalFinalTag)["default"] = ServerTag
				}
				if err := desktopExternalRouterServerRows(rows, original.capture, sealed); err == nil {
					t.Fatal("candidate row guard accepted substituted captured final authority")
				}
				if _, err := original.DesktopCapture(); err != nil {
					t.Fatal("candidate rejection mutated the sealed original", err)
				}
			})
		}
	}
}

func TestDesktopWindowsExternalRouterFinalLayersKeepImmutableSource(t *testing.T) {
	for _, fault := range []string{"local-key", "local-bypass", "outer-key", "outer-cipher", "outer-bypass", "selector", "entry-key", "selected-dns", "saved-layer"} {
		t.Run(fault, func(t *testing.T) {
			source, capture := desktopExternalRouterLayerInput(t, "server", "aes-256-gcm+xor-whitening", desktopSS2022Methods[1], "home")
			original := desktopExternalRouterLayerPolicy(t, source, capture, "")
			graph := externalTestRead(t, original.Config())
			switch fault {
			case "local-key":
				externalTestFind(t, graph, LocalTag)["password"] = "foreign-key"
			case "local-bypass":
				externalTestFind(t, graph, LocalTag)["detour"] = externalEntryTag
			case "outer-key":
				externalTestFind(t, graph, multihoprelay.ExitStartLayerTag)["password"] = "foreign-key"
			case "outer-cipher":
				externalTestFind(t, graph, multihoprelay.ExitStartLayerTag)["method"] = desktopSS2022Methods[2]
			case "outer-bypass":
				delete(externalTestFind(t, graph, multihoprelay.ExitStartLayerTag), "detour")
			case "selector":
				externalTestFind(t, graph, ExternalFinalTag)["default"] = LocalTag
			case "entry-key":
				externalTestFind(t, graph, externalEntryTag)["private_key"] = "foreign-key"
			case "selected-dns":
				graph["dns"].(map[string]any)["final"] = "foreign"
			case "saved-layer":
				original.capture.Profile["start_layer"] = "off"
			}
			original.config = externalTestJSON(t, graph)
			if _, err := original.DesktopCapture(); err == nil {
				t.Fatal("modified immutable original retained its source seal")
			}
			if _, err := NewDesktopExternalPolicy(original, strings.Repeat("d", 32), "windows"); err == nil {
				t.Fatal("modified immutable source acquired Windows adaptation")
			}
		})
	}
}
