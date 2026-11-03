package mobilemultihop

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const desktopExternalTestSession = "0123456789abcdef0123456789abcdef"

func desktopExternalInputFixture(t *testing.T, protocol, entry, variant string) (map[string]any, map[string]any) {
	t.Helper()
	if protocol != "amneziawg" {
		return externalTestFixture(t, protocol, entry)
	}
	graph, selection := externalTestFixture(t, "wireguard", entry)
	if variant == "" {
		variant = "strong"
	}
	externalAmneziaReplace(t, graph, selection, false, variant)
	return graph, selection
}

func desktopExternalPolicyFixture(t *testing.T, protocol, kill, ipv6 string, lan bool) *ExternalPolicy {
	t.Helper()
	graph, selection := desktopExternalInputFixture(t, protocol, "", "")
	profile := selection["profile"].(map[string]any)
	profile["kill_switch_policy"], profile["kill_switch"] = kill, kill != "off"
	profile["ipv6_mode"], profile["home_lan_access"] = ipv6, lan
	profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1360)
	profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "custom", "https", "192.0.2.53"
	profile["dns_port"], profile["dns_server_name"], profile["dns_path"] = float64(5443), "selected.resolver.example", "/captured/query"
	return externalDesktopCompile(t, graph, selection)
}

func desktopExternalPlan(t *testing.T, original *ExternalPolicy, session, target string) *DesktopExternalPolicy {
	t.Helper()
	policy, err := NewDesktopExternalPolicy(original, session, target)
	if err != nil {
		t.Fatal("valid direct proxy lost its guarded desktop plan", err)
	}
	return policy
}

func TestDesktopExternalPolicyPreservesExactGraphAndSelectedPolicy(t *testing.T) {
	count := 0
	for _, protocol := range []string{"socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		for _, target := range []string{"linux", "windows", "darwin"} {
			for _, kill := range []string{"on-connect", "always"} {
				for _, ipv6 := range []string{"on", "off"} {
					for _, lan := range []bool{true, false} {
						t.Run(strings.Join([]string{protocol, target, kill, ipv6, map[bool]string{true: "lan", false: "no-lan"}[lan]}, "/"), func(t *testing.T) {
							original := desktopExternalPolicyFixture(t, protocol, kill, ipv6, lan)
							if protocol == "hysteria2" && target == "darwin" {
								if _, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target); err == nil {
									t.Fatal("connected UDP broadened unimplemented Darwin Hysteria2 admission")
								}
								return
							}
							before, oldMeta := original.Config(), original.Metadata()
							policy := desktopExternalPlan(t, original, desktopExternalTestSession, target)
							meta := policy.Metadata()
							capture, err := policy.Capture()
							if err != nil || policy.Validate() != nil || policy.OriginalPolicy() != original || meta.Schema != 1 || meta.SessionID != desktopExternalTestSession || meta.TargetOS != target ||
								meta.OriginalSourceSHA256 != original.SourceSHA256() || meta.OriginalConfigSHA256 != externalDigest([]byte(before)) ||
								meta.OriginalMetadataSHA256 != externalDigest([]byte(oldMeta)) || meta.OriginalCaptureSHA256 != capture.CaptureSHA256 ||
								meta.ConfigSHA256 != externalDigest([]byte(policy.Config())) || meta.ConfigSHA256 == meta.OriginalConfigSHA256 ||
								meta.SourceSHA256 == meta.OriginalSourceSHA256 || !proofID.MatchString(meta.SourceSHA256) || meta.RootTag != ExternalFinalTag ||
								meta.KillSwitchPolicy != kill || meta.IPv6Mode != ipv6 || meta.HomeLANAccess != lan ||
								meta.SOCKSUDPAssociationRequired != (protocol == "socks5") {
								t.Fatal("desktop plan lost exact original/derived ownership or reported SOCKS TCP as full UDP support", meta, err)
							}
							graph := externalTestRead(t, policy.Config())
							rows := graph["outbounds"].([]any)
							if len(rows) != 2 || meta.DerivedRootSHA256 != desktopExternalObjectDigest(rows[0]) || meta.OriginalRootSHA256 != capture.PhysicalRoots[0].ConfigSHA256 {
								t.Fatal("root identity changed or physical scope became unbounded")
							}
							physical := rows[1].(map[string]any)
							services := graph["services"].([]any)
							if len(services) != 1 || len(physical) != 4 || physical["type"] != DesktopExternalPhysicalType || physical["tag"] != DesktopExternalPhysicalTag ||
								physical["session_id"] != meta.SessionID || physical["source_sha256"] != meta.SourceSHA256 {
								t.Fatal("derived graph acquired an unrelated lower capability", physical, services)
							}
							service := services[0].(map[string]any)
							if len(service) != 4 || service["type"] != DesktopExternalNetworkType || service["tag"] != DesktopExternalNetworkTag || service["session_id"] != meta.SessionID || service["source_sha256"] != meta.SourceSHA256 {
								t.Fatal("native network owner lost its exact session/source", service)
							}
							root := rows[0].(map[string]any)
							if root["detour"] != DesktopExternalPhysicalTag {
								t.Fatal("ordinary transport bypassed the owned lower path")
							}
							if protocol == "hysteria2" && (root["type"] != "hysteria2" ||
								!reflect.DeepEqual(capture.PhysicalRoots[0].Networks, []string{"udp"}) ||
								len(capture.PhysicalRoots[0].Destinations) != 1 || capture.PhysicalRoots[0].Destinations[0].Network != "udp") {
								t.Fatal("Hysteria2 lost its one captured UDP destination")
							}
							delete(root, "detour")
							if protocol == "socks5" && (target == "linux" || target == "windows") {
								if root["type"] != DesktopExternalSOCKSType || root["session_id"] != meta.SessionID || root["source_sha256"] != meta.SourceSHA256 {
									t.Fatal("SOCKS association lost its exact derived source owner")
								}
								root["type"] = "socks"
								delete(root, "session_id")
								delete(root, "source_sha256")
							}
							graph["outbounds"] = rows[:1]
							delete(graph, "services")
							if !reflect.DeepEqual(graph, externalTestRead(t, before)) || original.Config() != before || original.Metadata() != oldMeta {
								t.Fatal("desktop derivation changed credentials, selected DNS, TLS, routes, MTU or source inputs")
							}
							count++
						})
					}
				}
			}
		}
	}
	if count != 112 {
		t.Fatal("missing complete direct proxy/device/target combinations", count)
	}
}

func TestDesktopExternalPolicyPreservesRoutedDNSBootstrapAndCopies(t *testing.T) {
	original := externalDesktopDNSFixture(t)
	policy := desktopExternalPlan(t, original, desktopExternalTestSession, "windows")
	before, err := original.DesktopCapture()
	if err != nil {
		t.Fatal(err)
	}
	capture, err := policy.Capture()
	if err != nil || !reflect.DeepEqual(capture, before) {
		t.Fatal("desktop adaptation changed the complete selected DNS/bootstrap capture", err)
	}
	old := externalTestRead(t, original.Config())
	derived := externalTestRead(t, policy.Config())
	if !reflect.DeepEqual(old["dns"], derived["dns"]) {
		t.Fatal("selected query cache/TTL/subnet or resolver transport, port and TLS identity were rewritten")
	}
	capture.PhysicalRoots[0].Networks[0] = "ip"
	capture.PhysicalRoots[0].Destinations[0].Host = "10.8.0.1"
	capture.BootstrapDNS[0].Host = "10.8.0.53"
	*capture.SelectedDNS.Resolver.DisableCache = false
	*capture.SelectedDNS.Resolver.RewriteTTL = 99
	meta := policy.Metadata()
	meta.SourceSHA256 = strings.Repeat("c", 64)
	again, err := policy.Capture()
	if err != nil || !reflect.DeepEqual(again, before) || policy.Metadata() == meta || policy.Validate() != nil {
		t.Fatal("caller mutation changed retained native planning authority")
	}
}

func TestDesktopExternalPolicyWireGuardPreservesEndpointAndSelectedPolicy(t *testing.T) {
	desktopExternalPacketPolicyPreservesEndpoint(t, "wireguard", "")
}

func TestDesktopExternalPolicyAmneziaPreservesExactParametersAndSelectedPolicy(t *testing.T) {
	for _, variant := range []string{"fast", "strong"} {
		t.Run(variant, func(t *testing.T) {
			desktopExternalPacketPolicyPreservesEndpoint(t, "amneziawg", variant)
		})
	}
}

func desktopExternalPacketPolicyPreservesEndpoint(t *testing.T, protocol, variant string) {
	t.Helper()
	kind := "wireguard"
	if protocol == "amneziawg" {
		kind = AmneziaType
	}
	for _, outboundTable := range []string{"absent", "empty"} {
		for _, kill := range []string{"on-connect", "always"} {
			for _, ipv6 := range []string{"on", "off"} {
				for _, lan := range []bool{true, false} {
					t.Run(strings.Join([]string{outboundTable, kill, ipv6, map[bool]string{true: "lan", false: "no-lan"}[lan]}, "/"), func(t *testing.T) {
						graph, selection := desktopExternalInputFixture(t, protocol, "", variant)
						if outboundTable == "absent" {
							delete(graph, "outbounds")
						}
						profile := selection["profile"].(map[string]any)
						profile["kill_switch_policy"], profile["ipv6_mode"], profile["home_lan_access"] = kill, ipv6, lan
						profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1360)
						profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "custom", "udp", "192.0.2.53"
						profile["dns_port"] = float64(5353)
						original := externalDesktopCompile(t, graph, selection)
						before, oldMeta := original.Config(), original.Metadata()
						policy := desktopExternalPlan(t, original, desktopExternalTestSession, "linux")
						capture, err := policy.Capture()
						meta := policy.Metadata()
						if err != nil || policy.Validate() != nil || policy.OriginalPolicy() != original ||
							meta.TargetOS != "linux" || meta.Protocol != protocol || meta.RootType != kind || meta.RootTag != ExternalFinalTag ||
							meta.OriginalSourceSHA256 != original.SourceSHA256() || meta.OriginalConfigSHA256 != externalDigest([]byte(before)) ||
							meta.OriginalCaptureSHA256 != capture.CaptureSHA256 || meta.ConfigSHA256 != externalDigest([]byte(policy.Config())) ||
							meta.SourceSHA256 == meta.OriginalSourceSHA256 || meta.SOCKSUDPAssociationRequired ||
							meta.KillSwitchPolicy != kill || meta.IPv6Mode != ipv6 || meta.HomeLANAccess != lan || capture.ConfiguredMTU != 1360 ||
							capture.SelectedDNS.Host != "192.0.2.53" || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Port != 5353 || capture.SelectedDNS.Physical ||
							len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Family != "endpoints" ||
							!reflect.DeepEqual(capture.PhysicalRoots[0].Networks, []string{"udp"}) || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.PhysicalRoots[0].Destinations[0].Network != "udp" {
							t.Fatal("WireGuard lost its exact endpoint, UDP peer, selected DNS or original/derived source", meta, err)
						}
						derived := externalTestRead(t, policy.Config())
						endpoints, outbounds, services := derived["endpoints"].([]any), derived["outbounds"].([]any), derived["services"].([]any)
						if len(endpoints) != 1 || len(outbounds) != 1 || len(services) != 1 ||
							meta.OriginalRootSHA256 != capture.PhysicalRoots[0].ConfigSHA256 || meta.DerivedRootSHA256 != desktopExternalObjectDigest(endpoints[0]) {
							t.Fatal("WireGuard moved out of its endpoint table or acquired another graph owner")
						}
						endpoint, physical := endpoints[0].(map[string]any), outbounds[0].(map[string]any)
						if protocol == "amneziawg" {
							parameters := profile["external"].(map[string]any)["amneziawg"].(map[string]any)["parameters"].(map[string]any)
							padding, err := strconv.Atoi(parameters["s4"].(string))
							native, nativeErr := AmneziaRuntimeConfig(externalTestJSON(t, endpoint))
							if err != nil || nativeErr != nil || len(parameters) != 11 || !reflect.DeepEqual(endpoint["amnezia"], parameters) ||
								native.TransportPadding != padding || native.MTU != 1360 {
								t.Fatal("desktop Amnezia derivation changed imported parameters, S4 overhead or selected MTU", err, nativeErr)
							}
						}
						service := services[0].(map[string]any)
						if endpoint["detour"] != DesktopExternalPhysicalTag || len(physical) != 4 || len(service) != 4 ||
							physical["type"] != DesktopExternalPhysicalType || physical["tag"] != DesktopExternalPhysicalTag ||
							service["type"] != DesktopExternalNetworkType || service["tag"] != DesktopExternalNetworkTag ||
							physical["source_sha256"] != meta.SourceSHA256 || physical["session_id"] != meta.SessionID ||
							service["source_sha256"] != meta.SourceSHA256 || service["session_id"] != meta.SessionID {
							t.Fatal("WireGuard acquired an unrelated lower capability or source owner")
						}
						delete(endpoint, "detour")
						delete(derived, "services")
						old := externalTestRead(t, before)
						if value, exists := old["outbounds"]; exists {
							derived["outbounds"] = value
						} else {
							delete(derived, "outbounds")
						}
						if !reflect.DeepEqual(derived, old) || original.Config() != before || original.Metadata() != oldMeta {
							t.Fatal("WireGuard derivation changed its private key, peer, PSK, routes, DNS, MTU or source")
						}
					})
				}
			}
		}
	}
}

func TestDesktopExternalPolicyBindsSessionTargetAndCompleteSource(t *testing.T) {
	original := desktopExternalPolicyFixture(t, "https-connect", "always", "on", true)
	base := desktopExternalPlan(t, original, desktopExternalTestSession, "windows")
	if again := desktopExternalPlan(t, original, desktopExternalTestSession, "windows"); again.Config() != base.Config() || again.Metadata() != base.Metadata() {
		t.Fatal("identical captured input did not derive identical native bytes")
	}
	changedSource, changedSelection := externalTestFixture(t, "https-connect", "")
	profile := changedSelection["profile"].(map[string]any)
	profile["kill_switch_policy"], profile["kill_switch"] = "always", true
	changed := externalDesktopCompile(t, changedSource, changedSelection)
	for label, next := range map[string]*DesktopExternalPolicy{
		"session":         desktopExternalPlan(t, original, strings.Repeat("b", 32), "windows"),
		"target":          desktopExternalPlan(t, original, desktopExternalTestSession, "linux"),
		"complete-source": desktopExternalPlan(t, changed, desktopExternalTestSession, "windows"),
	} {
		if next.Metadata().SourceSHA256 == base.Metadata().SourceSHA256 || next.Metadata().ConfigSHA256 == base.Metadata().ConfigSHA256 {
			t.Fatal("captured identity was reused across a different native plan", label)
		}
	}
}

func TestDesktopExternalPolicyRejectsSubstitutedAuthorityAndDerivedBytes(t *testing.T) {
	for label, mutate := range map[string]func(*DesktopExternalPolicy){
		"derived-config":     func(p *DesktopExternalPolicy) { p.config += " " },
		"derived-metadata":   func(p *DesktopExternalPolicy) { p.metadata.SOCKSUDPAssociationRequired = false },
		"source":             func(p *DesktopExternalPolicy) { p.metadata.SourceSHA256 = strings.Repeat("c", 64) },
		"session":            func(p *DesktopExternalPolicy) { p.metadata.SessionID = strings.Repeat("b", 32) },
		"no-seal":            func(p *DesktopExternalPolicy) { p.seal = "" },
		"no-original":        func(p *DesktopExternalPolicy) { p.original = nil },
		"original-config":    func(p *DesktopExternalPolicy) { p.original.config += " " },
		"original-metadata":  func(p *DesktopExternalPolicy) { p.original.metadata += " " },
		"original-selection": func(p *DesktopExternalPolicy) { p.original.capture.Profile["home_lan_access"] = false },
		"other-valid-original": func(p *DesktopExternalPolicy) {
			p.original = desktopExternalPolicyFixture(t, "http-connect", "always", "on", true)
		},
	} {
		t.Run(label, func(t *testing.T) {
			policy := desktopExternalPlan(t, desktopExternalPolicyFixture(t, "socks5", "always", "on", true), desktopExternalTestSession, "windows")
			mutate(policy)
			if policy.Validate() == nil || policy.Config() != "" || policy.Metadata() != (DesktopExternalMetadata{}) || policy.OriginalPolicy() != nil {
				t.Fatal("stale or fabricated native policy was accepted")
			}
			if _, err := policy.Capture(); err == nil {
				t.Fatal("stale policy retained a public authority projection")
			}
		})
	}
	for _, policy := range []*DesktopExternalPolicy{nil, {}} {
		if policy.Validate() == nil || policy.Config() != "" || policy.OriginalPolicy() != nil {
			t.Fatal("unconstructed native policy was admitted")
		}
	}
}

func TestDesktopExternalPolicyDoesNotBroadenInitialNativeScope(t *testing.T) {
	valid := desktopExternalPolicyFixture(t, "shadowsocks", "always", "on", true)
	for _, target := range []string{"", "WINDOWS", "android", "ios", "freebsd", "unknown"} {
		if _, err := NewDesktopExternalPolicy(valid, desktopExternalTestSession, target); err == nil {
			t.Fatal("non-desktop target acquired an ordinary desktop plan", target)
		}
	}
	for _, session := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32)} {
		if _, err := NewDesktopExternalPolicy(valid, session, "windows"); err == nil {
			t.Fatal("uncaptured session acquired a physical plan")
		}
	}
	for _, protocol := range []string{"wireguard", "hysteria2", "amneziawg"} {
		original := desktopExternalPolicyFixture(t, protocol, "always", "on", true)
		for _, target := range []string{"windows", "darwin"} {
			if protocol == "hysteria2" && target == "windows" {
				continue // This exact direct UDP owner is independently exercised above.
			}
			if _, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target); err == nil {
				t.Fatal("unintegrated outer transport acquired a claimed native physical implementation", protocol, target)
			}
		}
	}
	for _, protocol := range []string{"socks5", "hysteria2"} {
		if _, err := NewDesktopExternalPolicy(desktopExternalPolicyFixture(t, protocol, "off", "on", true), desktopExternalTestSession, "linux"); err == nil {
			t.Fatal("Off acquired a strict Linux baseline without an explicit captured policy", protocol)
		}
	}
	for _, entry := range []string{"router-wg", "http-connect", "socks5", "shadowsocks"} {
		graph, selection := externalTestFixture(t, "shadowsocks", entry)
		selection["profile"].(map[string]any)["kill_switch_policy"] = "always"
		original := externalDesktopCompile(t, graph, selection)
		if _, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, "windows"); err == nil {
			t.Fatal("predecessor or private node was silently admitted as direct", entry)
		}
	}
	if _, err := NewDesktopExternalPolicy(desktopExternalPolicyFixture(t, "socks5", "off", "on", true), desktopExternalTestSession, "windows"); err == nil {
		t.Fatal("Off acquired a strict native baseline without an explicit captured policy")
	}
	for _, original := range []*ExternalPolicy{nil, {}, {config: valid.Config(), metadata: valid.Metadata(), source: valid.SourceSHA256()}} {
		if _, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, "windows"); err == nil {
			t.Fatal("public config/metadata strings manufactured original constructor authority")
		}
	}
}

func TestDesktopExternalPolicyHysteria2KeepsUnsupportedSelectionGuards(t *testing.T) {
	desktopExternalPolicyKeepsUnsupportedSelectionGuards(t, "hysteria2")
}

func TestDesktopExternalPolicyWireGuardKeepsUnsupportedSelectionGuards(t *testing.T) {
	desktopExternalPolicyKeepsUnsupportedSelectionGuards(t, "wireguard")
}

func TestDesktopExternalPolicyAmneziaKeepsUnsupportedSelectionGuards(t *testing.T) {
	desktopExternalPolicyKeepsUnsupportedSelectionGuards(t, "amneziawg")
}

func desktopExternalPolicyKeepsUnsupportedSelectionGuards(t *testing.T, protocol string) {
	t.Helper()
	reject := func(t *testing.T, original *ExternalPolicy) {
		t.Helper()
		if _, err := original.DesktopCapture(); err != nil {
			t.Fatal("negative case must retain a valid complete ordinary policy", err)
		}
		before := original.Config()
		targets := []string{"linux"}
		if protocol == "hysteria2" {
			targets = append(targets, "windows")
		}
		for _, target := range targets {
			if derived, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target); err == nil || derived != nil || original.Config() != before {
				t.Fatal("unsupported selection acquired or changed a physical owner", protocol, target)
			}
		}
	}
	t.Run("off", func(t *testing.T) {
		reject(t, desktopExternalPolicyFixture(t, protocol, "off", "on", true))
	})
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run("start-layer/"+layer, func(t *testing.T) {
			var source, capture string
			if protocol == "wireguard" || protocol == "amneziawg" {
				source, capture = externalExecutionPacketFixture(t, protocol, "local", layer)
				graph, selected := externalTestRead(t, source), externalTestRead(t, capture)
				final := externalTestFind(t, graph, ExternalFinalTag)
				delete(final, "detour")
				graph["endpoints"] = []any{final}
				delete(selected, "entry")
				delete(selected, "entry_tag")
				profile := selected["profile"].(map[string]any)
				profile["multihop_enabled"] = false
				delete(profile["external"].(map[string]any), "response_probe")
				delete(profile["external"].(map[string]any), "server_peer")
				source, capture = externalTestJSON(t, graph), externalTestJSON(t, selected)
			} else {
				source, capture = externalDirectLayerFixture(t, protocol, layer)
			}
			selected := externalTestRead(t, capture)
			selected["profile"].(map[string]any)["kill_switch_policy"] = "always"
			original, err := NewExternalPolicy(source, externalTestJSON(t, selected))
			if err != nil {
				t.Fatal(err)
			}
			reject(t, original)
		})
	}
	for _, entry := range []string{"router-wg", "socks5", "shadowsocks", "hysteria2"} {
		t.Run("predecessor/"+entry, func(t *testing.T) {
			graph, selected := desktopExternalInputFixture(t, protocol, entry, "")
			selected["profile"].(map[string]any)["kill_switch_policy"] = "always"
			reject(t, externalDesktopCompile(t, graph, selected))
		})
	}
	for _, execution := range []string{"server", "auto"} {
		t.Run("execution/"+execution, func(t *testing.T) {
			var source, capture string
			if protocol == "wireguard" || protocol == "amneziawg" {
				source, capture = externalExecutionPacketFixture(t, protocol, execution, "")
			} else {
				source, capture = externalExecutionProtocolFixture(t, protocol, execution, "")
			}
			selected := externalTestRead(t, capture)
			selected["profile"].(map[string]any)["kill_switch_policy"] = "always"
			prepared, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, selected), "")
			if err != nil {
				t.Fatal(err)
			}
			original, err := NewExternalPolicy(source, prepared)
			if err != nil {
				t.Fatal(err)
			}
			owned, err := original.DesktopCapture()
			if err != nil || owned.Execution != execution {
				t.Fatal("negative selection lost its captured execution", err)
			}
			reject(t, original)
		})
	}
}

// The native SOCKS authentication frame has one-byte lengths. Reject before
// deriving either admitted host; never truncate or change captured credentials.
func TestDesktopExternalSOCKSAuthenticationBoundsPreserveExactOriginal(t *testing.T) {
	for _, target := range []string{"linux", "windows"} {
		for _, field := range []string{"username", "password"} {
			for _, size := range []int{255, 256} {
				t.Run(target+"/"+field+"/"+strconv.Itoa(size), func(t *testing.T) {
					graph, selection := desktopExternalInputFixture(t, "socks5", "", "")
					profile := selection["profile"].(map[string]any)
					profile["kill_switch_policy"], profile["kill_switch"] = "always", true
					graph["outbounds"].([]any)[0].(map[string]any)[field] = strings.Repeat("a", size)
					selection["profile"].(map[string]any)["external"].(map[string]any)["socks5"].(map[string]any)[field] = strings.Repeat("a", size)
					original := externalDesktopCompile(t, graph, selection)
					before := original.Config()
					derived, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target)
					if (err == nil) != (size == 255) || original.Config() != before {
						t.Fatal("native authentication changed or accepted an unrepresentable original credential", err)
					}
					if derived != nil && derived.Validate() != nil {
						t.Fatal("valid exact authentication lost its retained seal")
					}
				})
			}
		}
	}
}
