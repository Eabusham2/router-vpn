package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

const desktopExternalTestSession = "0123456789abcdef0123456789abcdef"

func desktopExternalPolicyFixture(t *testing.T, protocol, kill, ipv6 string, lan bool) *ExternalPolicy {
	t.Helper()
	graph, selection := externalTestFixture(t, protocol, "")
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
	for _, protocol := range []string{"socks5", "http-connect", "https-connect", "shadowsocks"} {
		for _, target := range []string{"linux", "windows", "darwin"} {
			for _, kill := range []string{"on-connect", "always"} {
				for _, ipv6 := range []string{"on", "off"} {
					for _, lan := range []bool{true, false} {
						t.Run(strings.Join([]string{protocol, target, kill, ipv6, map[bool]string{true: "lan", false: "no-lan"}[lan]}, "/"), func(t *testing.T) {
							original := desktopExternalPolicyFixture(t, protocol, kill, ipv6, lan)
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
							delete(root, "detour")
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
	if count != 96 {
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
	for _, protocol := range []string{"wireguard", "hysteria2"} {
		original := desktopExternalPolicyFixture(t, protocol, "always", "on", true)
		if _, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, "windows"); err == nil {
			t.Fatal("unintegrated outer transport acquired a claimed native physical implementation", protocol)
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
