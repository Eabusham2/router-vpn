package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

const desktopNodeTestSession = "fedcba9876543210fedcba9876543210"

func desktopNodePlan(t *testing.T, original *NodeProfile, session, target string) *DesktopNodePolicy {
	t.Helper()
	policy, err := NewDesktopNodePolicy(original, session, target)
	if err != nil {
		t.Fatal("complete Router profile lost its captured desktop adaptation", err)
	}
	return policy
}

func desktopNodeObject(t *testing.T, graph map[string]any, family, tag string) map[string]any {
	t.Helper()
	var result map[string]any
	rows, _ := graph[family].([]any)
	for _, raw := range rows {
		value := raw.(map[string]any)
		if value["tag"] == tag {
			if result != nil {
				t.Fatal("desktop fixture contains an ambiguous native owner")
			}
			result = value
		}
	}
	if result == nil {
		t.Fatal("desktop fixture lost its captured native object", family, tag)
	}
	return result
}

func assertDesktopNodeExactDerivation(t *testing.T, policy *DesktopNodePolicy) {
	t.Helper()
	original := policy.OriginalProfile()
	if original == nil || policy.Validate() != nil {
		t.Fatal("desktop policy lost original constructor authority")
	}
	before := startObject(t, original.Config())
	derived := startObject(t, policy.Config())
	meta := policy.Metadata()
	capture, err := policy.Capture()
	if err != nil || len(meta.Roots) != len(capture.PhysicalRoots) {
		t.Fatal("desktop root identities are incomplete", err)
	}
	for index, root := range capture.PhysicalRoots {
		old := desktopNodeObject(t, before, root.Family, root.Tag)
		changed := desktopNodeObject(t, derived, root.Family, root.Tag)
		binding := meta.Roots[index]
		if changed["detour"] != DesktopNodePhysicalTag || binding.Family != root.Family || binding.Tag != root.Tag || binding.Type != root.Type ||
			binding.OriginalSHA256 != root.ConfigSHA256 || binding.OriginalSHA256 != desktopExternalObjectDigest(old) ||
			binding.DerivedSHA256 != desktopExternalObjectDigest(changed) {
			t.Fatal("derived lower transport lost its exact original object identity")
		}
		if value, existed := old["detour"]; existed {
			changed["detour"] = value
		} else {
			delete(changed, "detour")
		}
		if !reflect.DeepEqual(changed, old) {
			t.Fatal("desktop adaptation changed transport credentials, endpoint or native protocol")
		}
	}
	oldTUN := desktopNodeObject(t, before, "inbounds", capture.TUNTag)
	tun := desktopNodeObject(t, derived, "inbounds", capture.TUNTag)
	if meta.OriginalTUNSHA256 != desktopExternalObjectDigest(oldTUN) || meta.DerivedTUNSHA256 != desktopExternalObjectDigest(tun) {
		t.Fatal("desktop adaptation lost original or actual TUN identity")
	}
	if meta.TargetOS == "darwin" {
		if _, exists := tun["interface_name"]; exists {
			t.Fatal("Darwin inherited a caller-selected desktop interface name")
		}
	} else if tun["interface_name"] != "router-vpn" {
		t.Fatal("desktop interface name escaped sealed adaptation")
	}
	if value, existed := oldTUN["interface_name"]; existed {
		tun["interface_name"] = value
	} else {
		delete(tun, "interface_name")
	}
	if !reflect.DeepEqual(tun, oldTUN) {
		t.Fatal("desktop interface naming changed MTU, addresses or device routing")
	}
	for _, pair := range []struct{ family, tag, kind string }{
		{"outbounds", DesktopNodePhysicalTag, DesktopNodePhysicalType},
		{"services", DesktopNodeNetworkTag, DesktopNodeNetworkType},
	} {
		rows := derived[pair.family].([]any)
		owner := rows[len(rows)-1].(map[string]any)
		if len(owner) != 4 || owner["tag"] != pair.tag || owner["type"] != pair.kind ||
			owner["session_id"] != meta.SessionID || owner["source_sha256"] != meta.SourceSHA256 {
			t.Fatal("desktop graph gained another native capability")
		}
		if _, existed := before[pair.family]; existed {
			derived[pair.family] = rows[:len(rows)-1]
		} else {
			if len(rows) != 1 {
				t.Fatal("desktop graph invented additional native objects")
			}
			delete(derived, pair.family)
		}
	}
	oldDNS := before["dns"].(map[string]any)
	newDNS := derived["dns"].(map[string]any)
	for _, bootstrap := range capture.BootstrapDNS {
		if !bootstrap.Physical {
			continue
		}
		var old, changed map[string]any
		for _, raw := range oldDNS["servers"].([]any) {
			server := raw.(map[string]any)
			if server["tag"] == bootstrap.Tag {
				old = server
			}
		}
		for _, raw := range newDNS["servers"].([]any) {
			server := raw.(map[string]any)
			if server["tag"] == bootstrap.Tag {
				changed = server
			}
		}
		if old == nil || changed == nil || changed["detour"] != DesktopNodePhysicalTag || desktopExternalObjectDigest(old) != bootstrap.ConfigSHA256 {
			t.Fatal("desktop bootstrap lost its exact captured resolver")
		}
		if value, existed := old["detour"]; existed {
			changed["detour"] = value
		} else {
			delete(changed, "detour")
		}
	}
	if !reflect.DeepEqual(derived, before) {
		t.Fatal("desktop derivation changed selected DNS, proof owner, MTU, padding, route or original graph")
	}
}

func TestDesktopNodePolicyPreservesEveryModeLayerAndDesktop(t *testing.T) {
	count := 0
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, target := range []string{"windows", "linux", "darwin"} {
				t.Run(mode+"/"+layer+"/"+target, func(t *testing.T) {
					original := desktopNodeFixture(t, mode, layer)
					before, oldMeta := original.Config(), original.Metadata()
					policy := desktopNodePlan(t, original, desktopNodeTestSession, target)
					meta := policy.Metadata()
					capture, err := policy.Capture()
					if err != nil || meta.Schema != 1 || meta.SessionID != desktopNodeTestSession || meta.TargetOS != target ||
						meta.Mode != mode || meta.StartLayer != layer || meta.ProfileID != capture.ProfileID || meta.NodeID != capture.NodeID ||
						meta.FinalTag != capture.FinalTag || meta.TUNTag != capture.TUNTag ||
						meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "on" || meta.HomeLANAccess ||
						meta.OriginalSourceSHA256 != original.SourceSHA256() || meta.OriginalConfigSHA256 != externalDigest([]byte(before)) ||
						meta.OriginalMetadataSHA256 != externalDigest([]byte(oldMeta)) || meta.OriginalCaptureSHA256 != capture.CaptureSHA256 ||
						meta.ConfigSHA256 != externalDigest([]byte(policy.Config())) || meta.ConfigSHA256 == meta.OriginalConfigSHA256 ||
						!proofID.MatchString(meta.SourceSHA256) || meta.SourceSHA256 == meta.OriginalSourceSHA256 {
						t.Fatal("desktop Router adaptation lost original, target or session identity", err)
					}
					assertDesktopNodeExactDerivation(t, policy)
					if original.Config() != before || original.Metadata() != oldMeta {
						t.Fatal("desktop adapter changed original compiler output")
					}
					count++
				})
			}
		}
	}
	if count != 171 {
		t.Fatal("missing Router mode, Start Layer or desktop adaptation", count)
	}
}

func TestDesktopNodePolicyRetainsSelectedDNSPaddingAndCopies(t *testing.T) {
	original := desktopNodeDNSFixture(t)
	policy := desktopNodePlan(t, original, desktopNodeTestSession, "windows")
	assertDesktopNodeExactDerivation(t, policy)
	old := startObject(t, original.Config())
	derived := startObject(t, policy.Config())
	if !reflect.DeepEqual(old["dns"], derived["dns"]) || len(derived["services"].([]any)) != len(old["services"].([]any))+1 ||
		!reflect.DeepEqual(derived["services"].([]any)[0], old["services"].([]any)[0]) {
		t.Fatal("routed DNS/bootstrap or captured padding owner was changed")
	}
	before := policy.Metadata()
	copy := policy.Metadata()
	copy.Roots[0].Type = "direct"
	copy.ConfigSHA256 = strings.Repeat("f", 64)
	if policy.Validate() != nil || !reflect.DeepEqual(policy.Metadata(), before) {
		t.Fatal("caller metadata mutation replaced retained desktop authority")
	}
	capture, err := policy.Capture()
	if err != nil {
		t.Fatal(err)
	}
	*capture.SelectedDNS.Resolver.RewriteTTL = 999
	capture.PhysicalRoots[0].Destinations[0].Port = 1
	again, err := policy.Capture()
	if err != nil || *again.SelectedDNS.Resolver.RewriteTTL != 17 || again.PhysicalRoots[0].Destinations[0].Port == 1 {
		t.Fatal("returned capture aliases a retained native plan", err)
	}
}

func TestDesktopNodePolicyBindsSessionTargetAndExactPrivateInputs(t *testing.T) {
	original := desktopNodeFixture(t, "wg", "")
	base := desktopNodePlan(t, original, desktopNodeTestSession, "windows")
	again := desktopNodePlan(t, original, desktopNodeTestSession, "windows")
	if again.Config() != base.Config() || !reflect.DeepEqual(again.Metadata(), base.Metadata()) {
		t.Fatal("identical source produced different desktop bytes")
	}
	inputs := original.inputs
	inputs.ProfileJSON = strings.Replace(inputs.ProfileJSON, "captured-secret-token", "different-private-token", 1)
	changed, err := NewNodeProfile(inputs.Mode, inputs.Files, inputs.ProfileJSON, inputs.Start, inputs.DNSBootstrap)
	if err != nil || changed.Config() != original.Config() {
		t.Fatal("private identity fixture unexpectedly changed the native graph", err)
	}
	for label, policy := range map[string]*DesktopNodePolicy{
		"session":        desktopNodePlan(t, original, strings.Repeat("b", 32), "windows"),
		"target":         desktopNodePlan(t, original, desktopNodeTestSession, "linux"),
		"private-source": desktopNodePlan(t, changed, desktopNodeTestSession, "windows"),
	} {
		if policy.Metadata().SourceSHA256 == base.Metadata().SourceSHA256 || policy.Metadata().ConfigSHA256 == base.Metadata().ConfigSHA256 {
			t.Fatal("desktop identity was reused for another source, session or platform", label)
		}
	}
	launch, err := original.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := ParseNodeLaunchInput(launch)
	if err != nil {
		t.Fatal(err)
	}
	child := desktopNodePlan(t, rebuilt, desktopNodeTestSession, "windows")
	if child.Config() != base.Config() || !reflect.DeepEqual(child.Metadata(), base.Metadata()) {
		t.Fatal("independent native-child recompile did not reproduce the original and derived identities")
	}
}

func TestDesktopNodePolicyRejectsReplacedSourceAndDerivedAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*DesktopNodePolicy){
		"config": func(p *DesktopNodePolicy) { p.config += " " }, "seal": func(p *DesktopNodePolicy) { p.seal = "" },
		"session":              func(p *DesktopNodePolicy) { p.metadata.SessionID = strings.Repeat("b", 32) },
		"target":               func(p *DesktopNodePolicy) { p.metadata.TargetOS = "linux" },
		"root":                 func(p *DesktopNodePolicy) { p.metadata.Roots[0].OriginalSHA256 = strings.Repeat("a", 64) },
		"tun":                  func(p *DesktopNodePolicy) { p.metadata.DerivedTUNSHA256 = strings.Repeat("c", 64) },
		"policy":               func(p *DesktopNodePolicy) { p.metadata.KillSwitchPolicy = "off" },
		"no-original":          func(p *DesktopNodePolicy) { p.original = nil },
		"original-config":      func(p *DesktopNodePolicy) { p.original.config += " " },
		"original-profile":     func(p *DesktopNodePolicy) { p.original.profile["api_token"] = "another-owner" },
		"original-inputs":      func(p *DesktopNodePolicy) { p.original.inputs.Files += " " },
		"replacement-original": func(p *DesktopNodePolicy) { p.original = desktopNodeFixture(t, "shadowsocks", "") },
	} {
		t.Run(name, func(t *testing.T) {
			policy := desktopNodePlan(t, desktopNodeFixture(t, "wg", ""), desktopNodeTestSession, "windows")
			mutate(policy)
			if policy.Validate() == nil || policy.Config() != "" || policy.OriginalProfile() != nil || !reflect.DeepEqual(policy.Metadata(), DesktopNodeMetadata{}) {
				t.Fatal("mutated native desktop plan retained authority")
			}
			if _, err := policy.Capture(); err == nil {
				t.Fatal("mutated desktop plan returned an admissible capture")
			}
		})
	}
	original := desktopNodeFixture(t, "wg", "")
	for _, pair := range [][2]string{{"", "windows"}, {strings.Repeat("A", 32), "windows"}, {desktopNodeTestSession, "WINDOWS"}, {desktopNodeTestSession, "android"}} {
		if _, err := NewDesktopNodePolicy(original, pair[0], pair[1]); err == nil {
			t.Fatal("desktop node constructor admitted an aliased session or target")
		}
	}
	if _, err := NewDesktopNodePolicy(nil, desktopNodeTestSession, "windows"); err == nil {
		t.Fatal("desktop adapter invented original source authority")
	}
	for _, policy := range []*DesktopNodePolicy{nil, {original: original, config: original.Config()}} {
		if policy.Validate() == nil || policy.Config() != "" || policy.OriginalProfile() != nil {
			t.Fatal("copied graph or nil plan gained native authority")
		}
	}
}
