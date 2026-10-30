package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func desktopNodeMTUOriginal(t *testing.T, mode, policy string, fixed int, jumbo bool, ipv6 string) *NodeProfile {
	t.Helper()
	files, profile, start := nodeProfileFixture(t, mode, "")
	profile["kill_switch_policy"], profile["kill_switch"] = "always", true
	profile["mtu_policy"], profile["manual_mtu"] = policy, float64(fixed)
	profile["jumbo_tun"], profile["ipv6_mode"] = jumbo, ipv6
	// Saved history is deliberately unrelated to the live value requested by
	// the caller. Neither constructor may silently adopt it as a fresh result.
	profile["effective_mtu"] = float64(1480)
	original, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal("complete MTU source did not compile", err)
	}
	return original
}

func desktopNodeMTUPolicy(t *testing.T, original *NodeProfile, target string, mtu int) *DesktopNodePolicy {
	t.Helper()
	policy, err := NewDesktopNodePolicyWithMTU(original, desktopNodeTestSession, target, mtu)
	if err != nil {
		t.Fatal("captured live TUN MTU was rejected", err)
	}
	return policy
}

func assertDesktopNodeRestoredMTU(t *testing.T, original *NodeProfile, target string, mtu int) *DesktopNodePolicy {
	t.Helper()
	config, metadata := original.Config(), original.Metadata()
	input, err := original.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	capture, err := original.DesktopCapture()
	if err != nil {
		t.Fatal(err)
	}
	normal := desktopNodePlan(t, original, desktopNodeTestSession, target)
	restored := desktopNodeMTUPolicy(t, original, target, mtu)
	meta, normalMeta := restored.Metadata(), normal.Metadata()
	if restored.Validate() != nil || restored.OriginalProfile() != original || meta.RestoredMTU != mtu ||
		meta.OriginalSourceSHA256 != normalMeta.OriginalSourceSHA256 || meta.OriginalConfigSHA256 != normalMeta.OriginalConfigSHA256 ||
		meta.OriginalMetadataSHA256 != normalMeta.OriginalMetadataSHA256 || meta.OriginalCaptureSHA256 != normalMeta.OriginalCaptureSHA256 ||
		meta.OriginalTUNSHA256 != normalMeta.OriginalTUNSHA256 || meta.SourceSHA256 == normalMeta.SourceSHA256 ||
		meta.ConfigSHA256 == normalMeta.ConfigSHA256 || meta.ConfigSHA256 != externalDigest([]byte(restored.Config())) {
		t.Fatal("restored MTU lost its explicit source identity or original capture")
	}
	old := startObject(t, normal.Config())
	actual := startObject(t, restored.Config())
	tun := desktopNodeObject(t, actual, "inbounds", capture.TUNTag)
	if tun["mtu"] != float64(mtu) || meta.DerivedTUNSHA256 != desktopExternalObjectDigest(tun) ||
		(mtu == capture.ConfiguredMTU) != (meta.DerivedTUNSHA256 == normalMeta.DerivedTUNSHA256) {
		t.Fatal("restored MTU is not the exact derived TUN value")
	}
	// Undo only the authorized runtime MTU and the source identity carried by
	// the two native owner objects. Every other graph byte must retain its
	// exact DNS, endpoint MTU/keys, transport, routes, addresses and padding.
	tun["mtu"] = float64(capture.ConfiguredMTU)
	for _, pair := range [][2]string{{"outbounds", DesktopNodePhysicalTag}, {"services", DesktopNodeNetworkTag}} {
		owner := desktopNodeObject(t, actual, pair[0], pair[1])
		if owner["source_sha256"] != meta.SourceSHA256 {
			t.Fatal("restored native owner has another source identity")
		}
		owner["source_sha256"] = normalMeta.SourceSHA256
	}
	if !reflect.DeepEqual(old, actual) {
		t.Fatal("restored TUN MTU changed another captured graph field")
	}
	after, err := restored.Capture()
	if err != nil || !reflect.DeepEqual(after, capture) || after.ConfiguredMTU != capture.ConfiguredMTU || after.MTUPolicy != capture.MTUPolicy {
		t.Fatal("restoration overwrote the original configured MTU or saved policy", err)
	}
	again, err := original.LaunchInput()
	if err != nil || again != input || original.Config() != config || original.Metadata() != metadata {
		t.Fatal("restoration modified private constructor inputs or original output", err)
	}
	return restored
}

func TestDesktopNodeMTURestoresEveryCapturedGraphWithoutChangingOriginal(t *testing.T) {
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, target := range []string{"windows", "linux", "darwin"} {
				t.Run(mode+"/"+layer+"/"+target, func(t *testing.T) {
					assertDesktopNodeRestoredMTU(t, desktopNodeFixture(t, mode, layer), target, 1320)
				})
			}
		}
	}
	assertDesktopNodeRestoredMTU(t, desktopNodeDNSFixture(t), "windows", 1392)
}

func TestDesktopNodeMTUBoundsPreserveFixedJumboAndIPv6Policy(t *testing.T) {
	for _, ipv6 := range []string{"on", "off"} {
		for _, policy := range []string{"auto", "default"} {
			original := desktopNodeMTUOriginal(t, "wg", policy, 0, false, ipv6)
			for _, value := range []int{1280, 1320, 1500, 9000} {
				// These are the existing native TUN transaction bounds, not a
				// claim about packet size or fresh path measurement. Endpoint
				// MTUs and Jumbo selection are independently preserved above.
				assertDesktopNodeRestoredMTU(t, original, "windows", value)
			}
			for _, value := range []int{-1, 1, 576, 1279, 9001, 1 << 30} {
				if _, err := NewDesktopNodePolicyWithMTU(original, desktopNodeTestSession, "windows", value); err == nil {
					t.Fatal("invalid native dual-stack restore MTU was accepted", ipv6, policy, value)
				}
			}
		}
		for _, policy := range []string{"manual", "fixed"} {
			original := desktopNodeMTUOriginal(t, "wg", policy, 1392, false, ipv6)
			assertDesktopNodeRestoredMTU(t, original, "windows", 1392)
			for _, value := range []int{1280, 1391, 1393, 1500, 9000} {
				if _, err := NewDesktopNodePolicyWithMTU(original, desktopNodeTestSession, "windows", value); err == nil {
					t.Fatal("restoration changed the saved fixed MTU", policy, value)
				}
			}
		}
		for _, policy := range []string{"auto", "fixed"} {
			original := desktopNodeMTUOriginal(t, "hysteria2", policy, 9000, true, ipv6)
			assertDesktopNodeRestoredMTU(t, original, "windows", 9000)
			for _, value := range []int{1280, 1500, 8999} {
				if _, err := NewDesktopNodePolicyWithMTU(original, desktopNodeTestSession, "windows", value); err == nil {
					t.Fatal("restoration changed explicit Jumbo", policy, value)
				}
			}
		}
	}
}

func TestDesktopNodeMTUIndependentChildRecompileRequiresExactOverride(t *testing.T) {
	original := desktopNodeFixture(t, "awg2-strong", "")
	input, err := original.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []int{1280, 1380, 1500} {
		parent := desktopNodeMTUPolicy(t, original, "windows", value)
		childOriginal, err := ParseNodeLaunchInput(input)
		if err != nil {
			t.Fatal(err)
		}
		child := desktopNodeMTUPolicy(t, childOriginal, "windows", value)
		if parent.Config() != child.Config() || !reflect.DeepEqual(parent.Metadata(), child.Metadata()) {
			t.Fatal("independent child did not reproduce its captured restored graph")
		}
		for _, wrong := range []int{0, value + 1} {
			other := desktopNodeMTUPolicy(t, childOriginal, "windows", wrong)
			if other.Metadata().SourceSHA256 == parent.Metadata().SourceSHA256 || other.Metadata().ConfigSHA256 == parent.Metadata().ConfigSHA256 {
				t.Fatal("missing or substituted restore MTU matched captured source/config", value, wrong)
			}
		}
		copy := child.Metadata()
		copy.RestoredMTU++
		if child.Validate() != nil || child.Metadata().RestoredMTU != value {
			t.Fatal("returned metadata changed the retained restore selection")
		}
	}
}

func TestDesktopNodeMTUValidationRederivesPrivateCaptureAfterResealing(t *testing.T) {
	for name, mutate := range map[string]func(*DesktopNodePolicy){
		"private-override":          func(p *DesktopNodePolicy) { p.inputs.restoredMTU = 1381 },
		"missing-private-override":  func(p *DesktopNodePolicy) { p.inputs.restoredMTU = 0 },
		"metadata-override":         func(p *DesktopNodePolicy) { p.metadata.RestoredMTU = 1381 },
		"missing-metadata-override": func(p *DesktopNodePolicy) { p.metadata.RestoredMTU = 0 },
		"derived-tun": func(p *DesktopNodePolicy) {
			graph := startObject(t, p.config)
			tun := desktopNodeObject(t, graph, "inbounds", p.metadata.TUNTag)
			tun["mtu"] = float64(1381)
			p.metadata.DerivedTUNSHA256 = desktopExternalObjectDigest(tun)
			p.config = startJSON(t, graph)
		},
		"derived-dns": func(p *DesktopNodePolicy) {
			graph := startObject(t, p.config)
			dns := graph["dns"].(map[string]any)
			dns["servers"].([]any)[0].(map[string]any)["server"] = "203.0.113.53"
			p.config = startJSON(t, graph)
		},
		"derived-endpoint": func(p *DesktopNodePolicy) {
			graph := startObject(t, p.config)
			endpoint := desktopNodeObject(t, graph, "endpoints", "proxy")
			endpoint["mtu"] = endpoint["mtu"].(float64) + 1
			p.metadata.Roots[0].DerivedSHA256 = desktopExternalObjectDigest(endpoint)
			p.config = startJSON(t, graph)
		},
		"original-tun-digest":     func(p *DesktopNodePolicy) { p.metadata.OriginalTUNSHA256 = strings.Repeat("b", 64) },
		"private-session":         func(p *DesktopNodePolicy) { p.inputs.sessionID = strings.Repeat("b", 32) },
		"private-target":          func(p *DesktopNodePolicy) { p.inputs.targetOS = "linux" },
		"missing-private-capture": func(p *DesktopNodePolicy) { p.inputs = desktopNodePolicyInputs{} },
	} {
		t.Run(name, func(t *testing.T) {
			policy := desktopNodeMTUPolicy(t, desktopNodeFixture(t, "wg", ""), "windows", 1380)
			mutate(policy)
			// Matching edited hashes are not original constructor authority.
			policy.metadata.ConfigSHA256 = externalDigest([]byte(policy.config))
			policy.seal = policy.currentSeal()
			if policy.Validate() == nil || policy.Config() != "" || policy.OriginalProfile() != nil ||
				!reflect.DeepEqual(policy.Metadata(), DesktopNodeMetadata{}) {
				t.Fatal("recomputed seal authorized a substituted restore graph or private input")
			}
			if _, err := policy.Capture(); err == nil {
				t.Fatal("substituted restore returned its original capture as native authority")
			}
		})
	}
}

func desktopNodeMTUCompatibilityOriginal(t *testing.T, name string) *NodeProfile {
	t.Helper()
	switch name {
	case "auto-wg":
		return desktopNodeFixture(t, "wg", "")
	case "fixed-dns":
		return desktopNodeDNSFixture(t)
	case "jumbo-shadowsocks":
		files, profile, start := nodeProfileFixture(t, "shadowsocks", "")
		profile["kill_switch_policy"], profile["kill_switch"] = "always", true
		profile["jumbo_tun"] = true
		original, err := NewNodeProfile("shadowsocks", files, startJSON(t, profile), start, "")
		if err != nil {
			t.Fatal(err)
		}
		return original
	default:
		t.Fatal("unknown zero-override compatibility fixture")
		return nil
	}
}

func TestDesktopNodeMTUZeroPreservesPublishedDefaultBytes(t *testing.T) {
	// These source/config/metadata SHA-256 values were executed against the
	// original constructor before adding restoration. Comparing only the new
	// wrapper to its new implementation would not prove byte compatibility.
	for _, row := range []struct{ name, target, source, config, metadata string }{
		{"auto-wg", "windows", "fd880ffa95db018c9d41cba2fe47e8135e1a23bf52048e09c56d53ce4915b0ae", "b62cf473eded28c285cb1e88d839a3446b641093ec7916bd444f5932df2fbf06", "54959fa72b96bf682c2b3afc7d9e196db894fd6d60afdd559681c21557ab962a"},
		{"fixed-dns", "windows", "b13ee4130cf262b942c67d9b0e2527e9a1ae6a291a749274cee3ae7a74239a88", "44d2efb2b1379aefc1c380d460351def40f1917b96ea26c439b799bd5a97de8e", "b473a246ff8b332ae55bfd4fc37896f123937e2135f68531760970bc26830b2d"},
		{"jumbo-shadowsocks", "windows", "d9ccdf30b95f864cac16fc73904437cabaf614abda01e0d5473f129a3618828c", "2f06e76bf0b263a3661e4262f90cecd4b4add8a82bb47c666956a5e2396d4c9e", "b7274f6a8898e238297a9cbd480865ef6c08419aa3ebcdca3ec52ad34009b5af"},
		{"auto-wg", "linux", "e9853aa240953ecc0fdf1abd84181d90d52b65e6fb512c3719242265140b749a", "b22193d13aae61aefa99576f9fa07cc4202598d3ee50d471add789349a9e1fd4", "3da5c3bb07d574dcb390aace6a12e9f3105a923b9086082a6e433ce8c2e646f7"},
		{"fixed-dns", "linux", "f58c79fdb6e5db2c34def87bdc74b67e518d4eee7e8248a9645082e8051bca96", "b2cc0159d13129ced4495ab79a30d087ff57c8336453024db26f9585d0b0bcde", "8b323d458af0df7e477ca3add1656b1d9b70a4fce54c90de44fa888d16d2eefb"},
		{"jumbo-shadowsocks", "linux", "abc6aea5e10085c1983e620b9989273bdf9977983114bc8331635ed659c5a9a6", "d35f5579dd69d3270e1da90a633bb983682488c7b1d7609d245e91f20c066113", "ba3220d61db51d8cac9fc33fb433efc883ee7cebd607cdac8feb11c0d8da55b8"},
		{"auto-wg", "darwin", "bc45b8ff4f5619fb0c74e3597f11a34ba4e5279f109a90602c17168c2741abcf", "a49c8d47a7c7e819e294557a7156e3de4de0be25f07040d28686376557ece513", "b78cdf41db8f943c527a7cc5a42e825c0669c21323e9ef006ee1921342b53ba9"},
		{"fixed-dns", "darwin", "3e523ef2a036dbdac5e5b4b1144da4e61b2432286b174bd7ab8ccd823abd7ada", "2b5328004a49f3eaa837abf514e948fce35988da021bf3df8ea867ee54a0c84c", "8549a534824121571234298312196aa8640ed610555c133cc6eb427623e448b7"},
		{"jumbo-shadowsocks", "darwin", "0c6af245f19ef21aaf8f3fb91b8876da0453a3638e506f16736bb516ef104a75", "f66ba18ab6da50b37e9034fc066e7c2576733582f00a807970cd401dee9130e1", "b2498c4fd1a3aaef9a2876eb6cae41fd714e373f166d0c38e2eda08135e44694"},
	} {
		t.Run(row.name+"/"+row.target, func(t *testing.T) {
			original := desktopNodeMTUCompatibilityOriginal(t, row.name)
			legacy := desktopNodePlan(t, original, desktopNodeTestSession, row.target)
			explicit := desktopNodeMTUPolicy(t, original, row.target, 0)
			metadata, err := json.Marshal(explicit.Metadata())
			if err != nil || explicit.Config() != legacy.Config() || !reflect.DeepEqual(explicit.Metadata(), legacy.Metadata()) ||
				explicit.Metadata().RestoredMTU != 0 || explicit.Metadata().SourceSHA256 != row.source ||
				externalDigest([]byte(explicit.Config())) != row.config || externalDigest(metadata) != row.metadata ||
				strings.Contains(string(metadata), "restored_mtu") {
				t.Fatal("zero restore changed existing default source/config/metadata bytes")
			}
		})
	}
}
