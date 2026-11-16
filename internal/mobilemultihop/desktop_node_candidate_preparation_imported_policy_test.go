package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The uncontacted middle alone supplies the strongest restrictions. Every
// paired node stays permissive, so dropping the saved middle is observable.
func desktopCandidateImportedSource(t *testing.T, count int, mode, network string) (NodeChainSource, string) {
	t.Helper()
	var source NodeChainSource
	if network == "ss" {
		source = nodeChainImportedFixture(t, mode, "")
	} else {
		source = nodeChainOpenVPNPrefixFixture(t, count-2, mode, network, "")
	}
	middle := len(source.Nodes) - 2
	for i, input := range source.Nodes {
		if i == middle {
			continue
		}
		node, err := ParseNodeLaunchInput(input)
		if err != nil {
			t.Fatal(err)
		}
		profile := predecessorCopy(node.profile)
		profile["kill_switch"], profile["kill_switch_policy"], profile["ipv6_mode"], profile["home_lan_access"] = false, "off", "on", true
		node, err = NewNodeProfile(node.inputs.Mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes[i], err = node.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
	}
	var member nodeChainImportedInput
	if err := json.Unmarshal([]byte(source.Nodes[middle]), &member); err != nil {
		t.Fatal(err)
	}
	capture := startObject(t, member.Capture)
	profile := capture["profile"].(map[string]any)
	profile["kill_switch"], profile["kill_switch_policy"], profile["ipv6_mode"], profile["home_lan_access"] = true, "always", "off", false
	var err error
	if network == "ss" {
		source.Nodes[middle], err = NodeChainImportedMemberInput(member.Config, startJSON(t, capture))
	} else {
		source.Nodes[middle], err = NodeChainImportedOpenVPNMemberInput(member.Config, startJSON(t, capture))
	}
	if err != nil {
		t.Fatal(err)
	}
	target, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	return source, candidateInventoryFixture(t, "original-desktop-saved-prefix", target)
}

func desktopCandidateImportedPolicy(t *testing.T, source NodeChainSource, inventory, target string) *DesktopNodeCandidatePreparationPolicy {
	t.Helper()
	base, err := NewNodeChainCandidatePreparation(startJSON(t, source), len(source.Nodes)-3, inventory)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewDesktopNodeCandidatePreparationPolicy(base, desktopNodeTestSession, target, 0)
	if err != nil {
		t.Fatal("saved imported middle must retain desktop prefix protection", err)
	}
	return p
}

func assertDesktopCandidateImportedPolicy(t *testing.T, p *DesktopNodeCandidatePreparationPolicy) {
	t.Helper()
	config, meta, physical, err := p.PhysicalReadValidated()
	control, controlErr := ReadDesktopProtectionProfileID(p)
	final := p.original.original.proofs[len(p.original.original.proofs)-1]
	if err != nil || controlErr != nil || meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess ||
		physical.IPv6Mode != "off" || control != final.ProfileID || p.Metadata().PolicyProfileID != final.ProfileID ||
		meta.ProfileID == control || len(physical.PhysicalRoots) != 1 || physical.SelectedDNS.Physical ||
		physical.SelectedDNS.Detour != p.original.proofs[p.original.position].Tag || p.Metadata().ApplicationOpen || p.Metadata().DNSOpen {
		t.Fatal("saved middle protection or final control was lost", err, controlErr, meta)
	}
	graph := startObject(t, config)
	if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag ||
		!reflect.DeepEqual(externalTestFind(t, graph, SelectorTag)["outbounds"], []any{p.original.proofs[p.original.position].Tag}) {
		t.Fatal("candidate prefix opened application ingress or selected an unproved suffix")
	}
	for _, proof := range p.original.original.proofs[p.original.position+1:] {
		if strings.Contains(config, proof.Tag) {
			t.Fatal("uncontacted suffix became runnable", proof.Position)
		}
	}
	if strings.Contains(config, "openvpn-client") {
		t.Fatal("OpenVPN suffix became a native prefix dependency")
	}
	for i, root := range physical.PhysicalRoots {
		row := desktopNodeObject(t, graph, root.Family, root.Tag)
		if row["detour"] != DesktopNodePhysicalTag || desktopExternalObjectDigest(row) != p.metadata.Roots[i].DerivedSHA256 {
			t.Fatal("prefix physical root lost its captured owner")
		}
	}
	replay, err := ParseDesktopNodeCandidatePreparationPolicy(p.Source())
	if err != nil || replay == p || replay.original == p.original || replay.Config() != config || !reflect.DeepEqual(replay.Metadata(), p.Metadata()) {
		t.Fatal("desktop prefix replay changed full saved provenance", err)
	}
	mtu, err := p.Preparation().MTUPlan()
	if err != nil || len(mtu.Prefixes) != p.original.position+1 || mtu.Original > mtu.Ceiling {
		t.Fatal("prefix configured MTU changed", err)
	}
	restored, err := NewDesktopNodeCandidatePreparationPolicy(p.original, desktopNodeTestSession, p.Metadata().TargetOS, mtu.Original)
	if err != nil || restored.Metadata().RestoredMTU != mtu.Original {
		t.Fatal("valid retained MTU restore failed", err)
	}
	if _, err := NewDesktopNodeCandidatePreparationPolicy(p.original, desktopNodeTestSession, p.Metadata().TargetOS, 9000); err == nil {
		t.Fatal("over-ceiling restored MTU admitted")
	}
}

func TestDesktopNodeCandidateOpenVPNSavedPolicy(t *testing.T) {
	for i, target := range []string{"linux", "windows", "darwin"} {
		for j, count := range []int{3, 4, 8} {
			t.Run(fmt.Sprintf("%s/%d", target, count), func(t *testing.T) {
				mode := []string{"wg", "awg2-fast", "awg2-strong"}[(i+j)%3]
				network := []string{"tcp", "udp"}[(i+j)%2]
				source, inventory := desktopCandidateImportedSource(t, count, mode, network)
				p := desktopCandidateImportedPolicy(t, source, inventory, target)
				assertDesktopCandidateImportedPolicy(t, p)
			})
		}
	}
}

func TestDesktopNodeCandidateImportedSSOriginalTrioPolicy(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			source, inventory := desktopCandidateImportedSource(t, 3, "wg", "ss")
			assertDesktopCandidateImportedPolicy(t, desktopCandidateImportedPolicy(t, source, inventory, target))
		})
	}
}

func TestDesktopNodeCandidateOpenVPNPolicyRefusesMutation(t *testing.T) {
	for _, fault := range []string{"middle-copy", "middle-policy", "protection", "physical", "source-record"} {
		t.Run(fault, func(t *testing.T) {
			source, inventory := desktopCandidateImportedSource(t, 4, "wg", "tcp")
			p := desktopCandidateImportedPolicy(t, source, inventory, "linux")
			switch fault {
			case "middle-copy":
				copy := *p.original.original.openVPNMiddle
				p.original.original.openVPNMiddle = &copy
			case "middle-policy":
				p.original.original.openVPNMiddle.selection.Profile["home_lan_access"] = true
			case "protection":
				p.metadata.KillSwitchPolicy = "off"
			case "physical":
				p.capture.PhysicalRoots[0].ConfigSHA256 = strings.Repeat("f", 64)
			case "source-record":
				record := startObject(t, p.Source())
				record["preparation"] = strings.Replace(record["preparation"].(string), "original-desktop-saved-prefix", "foreign-desktop-saved-prefix", 1)
				if _, err := ParseDesktopNodeCandidatePreparationPolicy(startJSON(t, record)); err == nil {
					t.Fatal("foreign candidate catalog acquired original policy")
				}
				return
			}
			if p.Validate() == nil || p.Source() != "" {
				t.Fatal("mutated saved middle retained original desktop authority")
			}
		})
	}
}
