package mobilemultihop

import (
	"fmt"
	"testing"
)

func desktopCandidateTypedSource(t *testing.T, family string, count int) (NodeChainSource, string) {
	t.Helper()
	source, inventory := typedCandidatePreparationSource(t, family, count)
	// Make every paired member permissive. The uncontacted typed middle alone
	// contributes always-on kill protection, IPv6Off and no home LAN access.
	for i, input := range source.Nodes {
		if i == count-2 {
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
	return source, inventory
}

func TestDesktopNodeCandidateTypedSavedPolicy(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		for _, count := range []int{3, 4, 8} {
			t.Run(fmt.Sprintf("%s/%d", family, count), func(t *testing.T) {
				source, inventory := desktopCandidateTypedSource(t, family, count)
				original := typedCandidatePreparation(t, source, count-3, inventory)
				for _, target := range []string{"linux", "windows", "darwin"} {
					t.Run(target, func(t *testing.T) {
						policy, err := NewDesktopNodeCandidatePreparationPolicy(original, desktopNodeTestSession, target, 0)
						if err != nil {
							t.Fatal("typed saved middle cannot retain desktop prefix protection", err)
						}
						assertDesktopCandidateImportedPolicy(t, policy)
						if policy.Metadata().OriginalSourceSHA256 != original.OriginalSourceSHA256() {
							t.Fatal("desktop typed prefix lost full saved identity")
						}
					})
				}
			})
		}
	}
}

func TestDesktopNodeCandidateTypedPolicyRefusesOriginalChange(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		for _, fault := range []string{"middle-copy", "middle-protection", "final-control", "physical", "source-envelope"} {
			t.Run(family+"/"+fault, func(t *testing.T) {
				source, inventory := desktopCandidateTypedSource(t, family, 4)
				original := typedCandidatePreparation(t, source, 1, inventory)
				policy, err := NewDesktopNodeCandidatePreparationPolicy(original, desktopNodeTestSession, "linux", 0)
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "middle-copy":
					if s := original.typedOriginal.socks; s != nil {
						copied := *s.middle
						s.middle = &copied
					} else {
						copied := *original.typedOriginal.connect.middle
						original.typedOriginal.connect.middle = &copied
					}
				case "middle-protection":
					if s := original.typedOriginal.socks; s != nil {
						s.metadata.Devices[2].KillSwitchPolicy = "off"
					} else {
						original.typedOriginal.connect.metadata.Devices[2].KillSwitchPolicy = "off"
					}
				case "final-control":
					policy.metadata.PolicyProfileID = policy.metadata.ProfileID
				case "physical":
					policy.capture.PhysicalRoots[0].Tag = "foreign-root"
				case "source-envelope":
					record := externalTestRead(t, policy.Source())
					// A generic pair capture is never a substitute for the typed source.
					generic, err := NewNodeChainCandidatePreparation(original.original.sourceJSON, 1, inventory)
					if err != nil {
						t.Fatal(err)
					}
					record["preparation"] = generic.Source()
					if _, err := ParseDesktopNodeCandidatePreparationPolicy(startJSON(t, record)); err == nil {
						t.Fatal("detached pair substituted for complete typed protection")
					}
					return
				}
				if policy.Validate() == nil || policy.Source() != "" || policy.Preparation() != nil {
					t.Fatal("changed typed source retained original desktop prefix authority", fault)
				}
			})
		}
	}
}
