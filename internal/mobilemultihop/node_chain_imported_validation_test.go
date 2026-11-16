package mobilemultihop

import (
	"fmt"
	"testing"
)

// Every observation checks the complete original policy seal, not just its
// config and metadata. Re-sealing a changed policy cannot replace the retained
// constructor identity or authorize another native owner.
func TestNodeChainMultipleImportedObservationValidatesEachOriginalPolicy(t *testing.T) {
	layout := nodeChainImportedLayouts[len(nodeChainImportedLayouts)-1]
	for _, position := range layout.positions {
		for _, fault := range []string{"missing-policy-seal", "changed-private-capture", "resealed-invalid-private-capture", "resealed-valid-private-capture"} {
			t.Run(fmt.Sprintf("%d/%s", position, fault), func(t *testing.T) {
				source := nodeChainMultipleImportedFixture(t, layout, "wg", "")
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil || chain.validateCapture() != nil {
					t.Fatal("valid complete original capture refused", err)
				}
				member := chain.importedNodes.members[position]
				originalMemberDigest := member.digest()
				switch fault {
				case "missing-policy-seal":
					member.policy.desktopSeal = ""
				case "changed-private-capture":
					member.policy.capture.Profile["kill_switch_policy"] = "invalid-original-policy"
				case "resealed-invalid-private-capture":
					member.policy.capture.Profile["kill_switch_policy"] = "invalid-original-policy"
					if err := member.policy.sealDesktopCapture(); err != nil {
						t.Fatal(err)
					}
				case "resealed-valid-private-capture":
					changed := "always"
					if member.policy.capture.Profile["kill_switch_policy"] == changed {
						changed = "off"
					}
					member.policy.capture.Profile["kill_switch_policy"] = changed
					if err := member.policy.sealDesktopCapture(); err != nil {
						t.Fatal(err)
					}
					if _, err := member.policy.DesktopCapture(); err != nil {
						t.Fatal("replacement must independently remain a valid policy", err)
					}
				}
				if !chain.importedNodes.originalOwnersCurrent(chain) || member.digest() != originalMemberDigest {
					t.Fatal("control must preserve original aggregate and member digest")
				}
				if chain.validateCapture() == nil {
					t.Fatal("original imported policy validation was skipped")
				}
				if _, err := chain.LaunchInput(); err == nil {
					t.Fatal("changed original imported policy retained launch authority")
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedPolicyRetainsConstructor(t *testing.T) {
	for _, fault := range []string{"original", "copied-policy", "missing-owner", "missing-captured-seal", "changed-captured-seal", "copied-private-capture"} {
		t.Run(fault, func(t *testing.T) {
			source := nodeChainImportedSSPrefixFixture(t, 1, "wg", "2022-blake3-aes-256-gcm", false)
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			member := chain.importedMiddle
			switch fault {
			case "copied-policy":
				copy := *member.policy
				member.policy = &copy
			case "missing-owner":
				member.policyOwner = nil
			case "missing-captured-seal":
				member.policySeal = ""
			case "changed-captured-seal":
				member.policySeal += "0"
			case "copied-private-capture":
				member.policy.capture.Profile = predecessorCopy(member.policy.capture.Profile)
			}
			// An independent map holding the exact same private values remains
			// the same policy. Replacing its constructor owner never does.
			valid := fault == "original" || fault == "copied-private-capture"
			if (member.validate() == nil) != valid {
				t.Fatal("constructor-bound policy observation", fault)
			}
		})
	}
}
