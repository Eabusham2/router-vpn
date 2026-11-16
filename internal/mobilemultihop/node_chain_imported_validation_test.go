package mobilemultihop

import (
	"fmt"
	"testing"
)

// The aggregate pointer/position check is not a cached policy verdict. Each
// original member must still run its complete policy validation on every read,
// including a change that leaves the member's config and metadata unchanged.
func TestNodeChainMultipleImportedObservationValidatesEachOriginalPolicy(t *testing.T) {
	layout := nodeChainImportedLayouts[len(nodeChainImportedLayouts)-1]
	for _, position := range layout.positions {
		for _, fault := range []string{"missing-policy-seal", "changed-private-capture", "resealed-invalid-private-capture"} {
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
