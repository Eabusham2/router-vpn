package mobilemultihop

import (
	"fmt"
	"testing"
)

func TestOpenVPNSourceObservationKeepsOriginalReceipt(t *testing.T) {
	for _, prefixes := range []int{1, 6} {
		for _, network := range []string{"tcp", "udp"} {
			for _, fault := range []string{"original", "copied-receipt", "foreign-receipt", "resealed-source", "changed-receipt", "middle-input", "copied-middle", "copied-policy", "copied-prefix", "count", "nil-receipt", "changed-selection", "changed-policy", "changed-proof"} {
				t.Run(fmt.Sprintf("%d/%s/%s", prefixes+2, network, fault), func(t *testing.T) {
					source := nodeChainOpenVPNPrefixFixture(t, prefixes, "wg", network, "")
					chain, err := NewNodeChain(startJSON(t, source))
					if err != nil {
						t.Fatal(err)
					}
					switch fault {
					case "copied-receipt":
						copy := *chain.openVPNOwners
						chain.openVPNOwners = &copy
					case "foreign-receipt":
						other, e := NewNodeChain(startJSON(t, source))
						if e != nil {
							t.Fatal(e)
						}
						chain.openVPNOwners = other.openVPNOwners
					case "resealed-source":
						chain.sourceJSON += " "
						chain.seal = chain.captureSeal()
					case "changed-receipt":
						chain.openVPNOwners.sourceJSON += " "
					case "middle-input":
						chain.openVPNMiddle.input += " "
					case "copied-middle":
						copy := *chain.openVPNMiddle
						chain.openVPNMiddle = &copy
					case "copied-policy":
						copy := *chain.openVPNMiddle.policy
						chain.openVPNMiddle.policy = &copy
					case "copied-prefix":
						copy := *chain.nodes[0]
						chain.nodes[0] = &copy
					case "count":
						chain.openVPNOwners.count--
					case "nil-receipt":
						chain.openVPNOwners = nil
					case "changed-selection":
						chain.openVPNMiddle.selection.Profile["endpoint"] = "203.0.113.99"
					case "changed-policy":
						chain.openVPNMiddle.policy.capture.Profile["kill_switch_policy"] = "always"
					case "changed-proof":
						chain.proofs[prefixes].Mode = "shadowsocks"
						chain.seal = chain.captureSeal()
					}
					err = chain.validateCapture()
					if fault != "original" {
						if err == nil {
							t.Fatal("OpenVPN observation accepted changed original receipt", fault)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, target := range []string{"linux", "windows", "darwin", "android", "ios"} {
						projected, e := ProjectNodeChain(chain, target, 1280)
						if e != nil {
							t.Fatal(e)
						}
						if projected == chain || projected.openVPNOwners == chain.openVPNOwners || projected.openVPNOwners.owner != projected || projected.validateCapture() != nil {
							t.Fatal("authorized OpenVPN projection lost fresh original receipt", target)
						}
					}
				})
			}
		}
	}
}
