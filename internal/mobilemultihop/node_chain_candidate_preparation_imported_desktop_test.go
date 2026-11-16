package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func candidatePreparationImportedDesktopSource(t *testing.T, count int, mode string, hostname bool) (NodeChainSource, string) {
	t.Helper()
	source, inventory := candidatePreparationImportedSource(t, count, mode, "2022-blake3-aes-256-gcm", hostname)
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
	source.Nodes[middle], err = NodeChainImportedMemberInput(member.Config, startJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	return source, inventory
}

func candidatePreparationImportedDesktopPolicy(t *testing.T, hostname bool) {
	t.Helper()
	for i, target := range []string{"linux", "windows", "darwin"} {
		for j, count := range []int{2, 6} {
			t.Run(fmt.Sprintf("%s/%d", target, count+2), func(t *testing.T) {
				mode := []string{"wg", "awg2-fast", "awg2-strong"}[(i+j)%3]
				source, inventory := candidatePreparationImportedDesktopSource(t, count, mode, hostname)
				input := startJSON(t, source)
				p := desktopCandidateImportedPolicy(t, source, inventory, target)
				assertDesktopCandidateImportedPolicy(t, p)
				if p.original.original.sourceJSON != input || p.original.position != count-1 || len(p.Preparation().ProofInventory()) != count || p.original.original.importedMiddlePosition() != count {
					t.Fatal("complete desktop saved SS prefix lost original source or member position")
				}
				closure, err := p.original.original.importedMiddle.closure()
				if err != nil || strings.Contains(p.Config(), predecessorText(closure.final, "server")) || strings.Contains(p.Config(), predecessorText(closure.final, "password")) {
					t.Fatal("desktop saved SS suffix entered executable prefix", err)
				}
				if hostname {
					full := externalTestRead(t, p.original.original.Config())
					middle := externalTestFind(t, full, p.original.original.proofs[count].Tag)
					resolver, ok := middle["domain_resolver"].(map[string]any)
					tag := predecessorText(resolver, "server")
					if !ok || tag == "" || strings.Contains(p.Config(), tag) {
						t.Fatal("desktop saved hostname resolver became prefix authority")
					}
					if NodeChainCandidateInputSupported(source.Nodes[count]) {
						t.Fatal("saved hostname became a candidate TCP timing target")
					}
				}
				copied := *p.original.original.importedMiddle
				p.original.original.importedMiddle = &copied
				if _, _, _, err := p.PhysicalReadValidated(); err == nil || p.Source() != "" {
					t.Fatal("desktop prefix retained a substituted saved SS owner")
				}
			})
		}
	}
}

func TestNodeChainCandidatePreparationImportedSSDesktopLiteral(t *testing.T) {
	candidatePreparationImportedDesktopPolicy(t, false)
}
func TestNodeChainCandidatePreparationImportedSSDesktopHostname(t *testing.T) {
	candidatePreparationImportedDesktopPolicy(t, true)
}
