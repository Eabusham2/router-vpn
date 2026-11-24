package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

func TestMixedExtendedLocalSourceMTUAndBoundaries(t *testing.T) {
	for _, n := range []int{9, 16} {
		for _, spec := range []struct {
			mode    string
			packets int
		}{{"wg", 2}, {"awg2-fast", 1}, {"awg2-strong", 2}} {
			t.Run(fmt.Sprintf("%d-%s-%d", n, spec.mode, spec.packets), func(t *testing.T) {
				imports := make([]int, n-spec.packets-1)
				for i := range imports {
					imports[i] = i + spec.packets
				}
				source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"mixed", n, imports}, spec.mode, "")
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal("original Local capture", err)
				}
				check := func(chain *NodeChain) {
					t.Helper()
					if chain.ExtendedLocalNodeCount() != n || chain.ExtendedMixedLocalPacketCount() != spec.packets || chain.ExtendedPairedLocalNodeCount() != 0 {
						t.Fatal("mixed Local family marker")
					}
					plan, e := chain.MTUPlan()
					if e != nil || len(plan.Prefixes) != n {
						t.Fatal("original packet MTU", e)
					}
					_, e = chain.PlanForMTU(chain.Config(), plan.Original)
					if e != nil {
						t.Fatal("exact TUN readback", e)
					}
				}
				check(chain)
				input, e := chain.LaunchInput()
				if e != nil {
					t.Fatal(e)
				}
				reopened, e := ParseNodeChainLaunchInput(input)
				if e != nil || reopened.ConfigSHA256() != chain.ConfigSHA256() {
					t.Fatal("source replay", e)
				}
				check(reopened)
				for _, target := range []string{"linux", "windows", "darwin"} {
					policy, e := NewDesktopNodeChainPolicy(chain, "0123456789abcdef0123456789abcdef", target, 0)
					if e != nil {
						t.Fatal("desktop physical source", target, e)
					}
					check(policy.NodeChain())
				}
				for _, mode := range []string{"server", "auto"} {
					got, e := NewNodeChainMultipleImportedExecutionPreparation(chain, mode)
					if spec.mode == "awg2-fast" && spec.packets == 1 {
						if e != nil || got == nil || !chain.extendedFastSelectedSource() {
							t.Fatal("original Fast stream route lost its selected preparation", mode, e)
						}
					} else if e == nil || got != nil {
						t.Fatal("unqualified mixed Local source granted selected execution", mode)
					}
				}
				for _, mutation := range []string{"late-source", "late-identity", "reordered", "noncontiguous"} {
					bad := source
					bad.Nodes = slices.Clone(source.Nodes)
					bad.IdentitySources = slices.Clone(source.IdentitySources)
					switch mutation {
					case "late-source":
						bad.Nodes[n-2] = bad.Nodes[n-3]
					case "late-identity":
						bad.IdentitySources[n-2] = source.IdentitySources[0]
					case "reordered":
						bad.IdentitySources[n-1] = source.IdentitySources[0]
					case "noncontiguous":
						if spec.packets == 1 {
							continue
						}
						a, b := 1, n-2
						bad.Nodes[a], bad.Nodes[b] = bad.Nodes[b], bad.Nodes[a]
						bad.IdentitySources[a], bad.IdentitySources[b] = bad.IdentitySources[b], bad.IdentitySources[a]
					}
					if got, e := NewNodeChain(startJSON(t, bad)); e == nil || got != nil {
						t.Fatal("accepted", mutation)
					}
				}
				original := chain.importedNodes.members[n-2]
				chain.importedNodes.members[n-2] = chain.importedNodes.members[n-3]
				if chain.ExtendedMixedLocalPacketCount() != 0 || chain.ExtendedLocalNodeCount() != 0 {
					t.Fatal("changed late member retained original family")
				}
				chain.importedNodes.members[n-2] = original
			})
		}
	}
}

func TestExtendedLocalPrivateStreamRolesAtPhysicalDepth(t *testing.T) {
	const n = NodeChainExtendedLocalMaximumNodes
	modes := make([]string, n)
	var imports []int
	for i := range modes {
		modes[i] = "shadowsocks"
		if i > 0 && i < n-1 && i%3 == 1 {
			imports = append(imports, i)
		}
	}
	modes[0] = "wg"
	source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"recursive", n, imports}, "wg", "")
	nodes := nodeChainModeFixtureNodes(t, modes, make([]string, n))
	for i, node := range nodes {
		if source.IdentitySources[i] != "" {
			var err error
			source.Nodes[i], err = node.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	c, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	if c.ExtendedLocalNodeCount() != n || c.ExtendedMixedLocalPacketCount() != 1 || !c.HasPairedStreamInterior() ||
		c.CandidatePrefixMeasurement(n-2) != "routed-candidate-response" {
		t.Fatal("lost the complete original recursive path")
	}
	var roles []string
	if json.Unmarshal([]byte(c.ExtendedLocalRolesJSON()), &roles) != nil || len(roles) != n {
		t.Fatal("missing original role inventory")
	}
	for i, role := range roles {
		if (role == "public-path") != slices.Contains(imports, i) {
			t.Fatal("changed original role", i, role)
		}
	}
	original := c.nodes[n-2]
	c.nodes[n-2] = nodes[n-3]
	if c.ExtendedLocalRolesJSON() != "" || c.CandidatePrefixMeasurement(n-2) != "" {
		t.Fatal("relinked private source retained role or measurement authority")
	}
	c.nodes[n-2] = original
}
