package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

func mixedFixtureHostname(t *testing.T, input, host string, port any) string {
	t.Helper()
	var in nodeChainImportedInput
	if err := json.Unmarshal([]byte(input), &in); err != nil {
		t.Fatal(err)
	}
	graph, capture := externalTestRead(t, in.Config), externalTestRead(t, in.Capture)
	out := externalTestFind(t, graph, ExternalFinalTag)
	profile := capture["profile"].(map[string]any)
	ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
	profile["endpoint"], out["server"], ss["server"] = host, host, host
	profile["dns_mode"], profile["dns_protocol"] = "custom", "tcp"
	profile["dns_host"], profile["dns_port"] = "10.81.0.53", 5353
	out["server_port"], ss["port"] = port, port
	delete(graph, "dns")
	result, err := NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal("hostname input", err)
	}
	return result
}

func TestMixedLocalHostnameKeepsSavedResolverAndAllSuffixSockets(t *testing.T) {
	for _, n := range []int{4, 9, 16} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var imports []int
			for i := 1; i < n-1; i++ {
				imports = append(imports, i)
			}
			source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"hostname", n, imports}, "awg2-fast", "")
			// Deliberately share a port with a known original suffix socket.
			var suffix nodeChainImportedInput
			if err := json.Unmarshal([]byte(source.Nodes[n-2]), &suffix); err != nil {
				t.Fatal(err)
			}
			peer := externalTestFind(t, externalTestRead(t, suffix.Config), ExternalFinalTag)
			const host = "MiXeD.example.test"
			source.Nodes[1] = mixedFixtureHostname(t, source.Nodes[1], host, peer["server_port"])
			raw := startJSON(t, source)
			c, err := NewNodeChain(raw)
			if err != nil {
				t.Fatal("complete source", err)
			}
			if _, err = NewNodeChainMultipleImportedExecutionPreparation(c, "auto"); err == nil {
				t.Fatal("remote source granted")
			}
			expected, err := c.originalHostnameExclusions(1)
			if err != nil || !slices.Contains(expected, predecessorText(peer, "server")) {
				t.Fatal("missing original suffix", expected, err)
			}
			target, err := nodeChainFixtureNodes(t, n+1, "")[n].LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			inventory := candidateInventoryFixture(t, "independent-hostname-response", target)
			for _, pos := range []int{1, n - 2} {
				if c.CandidatePrefixMeasurement(pos) == "" {
					t.Fatal("missing recursive host measurement", pos)
				}
				p, err := NewNodeChainMultipleImportedCandidatePreparation(raw, pos, inventory)
				if err != nil {
					t.Fatal("closed prefix", pos, err)
				}
				closed := externalTestRead(t, p.Config())
				member := externalTestFind(t, closed, c.proofs[1].Tag)
				if startJSON(t, member[nodeChainOriginalPeerExclusions]) != startJSON(t, expected) || member["detour"] != c.proofs[0].Tag || member["server"] != host {
					t.Fatal("lost complete original peer guard", member)
				}
			}
			other := source
			other.Nodes = slices.Clone(source.Nodes)
			other.Nodes[1], other.Nodes[2] = other.Nodes[2], other.Nodes[1]
			later, err := NewNodeChain(startJSON(t, other))
			if err != nil || later == nil {
				t.Fatal("original later hostname after its independent literal stream failed", err)
			}
			if _, err := NewNodeChainMultipleImportedExecutionPreparation(later, "server"); err == nil {
				t.Fatal("later hostname acquired Server authority")
			}
			for _, pos := range []int{2, n - 2} {
				if later.CandidatePrefixMeasurement(pos) == "" {
					t.Fatal("later hostname lost private response authority", pos)
				}
				closed, err := NewNodeChainMultipleImportedCandidatePreparation(startJSON(t, other), pos, inventory)
				if err != nil {
					t.Fatal("later hostname lost its original candidate preparation", err)
				}
				for _, config := range []string{later.Config(), closed.Config()} {
					graph := externalTestRead(t, config)
					member := externalTestFind(t, graph, later.proofs[2].Tag)
					if member["server"] != host || member["detour"] != later.proofs[1].Tag || startJSON(t, member[nodeChainOriginalPeerExclusions]) != startJSON(t, expected) {
						t.Fatal("later hostname substituted original predecessor or suffix exclusions", member)
					}
					tag := member["domain_resolver"].(map[string]any)["server"]
					dns := graph["dns"].(map[string]any)
					found := 0
					for _, raw := range dns["servers"].([]any) {
						row := raw.(map[string]any)
						if row["tag"] == tag {
							found++
							if row["detour"] != later.proofs[1].Tag || row["type"] != "tcp" || row["server"] != "10.81.0.53" || row["server_port"] != float64(5353) {
								t.Fatal("saved transport DNS did not retain original literal predecessor", row)
							}
						}
					}
					if found != 1 || dns["final"] == tag {
						t.Fatal("transport DNS changed application DNS ownership", dns)
					}
				}
			}
			duplicate := other
			duplicate.Nodes = slices.Clone(other.Nodes)
			duplicate.Nodes[1] = mixedFixtureHostname(t, duplicate.Nodes[1], "another.example.test", float64(23002))
			if got, err := NewNodeChain(startJSON(t, duplicate)); got != nil || err == nil {
				t.Fatal("accepted second independently captured hostname")
			}
			if n == 9 {
				bad := other
				bad.Nodes = slices.Clone(other.Nodes)
				bad.IdentitySources = slices.Clone(other.IdentitySources)
				paired := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg", "shadowsocks"}, []string{"", "", "", ""})
				identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg", "wg"}, []string{"", "", "", ""})
				bad.Nodes[3], err = paired[3].LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				bad.IdentitySources[3] = identities[3].inputs.Files
				if got, err := NewNodeChain(startJSON(t, bad)); got != nil || err == nil {
					t.Fatal("accepted a paired stream suffix in the later-hostname family")
				}
				bad.IdentitySources[3], bad.Nodes[3] = other.IdentitySources[3], other.Nodes[3]
				bad.Nodes[2], bad.Nodes[3] = bad.Nodes[3], bad.Nodes[2]
				if got, err := NewNodeChain(startJSON(t, bad)); got == nil || err != nil || got.CandidatePrefixMeasurement(3) == "" {
					t.Fatal("hostname lost its second literal predecessor", err)
				}
			}
		})
	}
}

// A closed candidate preparation must retain suffix exclusions even when
// application and DNS remain unavailable to the temporary owner.
func TestLaterHostnameDepthAndPredecessor(t *testing.T) {
	for _, count := range []int{4, 5, 8, 9, 16, 96} {
		positions := []int{2}
		if count > 4 {
			positions = append(positions, count-2)
		}
		for _, at := range positions {
			t.Run(fmt.Sprintf("%d/hostname-%d", count, at), func(t *testing.T) {
				imports := make([]int, count-2)
				for i := range imports {
					imports[i] = i + 1
				}
				source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"later-source", count, imports}, "awg2-fast", "")
				peerPosition := count - 2
				if at == peerPosition {
					peerPosition = 1
				}
				var peerInput nodeChainImportedInput
				if err := json.Unmarshal([]byte(source.Nodes[peerPosition]), &peerInput); err != nil {
					t.Fatal(err)
				}
				peer := externalTestFind(t, externalTestRead(t, peerInput.Config), ExternalFinalTag)
				source.Nodes[at] = mixedFixtureHostname(t, source.Nodes[at], "late.original.test", peer["server_port"])
				raw := startJSON(t, source)
				c, err := NewNodeChain(raw)
				if err != nil {
					t.Fatal("complete original later hostname failed", err)
				}
				launch, err := c.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				reopened, err := ParseNodeChainLaunchInput(launch)
				if err != nil || reopened.SourceSHA256() != c.SourceSHA256() || reopened.ConfigSHA256() != c.ConfigSHA256() {
					t.Fatal("reopen changed original graph", err)
				}
				if _, err := NewNodeChainMultipleImportedExecutionPreparation(reopened, "auto"); err == nil {
					t.Fatal("later hostname acquired remote path")
				}
				exclusions, err := reopened.originalHostnameExclusions(at)
				if err != nil || !slices.Contains(exclusions, predecessorText(peer, "server")) {
					t.Fatal("missing literal peer exclusion", err)
				}
				target, err := nodeChainFixtureNodes(t, count+1, "")[count].LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				inventory := candidateInventoryFixture(t, "original-later-source", target)
				for _, prefix := range []int{at, count - 2} {
					if reopened.CandidatePrefixMeasurement(prefix) == "" {
						t.Fatal("private response authority lost", prefix)
					}
					plan, err := NewNodeChainMultipleImportedCandidatePreparation(raw, prefix, inventory)
					if err != nil || plan.OriginalSourceSHA256() != c.SourceSHA256() {
						t.Fatal("closed source", prefix, err)
					}
					graph := externalTestRead(t, plan.Config())
					host := externalTestFind(t, graph, c.proofs[at].Tag)
					if host["detour"] != c.proofs[at-1].Tag || host["server"] != "late.original.test" || startJSON(t, host[nodeChainOriginalPeerExclusions]) != startJSON(t, exclusions) {
						t.Fatal("closed prefix lost resolver predecessor, spelling or peer exclusions")
					}
				}
			})
		}
	}
}
