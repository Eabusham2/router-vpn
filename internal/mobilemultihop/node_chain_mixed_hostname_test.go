package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

func TestMixedLocalHostnameKeepsSavedResolverAndAllSuffixSockets(t *testing.T) {
	for _, n := range []int{4, 9, 16} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var imports []int
			for i := 1; i < n-1; i++ {
				imports = append(imports, i)
			}
			source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"hostname", n, imports}, "awg2-fast", "")
			var in nodeChainImportedInput
			if err := json.Unmarshal([]byte(source.Nodes[1]), &in); err != nil {
				t.Fatal(err)
			}
			graph, capture := externalTestRead(t, in.Config), externalTestRead(t, in.Capture)
			out := externalTestFind(t, graph, ExternalFinalTag)
			profile := capture["profile"].(map[string]any)
			ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
			const host = "MiXeD.example.test"
			profile["endpoint"], out["server"], ss["server"] = host, host, host
			profile["dns_mode"], profile["dns_protocol"] = "custom", "tcp"
			profile["dns_host"], profile["dns_port"] = "10.81.0.53", 5353
			// Deliberately share a port with a known original suffix socket.
			var suffix nodeChainImportedInput
			if err := json.Unmarshal([]byte(source.Nodes[n-2]), &suffix); err != nil {
				t.Fatal(err)
			}
			peer := externalTestFind(t, externalTestRead(t, suffix.Config), ExternalFinalTag)
			out["server_port"], ss["port"] = peer["server_port"], peer["server_port"]
			delete(graph, "dns")
			var err error
			source.Nodes[1], err = NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
			if err != nil {
				t.Fatal("hostname input", err)
			}
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
			if got, err := NewNodeChain(startJSON(t, other)); got != nil || err == nil {
				t.Fatal("accepted hostname after stream")
			}
		})
	}
}
