package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func extendedPairedFixture(t *testing.T, count, mtu int) NodeChainSource {
	t.Helper()
	nodes := nodeChainFixtureNodes(t, count, "")
	modes := make([]string, count)
	for i := range modes {
		modes[i] = "wg"
	}
	identities := nodeChainModeFixtureNodes(t, modes, make([]string, count))
	source := NodeChainSource{Schema: 1, Execution: "local"}
	for i, n := range nodes {
		if i < len(nodes)-1 {
			var files map[string]string
			if err := json.Unmarshal([]byte(n.inputs.Files), &files); err != nil {
				t.Fatal(err)
			}
			cfg := string(mustDecodeChainAsset(t, files["wg.conf"]))
			files["wg.conf"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(cfg, "MTU = 2000", fmt.Sprintf("MTU = %d", mtu), 1)))
			var err error
			n, err = NewNodeProfile("wg", startJSON(t, files), n.inputs.ProfileJSON, "", "")
			if err != nil {
				t.Fatal(err)
			}
			source.IdentitySources = append(source.IdentitySources, n.inputs.Files)
		} else {
			source.IdentitySources = append(source.IdentitySources, identities[i].inputs.Files)
		}
		input, err := n.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes = append(source.Nodes, input)
	}
	return source
}

func TestExtendedPairedLocalSourceAndPacketEnvelope(t *testing.T) {
	for _, n := range []int{9, 16} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			source := extendedPairedFixture(t, n, 3000)
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			if chain.ExtendedPairedLocalNodeCount() != n || chain.ExtendedLocalNodeCount() != n || chain.ExtendedLocalStatusLimit() < 512+1536*n {
				t.Fatal("complete original paired source was not retained")
			}
			for _, target := range []string{"windows", "linux", "darwin", "android", "ios"} {
				projected, err := ProjectNodeChain(chain, target, 1280)
				if err != nil {
					t.Fatal(target, err)
				}
				input, err := projected.LaunchInput()
				if err != nil {
					t.Fatal(target, err)
				}
				restored, err := ParseNodeChainLaunchInput(input)
				if err != nil || restored.ExtendedPairedLocalNodeCount() != n || restored.Config() != projected.Config() {
					t.Fatal(target, "lost complete original paired input", err)
				}
				plan, err := restored.PlanForMTU(restored.Config(), 1280)
				if err != nil || plan.Original != 1280 || plan.Ceiling < 1280 {
					t.Fatal(target, "lost sealed per-prefix MTU readback", err)
				}
			}
			original := chain.extendedPairedMembers[n-2]
			chain.extendedPairedMembers[n-2] = chain.nodes[0]
			if chain.ExtendedPairedLocalNodeCount() != 0 {
				t.Fatal("detached late native member retained ownership")
			}
			chain.extendedPairedMembers[n-2] = original
			for _, fault := range []string{"missing", "reordered", "layer", "remote"} {
				bad := source
				bad.IdentitySources = append([]string(nil), source.IdentitySources...)
				bad.Nodes = append([]string(nil), source.Nodes...)
				switch fault {
				case "missing":
					bad.IdentitySources = nil
				case "reordered":
					bad.IdentitySources[n-2] = source.IdentitySources[n-3]
				case "remote":
					bad.Execution = "server"
				case "layer":
					replacement := nodeChainFixtureNodes(t, n, "aes-256-gcm")[n-2]
					bad.Nodes[n-2], err = replacement.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
				}
				if got, err := NewNodeChain(startJSON(t, bad)); err == nil || got != nil {
					t.Fatal("extended source ignored", fault)
				}
			}
		})
	}
	if c, err := NewNodeChain(startJSON(t, extendedPairedFixture(t, 16, 2000))); err == nil || c != nil || !strings.Contains(err.Error(), "MTU") {
		t.Fatal("insufficient nested dual-stack envelope was admitted", err)
	}
}
