package mobilemultihop

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nodeChainOpenVPNPrefixFixture(t *testing.T, prefixes int, mode, network, layer string) NodeChainSource {
	t.Helper()
	original := nodeChainOpenVPNFixture(t, mode, network)
	if prefixes == 1 && layer == "" {
		return original
	}
	source := nodeChainSOCKSPrefixFixture(t, prefixes, mode, layer, "password")
	source.Schema, source.Nodes[prefixes] = 5, original.Nodes[1]
	return source
}

func TestNodeChainOpenVPNCompletePacketPrefixes(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, network := range []string{"tcp", "udp"} {
			for count := 1; count <= 6; count++ {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, network, count), func(t *testing.T) {
					source := nodeChainOpenVPNPrefixFixture(t, count, mode, network, "")
					chain, err := NewNodeChain(startJSON(t, source))
					if err != nil {
						t.Fatal(err)
					}
					capture, err := chain.OpenVPNMiddleCapture()
					if err != nil {
						t.Fatal(err)
					}
					if capture.Tag != chain.proofs[count].Tag || capture.Remote.Network != network || len(chain.proofs) != count+2 || len(chain.physical) != 1 {
						t.Fatal("original path inventory changed")
					}
					graph := startObject(t, chain.Config())
					for i, proof := range chain.proofs {
						endpoint := externalTestFind(t, graph, proof.Tag)
						if i > 0 && endpoint["detour"] != chain.proofs[i-1].Tag {
							t.Fatal("original prefix bypassed", i)
						}
						if i < count && proof.Mode != mode {
							t.Fatal("original packet owner lost", i)
						}
					}
					tag, _, err := chain.PublicMeasurementCapture()
					if err != nil || tag != capture.Tag {
						t.Fatal("public capture not original penultimate", err)
					}
					bound, err := chain.MTUPlan()
					if err != nil || len(bound.Prefixes) != count+2 {
						t.Fatal("per-member MTU lost", err)
					}
					if _, err := chain.PlanForMTU(chain.Config(), bound.Original); err != nil {
						t.Fatal(err)
					}
					replay, err := NewNodeChain(startJSON(t, source))
					if err != nil || replay.Config() != chain.Config() || replay.Metadata() != chain.Metadata() {
						t.Fatal("serialized replay changed", err)
					}
					for _, target := range []string{"android", "ios", "linux", "darwin", "windows"} {
						projected, err := ProjectNodeChain(chain, target, 1280)
						if err != nil {
							t.Fatal(target, err)
						}
						launch, err := projected.LaunchInput()
						if err != nil {
							t.Fatal(err)
						}
						reopened, err := ParseNodeChainLaunchInput(launch)
						if err != nil || reopened.Config() != projected.Config() {
							t.Fatal("projection replay", target, err)
						}
					}
					for _, target := range []string{"linux", "darwin", "windows"} {
						policy, err := NewDesktopNodeChainPolicy(chain, strings.Repeat("a", 32), target, 0)
						if err != nil {
							t.Fatal(target, err)
						}
						_, meta, physical, err := policy.ReadValidated()
						if err != nil || len(meta.Prefixes) != count+2 || len(physical.PhysicalRoots) != 1 || meta.NodeID != chain.proofs[count+1].NodeID {
							t.Fatal("desktop original owner changed", target, err)
						}
					}
				})
			}
		}
	}
}

func TestNodeChainOpenVPNPrefixOriginalPointers(t *testing.T) {
	for position := 0; position < 8; position++ {
		t.Run(fmt.Sprint(position), func(t *testing.T) {
			chain, err := NewNodeChain(startJSON(t, nodeChainOpenVPNPrefixFixture(t, 6, "wg", "udp", "")))
			if err != nil {
				t.Fatal(err)
			}
			if position == 6 {
				copy := *chain.openVPNMiddle
				chain.openVPNMiddle = &copy
			} else {
				copy := *chain.nodes[position]
				chain.nodes[position] = &copy
			}
			if chain.validateCapture() == nil {
				t.Fatal("equivalent foreign OpenVPN path owner accepted")
			}
			if _, err := chain.OpenVPNMiddleCapture(); err == nil {
				t.Fatal("foreign pointer acquired native observation authority")
			}
		})
	}
	t.Run("whole-source", func(t *testing.T) {
		chain, err := NewNodeChain(startJSON(t, nodeChainOpenVPNPrefixFixture(t, 2, "wg", "tcp", "")))
		if err != nil {
			t.Fatal(err)
		}
		copy := *chain
		if copy.validateCapture() == nil {
			t.Fatal("equivalent foreign OpenVPN path owner accepted")
		}
	})
}

func TestNodeChainOpenVPNPrefixSourceRefusals(t *testing.T) {
	for _, name := range []string{"missing-identity", "middle-identity", "reordered-identities", "duplicate-prefix", "missing-prefix", "wrong-position", "second-import", "wrong-schema", "server", "compare", "wrong-final"} {
		t.Run(name, func(t *testing.T) {
			source := nodeChainOpenVPNPrefixFixture(t, 6, "wg", "udp", "")
			switch name {
			case "missing-identity":
				source.IdentitySources[3] = ""
			case "middle-identity":
				source.IdentitySources[6] = source.IdentitySources[0]
			case "reordered-identities":
				source.IdentitySources[1], source.IdentitySources[3] = source.IdentitySources[3], source.IdentitySources[1]
			case "duplicate-prefix":
				source.Nodes[3] = source.Nodes[1]
			case "missing-prefix":
				source.Nodes = append(source.Nodes[:2], source.Nodes[3:]...)
			case "wrong-position":
				source.Nodes[1], source.Nodes[6] = source.Nodes[6], source.Nodes[1]
			case "second-import":
				source.Nodes[3] = source.Nodes[6]
			case "wrong-schema":
				source.Schema = 2
			case "server":
				source.Execution = "server"
			case "compare":
				source.Execution = "compare"
			case "wrong-final":
				source.Nodes[7] = source.Nodes[2]
			}
			if _, err := NewNodeChain(startJSON(t, source)); err == nil {
				t.Fatal("malformed original OpenVPN prefix accepted", name)
			}
		})
	}
	t.Run("trio-byte-replay", func(t *testing.T) {
		old := nodeChainOpenVPNFixture(t, "wg", "tcp")
		current := nodeChainOpenVPNPrefixFixture(t, 1, "wg", "tcp", "")
		if !reflect.DeepEqual(old, current) {
			t.Fatal("original trio bytes changed")
		}
	})
}
