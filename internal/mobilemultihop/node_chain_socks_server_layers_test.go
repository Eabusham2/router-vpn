package mobilemultihop

import (
	"reflect"
	"testing"
)

func socksServerLayerFixture(t *testing.T, mode, entryLayer, finalLayer string) (*NodeChainSOCKSSource, *NodeChainServerPolicy) {
	t.Helper()
	entryInput, finalInput := entryLayer, finalLayer
	if entryInput == "off" {
		entryInput = ""
	}
	if finalInput == "off" {
		finalInput = ""
	}
	source := nodeChainSOCKSFixture(t, mode, entryInput, "password")
	final := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "shadowsocks"}, []string{"", "", finalInput})[2]
	var err error
	source.Nodes[2], err = final.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	original, err := NewNodeChainSOCKSSource(startJSON(t, source))
	if err != nil {
		t.Fatal("independent original SOCKS layers", err)
	}
	suffix := NodeChainServerSource{Schema: 3, EntryID: original.metadata.Proofs[0].ProfileID, EntryNodeID: original.metadata.Proofs[0].NodeID, EntryMode: mode, Nodes: source.Nodes[1:], IdentitySources: source.IdentitySources[1:]}
	encoded := startJSON(t, suffix)
	if _, err = NewNodeChainServerPolicy(encoded); err == nil {
		t.Fatal("generic parser admitted typed layered SOCKS")
	}
	if _, err = NewNodeChainCONNECTServerPolicy(encoded); err == nil {
		t.Fatal("CONNECT parser admitted typed layered SOCKS")
	}
	p, err := NewNodeChainSOCKSServerPolicy(encoded)
	if err != nil {
		t.Fatal("original layered SOCKS suffix refused", err)
	}
	return original, p
}

func TestNodeChainSOCKSServerIndependentFinalLayers(t *testing.T) {
	layers := []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"}
	for i, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for j, finalLayer := range layers {
			entryLayer := layers[(i+j+1)%len(layers)]
			t.Run(mode+"/"+finalLayer, func(t *testing.T) {
				original, p := socksServerLayerFixture(t, mode, entryLayer, finalLayer)
				lease := nodeChainServerCaptureFixture(t, p)
				config, err := p.NativeConfig(lease)
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, config)
				proofs := p.ProofInventory()
				kind := "shadowsocks"
				if finalLayer == "aes-256-gcm+xor-whitening" {
					kind = "routervpn-aes-xor"
				}
				final := externalTestFind(t, graph, proofs[1].Tag)
				if len(proofs) != 2 || proofs[1].StartLayer != finalLayer || original.metadata.Proofs[0].StartLayer != entryLayer || final["type"] != kind || final["detour"] != proofs[0].Tag || final["udp_over_tcp"] != nil || final["method"] != NativeStartLayerMethod || len(graph["outbounds"].([]any)) != 2 || p.NativeCarrierRequired() {
					t.Fatal("layered suffix changed original layer or negotiated UDP authority")
				}
				dns, err := p.DNSCapture(lease)
				if err != nil || dns.FinalTag != proofs[1].Tag {
					t.Fatal("layered suffix lost final DNS", err)
				}
				targets, err := p.ProofTargets(lease)
				if err != nil || targets[1].Token == "" || targets[1].Proof.NodeID != proofs[1].NodeID {
					t.Fatal("layered suffix lost final proof", err)
				}
				for _, execution := range []string{"server", "auto"} {
					prep, err := NewNodeChainSOCKSExecutionPreparation(original, execution)
					if err != nil {
						t.Fatal("typed layered preparation", err)
					}
					reopened, err := ParseNodeChainSOCKSExecutionPreparation(prep.Source())
					if err != nil || reopened.Config() != prep.Config() {
						t.Fatal("typed layer restore changed source", err)
					}
					before, after := externalTestRead(t, original.config), externalTestRead(t, prep.Config())
					for _, proof := range original.metadata.Proofs {
						if !reflect.DeepEqual(externalTestFind(t, before, proof.Tag), externalTestFind(t, after, proof.Tag)) {
							t.Fatal("preparation replaced original layered member")
						}
					}
				}
			})
		}
	}
}

func TestNodeChainSOCKSServerLayerAuthorityRefusals(t *testing.T) {
	for _, fault := range []string{"foreign-final", "copied-scope", "final-type", "uot", "password", "layer", "detour"} {
		t.Run(fault, func(t *testing.T) {
			_, p := socksServerLayerFixture(t, "wg", "aes-256-gcm", "aes-256-gcm+xor-whitening")
			lease := nodeChainServerCaptureFixture(t, p)
			switch fault {
			case "foreign-final":
				input, _ := p.socks.final.LaunchInput()
				foreign, err := ParseNodeLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
				p.nodes[1] = foreign
			case "copied-scope":
				copied := *p.socks
				p.socks = &copied
			case "layer":
				p.socks.final.profile["start_layer"] = "off"
			default:
				graph := externalTestRead(t, p.config)
				final := externalTestFind(t, graph, p.proofs[1].Tag)
				switch fault {
				case "final-type":
					final["type"] = "shadowsocks"
				case "uot":
					final["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
				case "password":
					final["password"] = "foreign"
				case "detour":
					delete(final, "detour")
				}
				p.config = startJSON(t, graph)
			}
			if _, err := p.NativeConfig(lease); err == nil {
				t.Fatal("changed layered suffix authority accepted")
			}
		})
	}
}
