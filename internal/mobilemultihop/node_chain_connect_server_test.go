package mobilemultihop

import (
	"reflect"
	"router-vpn/internal/multihoprelay"
	"testing"
)

func connectServerFixture(t *testing.T, mode, protocol string) (*NodeChainCONNECTSource, *NodeChainExecutionPreparation, *NodeChainServerPolicy, multihoprelay.NodeChainCapture) {
	t.Helper()
	original, prep := connectExecutionPreparationFixture(t, mode, protocol, "server")
	var local NodeChainSource
	if exactJSON([]byte(original.sourceJSON), &local, NodeChainInputLimit) != nil {
		t.Fatal("original source")
	}
	source := NodeChainServerSource{Schema: 4, EntryID: original.metadata.Proofs[0].ProfileID, EntryNodeID: original.metadata.Proofs[0].NodeID, EntryMode: mode, Nodes: append([]string(nil), local.Nodes[1:]...), IdentitySources: append([]string(nil), local.IdentitySources[1:]...)}
	if _, err := NewNodeChainServerPolicy(startJSON(t, source)); err == nil {
		t.Fatal("generic server admitted CONNECT")
	}
	server, err := NewNodeChainCONNECTServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal("typed CONNECT suffix", err)
	}
	return original, prep, server, nodeChainServerCaptureFixture(t, server)
}

func TestNodeChainCONNECTServerRetainsOriginalStreamSuffix(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			t.Run(mode+"/"+protocol, func(t *testing.T) {
				original, prep, server, capture := connectServerFixture(t, mode, protocol)
				config, err := server.NativeConfig(capture)
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, config)
				if len(graph["endpoints"].([]any)) != 0 || len(graph["inbounds"].([]any)) != 0 || server.NativeCarrierRequired() || server.nodes[0] != nil || server.connect.middle.input != original.middle.input {
					t.Fatal("CONNECT suffix invented a packet lower or replaced import")
				}
				proofs := server.ProofInventory()
				middle := externalTestFind(t, graph, proofs[0].Tag)
				final := externalTestFind(t, graph, proofs[1].Tag)
				if middle["type"] != "http" || middle["detour"] != nil || final["detour"] != proofs[0].Tag || final["udp_over_tcp"] == nil || proofs[0].NodeID != "" || proofs[0].Mode != protocol {
					t.Fatal("remote stream transport authority changed")
				}
				dns, err := server.DNSCapture(capture)
				if err != nil || dns.FinalTag != proofs[1].Tag {
					t.Fatal("selected DNS", err)
				}
				targets, err := server.ProofTargets(capture)
				if err != nil || targets[0].Token != "" || targets[0].ExpectedPublicIP != original.middle.selection.ExpectedPublicIP || targets[1].Token == "" {
					t.Fatal("public/private proof", err)
				}
				routes, err := server.FrontRoutes(capture)
				if err != nil || routes[0].AllowsDestination("udp", "1.1.1.1:443") || routes[0].Final || !routes[1].Final || routes[1].UDPOverTCPVersion != 2 {
					t.Fatal("front scoping", err)
				}
				request := capture.Request.Clone()
				key, err := original.pair.nodes[0].PacketClientPublicKey()
				if err != nil {
					t.Fatal(err)
				}
				request.LocalPacketPublicKeys = []string{key}
				request.Peer = "10.80.0.2"
				request.Port = 32003
				input := NodeChainExecutionSource{Schema: 4, Execution: "server", LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
				if _, err := NewNodeChainExecutionPolicy(startJSON(t, input)); err == nil {
					t.Fatal("generic execution admitted CONNECT")
				}
				policy, err := NewNodeChainCONNECTExecutionPolicy(prep, startJSON(t, input))
				if err != nil {
					t.Fatal("typed execution", err)
				}
				if policy.local != prep.local || policy.connect != prep.connect || !reflect.DeepEqual(policy.local.proofs, original.metadata.Proofs) {
					t.Fatal("execution replaced original Local owners")
				}

				projection, err := prep.BindExecution(policy)
				if err != nil {
					t.Fatal("bind original execution", err)
				}
				bound, err := projection.MTUPlan()
				if err != nil || bound.Ceiling != original.metadata.MTU.Ceiling {
					t.Fatal("original configured MTU", err)
				}
				changed := externalTestRead(t, projection.Config())
				changed["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(bound.Ceiling)
				if _, err = projection.PlanForMTU(startJSON(t, changed), bound.Ceiling); err != nil {
					t.Fatal("actual-only MTU projection", err)
				}
				externalTestFind(t, changed, original.metadata.Proofs[1].Tag)["password"] = "foreign"
				if _, err = projection.PlanForMTU(startJSON(t, changed), bound.Ceiling); err == nil {
					t.Fatal("MTU projection changed original CONNECT credential")
				}

			})
		}
	}
}

func TestNodeChainCONNECTServerRejectsForeignAndChangedCapture(t *testing.T) {
	for _, fault := range []string{"ss-schema", "extra-member", "middle-identity", "missing-final-identity", "reordered", "entry-as-suffix", "foreign-final-identity", "copied-scope", "foreign-middle-pointer", "foreign-final-pointer", "changed-config", "lost-scope"} {
		t.Run(fault, func(t *testing.T) {
			original, _, p, capture := connectServerFixture(t, "wg", "https-connect")
			var source NodeChainServerSource
			if exactJSON([]byte(p.Source()), &source, NodeChainInputLimit) != nil {
				t.Fatal("source")
			}
			sourceFault := true
			switch fault {
			case "ss-schema":
				source.Schema = 2
			case "extra-member":
				source.Nodes = append(source.Nodes, source.Nodes[1])
				source.IdentitySources = append(source.IdentitySources, source.IdentitySources[1])
			case "middle-identity":
				source.IdentitySources[0] = source.IdentitySources[1]
			case "missing-final-identity":
				source.IdentitySources[1] = ""
			case "reordered":
				source.Nodes[0], source.Nodes[1] = source.Nodes[1], source.Nodes[0]
			case "entry-as-suffix":
				source.Nodes[0], _ = original.pair.nodes[0].LaunchInput()
				source.IdentitySources[0] = original.pair.nodes[0].inputs.Files
			case "foreign-final-identity":
				source.IdentitySources[1] = original.pair.nodes[0].inputs.Files
			default:
				sourceFault = false
			}
			if sourceFault {
				if _, err := NewNodeChainCONNECTServerPolicy(startJSON(t, source)); err == nil {
					t.Fatal("foreign suffix source accepted", fault)
				}
				return
			}
			switch fault {
			case "copied-scope":
				copy := *p.connect
				p.connect = &copy
			case "foreign-middle-pointer":
				fresh, err := parseNodeChainCONNECTMember(p.connect.middle.input)
				if err != nil {
					t.Fatal(err)
				}
				p.connect.middle = fresh
			case "foreign-final-pointer":
				fresh, err := ParseNodeLaunchInput(source.Nodes[1])
				if err != nil {
					t.Fatal(err)
				}
				p.nodes[1] = fresh
			case "changed-config":
				p.config += " "
			case "lost-scope":
				p.connect = nil
			}
			if _, err := p.NativeConfig(capture); err == nil {
				t.Fatal("replaced original suffix authority accepted", fault)
			}
		})
	}
}

func connectExecutionFixtureSource(t *testing.T, execution string) NodeChainExecutionSource {
	t.Helper()
	original, _, server, capture := connectServerFixture(t, "wg", "https-connect")
	request := capture.Request.Clone()
	key, err := original.pair.nodes[0].PacketClientPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	request.LocalPacketPublicKeys = []string{key}
	request.Peer = "10.80.0.2"
	request.Port = 32003
	return NodeChainExecutionSource{Schema: 4, Execution: execution, LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
}
