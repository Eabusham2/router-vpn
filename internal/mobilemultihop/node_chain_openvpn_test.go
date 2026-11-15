package mobilemultihop

import (
	"context"
	"net"
	"router-vpn/internal/nativeopenvpn"
	"strings"
	"testing"
)

func nodeChainOpenVPNFixture(t *testing.T, mode, network string) NodeChainSource {
	t.Helper()
	source := nodeChainImportedFixture(t, mode, "")
	graph, capture := externalTestFixture(t, "hysteria2", "")
	externalOpenVPNReplace(t, graph, capture, false, network)
	capture["profile"].(map[string]any)["endpoint"] = "203.0.113.24"
	private := capture["profile"].(map[string]any)["external"].(map[string]any)["openvpn"].(map[string]any)
	private["config"] = strings.Replace(private["config"].(string), "remote 2001:db8::24 443\n", "", 1)
	endpoint, err := nativeopenvpn.CompileEndpoint(private["config"].(string), private["username"].(string), private["password"].(string), ExternalFinalTag, "")
	if err != nil {
		t.Fatal(err)
	}
	graph["endpoints"] = []any{startObject(t, endpoint)}
	member, err := NodeChainImportedOpenVPNMemberInput(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	source.Schema = 5
	source.Nodes[1] = member
	return source
}
func TestNodeChainOpenVPNSourceAndProjection(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(mode+"/"+network, func(t *testing.T) {
				source := nodeChainOpenVPNFixture(t, mode, network)
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				capture, err := chain.OpenVPNMiddleCapture()
				if err != nil {
					t.Fatal(err)
				}
				if capture.Remote.Network != network || capture.Remote.Host != "203.0.113.24" || capture.ConfiguredMTU < 1280 || capture.Tag != chain.proofs[1].Tag {
					t.Fatal("middle capture changed", capture)
				}
				graph := startObject(t, chain.Config())
				middle := externalTestFind(t, graph, capture.Tag)
				final := externalTestFind(t, graph, chain.FinalTag())
				if middle["detour"] != chain.proofs[0].Tag || final["detour"] != capture.Tag {
					t.Fatal("detour escaped original prefix")
				}
				if len(chain.physical) != 1 || chain.proofs[1].NodeID != "" || chain.proofs[1].Kind != "public-path" {
					t.Fatal("middle borrowed physical or paired authority")
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
						t.Fatal("replay", target, err)
					}
				}
				if _, err := chain.NewCandidatePlan(0, "{}"); err == nil {
					t.Fatal("unsupported discovery admitted")
				}
			})
		}
	}
}

type nodeChainOpenVPNObserver struct {
	NodeChainEngine
	state    nativeopenvpn.PacketObservation
	err      error
	afterDNS func()
}

func (e *nodeChainOpenVPNObserver) OpenVPNMiddleStateContext(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
	return e.state, e.err
}
func TestNodeChainOpenVPNOriginalGenerationCapacity(t *testing.T) {
	source := nodeChainOpenVPNFixture(t, "wg", "udp")
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	capture, err := chain.OpenVPNMiddleCapture()
	if err != nil {
		t.Fatal(err)
	}
	original := nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: capture.Remote, Generation: 1, ConnectedAt: 1}, MTU: uint32(capture.ConfiguredMTU)}
	engine := &nodeChainOpenVPNObserver{state: original}
	if err := chain.observeOpenVPNMiddleContext(context.Background(), engine, true); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*nativeopenvpn.PacketObservation){func(s *nativeopenvpn.PacketObservation) { s.Remote.Generation++ }, func(s *nativeopenvpn.PacketObservation) { s.Remote.ConnectedAt++ }, func(s *nativeopenvpn.PacketObservation) { s.MTU++ }, func(s *nativeopenvpn.PacketObservation) { s.MTU-- }, func(s *nativeopenvpn.PacketObservation) { s.Remote.Remote.Port++ }} {
		engine.state = original
		change(&engine.state)
		if err := chain.observeOpenVPNMiddleContext(context.Background(), engine, false); err == nil {
			t.Fatal("changed native receipt accepted")
		}
	}
	engine.state = original
	if err := chain.observeOpenVPNMiddleContext(context.Background(), engine, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := chain.observeOpenVPNMiddleContext(ctx, engine, false); err == nil {
		t.Fatal("cancelled observation accepted")
	}
}

func TestNodeChainOpenVPNRuntimeRequiresOriginalNativeReceipt(t *testing.T) {
	for _, phase := range []string{"original", "missing", "prefix", "dns", "pending-cancel"} {
		t.Run(phase, func(t *testing.T) {
			source := nodeChainOpenVPNFixture(t, "wg", "tcp")
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			actual := newNodeChainTestEngine(t, chain)
			capture, _ := chain.OpenVPNMiddleCapture()
			native := &nodeChainOpenVPNObserver{NodeChainEngine: actual, state: nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: capture.Remote, Generation: 1, ConnectedAt: 1}, MTU: uint32(capture.ConfiguredMTU)}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var engine NodeChainEngine = native
			if phase == "missing" {
				engine = actual
			}
			if phase == "prefix" {
				actual.beforeDial = func(context.Context, string) (net.Conn, bool) { native.state.Remote.Generation++; return nil, false }
			}
			if phase == "dns" {
				native.afterDNS = func() { native.state.MTU++ }
			}
			if phase == "pending-cancel" {
				native.err = nativeopenvpn.ErrRemotePending
				cancel()
			}
			err = chain.Run(ctx, engine)
			if phase == "original" {
				if err != nil || !chain.Progress().Ready {
					t.Fatal("original runtime refused", err)
				}
			} else if err == nil || chain.Progress().Ready {
				t.Fatal("changed/missing native authority admitted", phase)
			}
			if phase == "missing" && (len(actual.calls) != 0 || actual.dnsCalls != 0) {
				t.Fatal("traffic before native authority")
			}
		})
	}
}

func (e *nodeChainOpenVPNObserver) DNSProofContext(ctx context.Context, capture NodeChainDNSCapture) error {
	err := e.NodeChainEngine.DNSProofContext(ctx, capture)
	if e.afterDNS != nil {
		e.afterDNS()
	}
	return err
}

func TestNodeChainOpenVPNRefusesAmbiguousOrSubstitutedSource(t *testing.T) {
	source := nodeChainOpenVPNFixture(t, "wg", "tcp")
	for _, name := range []string{"schema", "execution", "identity", "kind", "endpoint", "credentials", "layer", "multiple", "hostname", "private", "paired-authority", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			var copy NodeChainSource
			if exactJSON([]byte(startJSON(t, source)), &copy, NodeChainInputLimit) != nil {
				t.Fatal("copy")
			}
			var member nodeChainImportedInput
			if exactJSON([]byte(copy.Nodes[1]), &member, NodeChainInputLimit) != nil {
				t.Fatal("member")
			}
			cap := startObject(t, member.Capture)
			profile := cap["profile"].(map[string]any)
			switch name {
			case "schema":
				copy.Schema = 2
			case "execution":
				copy.Execution = "server"
			case "identity":
				copy.IdentitySources[1] = copy.IdentitySources[0]
			case "kind":
				member.Kind = "routervpn-node-chain-imported-member"
			case "endpoint":
				profile["endpoint"] = "203.0.113.25"
			case "credentials":
				profile["external"].(map[string]any)["openvpn"].(map[string]any)["password"] = "replacement"
			case "layer":
				profile["start_layer"] = "aes-256-gcm"
			case "paired-authority":
				profile["api_token"] = "borrowed"
			case "duplicate":
				copy.Nodes[2] = copy.Nodes[0]
				copy.IdentitySources[2] = copy.IdentitySources[0]
			case "multiple", "hostname", "private":
				private := profile["external"].(map[string]any)["openvpn"].(map[string]any)
				config := private["config"].(string)
				if name == "multiple" {
					config += "remote 203.0.113.25 1194\n"
				} else if name == "hostname" {
					config = strings.ReplaceAll(config, "203.0.113.24", "vpn.example.test")
				} else {
					config = strings.ReplaceAll(config, "203.0.113.24", "192.168.1.1")
				}
				private["config"] = config
			}
			member.Capture = startJSON(t, cap)
			copy.Nodes[1] = startJSON(t, member)
			if c, err := NewNodeChain(startJSON(t, copy)); err == nil || c != nil {
				t.Fatal("unsupported/substituted source admitted", name)
			}
		})
	}
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	chain.openVPNMiddle.selection.Profile["kill_switch_policy"] = "off"
	if _, err := chain.LaunchInput(); err == nil {
		t.Fatal("mutated original member remained sealed")
	}
}
