package mobilemultihop

import (
	"errors"
	"reflect"
	"router-vpn/internal/multihoprelay"
	"testing"
)

func socksServerFixture(t *testing.T, mode, authentication string) (*NodeChainSOCKSSource, *NodeChainServerPolicy, multihoprelay.NodeChainCapture) {
	t.Helper()
	local := nodeChainSOCKSFixture(t, mode, "", authentication)
	original, err := NewNodeChainSOCKSSource(startJSON(t, local))
	if err != nil {
		t.Fatal(err)
	}
	source := NodeChainServerSource{Schema: 3, EntryID: original.metadata.Proofs[0].ProfileID, EntryNodeID: original.metadata.Proofs[0].NodeID, EntryMode: mode, Nodes: append([]string(nil), local.Nodes[1:]...), IdentitySources: append([]string(nil), local.IdentitySources[1:]...)}
	if _, err := NewNodeChainServerPolicy(startJSON(t, source)); err == nil {
		t.Fatal("generic server admitted SOCKS")
	}
	if _, err := NewNodeChainCONNECTServerPolicy(startJSON(t, source)); err == nil {
		t.Fatal("CONNECT server admitted SOCKS")
	}
	server, err := NewNodeChainSOCKSServerPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal("typed SOCKS suffix", err)
	}
	return original, server, nodeChainServerCaptureFixture(t, server)
}

func TestNodeChainSOCKSServerRetainsOriginalAssociationSuffix(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, auth := range []string{"password", "none"} {
			t.Run(mode+"/"+auth, func(t *testing.T) {
				original, p, capture := socksServerFixture(t, mode, auth)
				config, err := p.NativeConfig(capture)
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, config)
				proofs := p.ProofInventory()
				if len(graph["inbounds"].([]any)) != 0 || len(graph["endpoints"].([]any)) != 0 || len(proofs) != 2 || p.NativeCarrierRequired() || p.nodes[0] != nil || p.socks.middle.input != original.middle.input {
					t.Fatal("suffix manufactured a packet owner or changed original import")
				}
				middle, final := externalTestFind(t, graph, proofs[0].Tag), externalTestFind(t, graph, proofs[1].Tag)
				if middle["type"] != "socks" || middle["version"] != "5" || middle["detour"] != nil || middle["udp_over_tcp"] != nil || final["detour"] != proofs[0].Tag || final["udp_over_tcp"] != nil || final["type"] != "shadowsocks" || proofs[0].NodeID != "" || proofs[0].Mode != "socks5" {
					t.Fatal("SOCKS association acquired CONNECT UoT or invented identity")
				}
				if _, err := compiledPhysicalEgress(config, []string{"tcp", "udp"}); !errors.Is(err, ErrDynamicPhysicalEgress) {
					t.Fatal("generic fixed egress accepted a negotiated relay", err)
				}
				dns, err := p.DNSCapture(capture)
				if err != nil || dns.FinalTag != proofs[1].Tag {
					t.Fatal("final DNS changed", err)
				}
				targets, err := p.ProofTargets(capture)
				if err != nil || targets[0].Token != "" || targets[0].ExpectedPublicIP != original.middle.selection.ExpectedPublicIP || targets[1].Token == "" {
					t.Fatal("public/private proof authority changed", err)
				}
				device, err := p.SOCKSServerDevice(capture)
				if err != nil || device.ProfileID != proofs[0].ProfileID || device.IPv6Mode != "off" || device.KillSwitchPolicy != "always" {
					t.Fatal("original device policy changed", err)
				}
				routes, err := p.FrontRoutes(capture)
				if err != nil || routes[0].Final || routes[0].AllowsDestination("udp", "1.1.1.1:443") || !routes[1].Final || routes[1].UDPOverTCPVersion != 2 {
					t.Fatal("authenticated front scope changed", err)
				}
				// The private client/server front retains its own UoT contract. It must not
				// convert the independently captured external SOCKS middle/final graph.
				if !reflect.DeepEqual(p.Descriptor().Members, capture.Source.Members) {
					t.Fatal("descriptor changed")
				}
			})
		}
	}
}
func TestNodeChainSOCKSServerRejectsChangedOriginalAuthority(t *testing.T) {
	for _, fault := range []string{"schema", "extra-member", "middle-identity", "missing-final-identity", "reordered", "entry-as-suffix", "foreign-final-identity", "copied-scope", "foreign-middle", "foreign-final", "changed-config", "lost-scope", "uot-final"} {
		t.Run(fault, func(t *testing.T) {
			original, p, capture := socksServerFixture(t, "wg", "password")
			var source NodeChainServerSource
			if exactJSON([]byte(p.Source()), &source, NodeChainInputLimit) != nil {
				t.Fatal("source")
			}
			sourceFault := true
			switch fault {
			case "schema":
				source.Schema = 4
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
				if _, err := NewNodeChainSOCKSServerPolicy(startJSON(t, source)); err == nil {
					t.Fatal("changed suffix admitted")
				}
				return
			}
			switch fault {
			case "copied-scope":
				copy := *p.socks
				p.socks = &copy
			case "foreign-middle":
				fresh, err := parseNodeChainSOCKSMember(p.socks.middle.input)
				if err != nil {
					t.Fatal(err)
				}
				p.socks.middle = fresh
			case "foreign-final":
				fresh, err := ParseNodeLaunchInput(source.Nodes[1])
				if err != nil {
					t.Fatal(err)
				}
				p.nodes[1] = fresh
			case "changed-config":
				p.config += " "
			case "lost-scope":
				p.socks = nil
			case "uot-final":
				graph := externalTestRead(t, p.config)
				externalTestFind(t, graph, p.proofs[1].Tag)["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
				p.config = startJSON(t, graph)
			}
			if _, err := p.NativeConfig(capture); err == nil {
				t.Fatal("foreign native suffix authority accepted")
			}
		})
	}
}
