package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
)

// Local and Server own distinct provider usernames/passwords and pairing keys;
// the public descriptors retain equal transport policy, never shared sessions.
func nodeChainOpenVPNServerSourceFixture(t *testing.T, count int, mode, network, layer string) (NodeChainSource, NodeChainServerSource) {
	t.Helper()
	local := nodeChainOpenVPNPrefixFixture(t, count, mode, network, layer)
	if count == 6 && layer != "" {
		// The same original Local envelope must fit its captured UDP datagram.
		// Increase fixture-owned packet budgets before either role is compiled;
		// no runtime capacity is inferred from this configured value.
		for i := 0; i < count; i++ {
			node, err := ParseNodeLaunchInput(local.Nodes[i])
			if err != nil {
				t.Fatal(err)
			}
			var assets map[string]string
			if json.Unmarshal([]byte(node.inputs.Files), &assets) != nil {
				t.Fatal("packet assets")
			}
			for _, name := range []string{"wg.conf", "awg.conf"} {
				if value, ok := assets[name]; ok {
					raw := string(mustDecodeChainAsset(t, value))
					assets[name] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(raw, "MTU = 2000", "MTU = 4096", 1)))
				}
			}
			fresh, err := NewNodeProfile(node.mode, startJSON(t, assets), node.inputs.ProfileJSON, node.inputs.Start, node.inputs.DNSBootstrap)
			if err != nil {
				t.Fatal(err)
			}
			local.Nodes[i], err = fresh.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "wg" {
				local.IdentitySources[i] = fresh.inputs.Files
			}
		}
	}
	middle, err := parseNodeChainOpenVPNMember(local.Nodes[count])
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := nodeChainOpenVPNProfile(middle)
	if err != nil {
		t.Fatal(err)
	}
	serverProfile := profile
	serverProfile.Username, serverProfile.Password = "original-server-provider", "server-private-password"
	localKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{71}, 32))
	serverKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{72}, 32))
	clientPublic, err := nativeopenvpn.DescribePeer(profile, localKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := nativeopenvpn.DescribePeer(serverProfile, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if nativeopenvpn.ValidatePublicPair(clientPublic, serverPublic) != nil {
		t.Fatal("independent provider pair")
	}
	var record nodeChainImportedInput
	if json.Unmarshal([]byte(middle.input), &record) != nil {
		t.Fatal("member")
	}
	serverCapture := externalTestRead(t, record.Capture)
	serverExternal := serverCapture["profile"].(map[string]any)["external"].(map[string]any)
	serverExternal["openvpn"] = serverProfile
	serverGraph := externalTestRead(t, record.Config)
	endpoint, err := nativeopenvpn.CompileProfile(serverProfile, ExternalFinalTag, "")
	if err != nil {
		t.Fatal(err)
	}
	serverGraph["endpoints"] = []any{endpoint}
	serverMember, err := NodeChainImportedOpenVPNMemberInput(startJSON(t, serverGraph), startJSON(t, serverCapture))
	if err != nil {
		t.Fatal(err)
	}
	localCapture := externalTestRead(t, record.Capture)
	localCapture["profile"].(map[string]any)["external"].(map[string]any)["openvpn_pairing"] = nativeopenvpn.Pairing{PrivateKey: localKey, Server: serverPublic}
	local.Nodes[count], err = NodeChainImportedOpenVPNMemberInput(record.Config, startJSON(t, localCapture))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ParseNodeLaunchInput(local.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	source := NodeChainServerSource{Schema: 5, EntryID: predecessorText(entry.profile, "id"), EntryNodeID: predecessorText(entry.profile, "node_proof_id"), EntryMode: mode,
		Nodes: append([]string(nil), local.Nodes[1:]...), IdentitySources: append([]string(nil), local.IdentitySources[1:]...),
		OpenVPNPairing: &NodeChainOpenVPNServerPairing{PrivateKey: serverKey, Local: clientPublic, Server: serverPublic}}
	source.Nodes[count-1] = serverMember
	// Every paired suffix uses its independently provisioned peer assets while
	// retaining the exact original node, transport policy and final layer.
	for i := range source.Nodes {
		if i == count-1 {
			continue
		}
		node, err := ParseNodeLaunchInput(local.Nodes[i+1])
		if err != nil {
			t.Fatal(err)
		}
		bundle := nodeChainServerPlanBundle(t, node, local.IdentitySources[i+1])
		peer := nodeChainServerPlanPeerBundle(t, bundle, i+1)
		independent, err := nodeChainPlanNodeFromBundle(peer, node.profile, node.mode, node.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes[i], err = independent.node.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
		source.IdentitySources[i] = independent.identity
	}
	return local, source
}

func TestNodeChainOpenVPNServerCompleteOriginalSuffix(t *testing.T) {
	for count := 1; count <= 6; count++ {
		for _, network := range []string{"tcp", "udp"} {
			for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, network, layer), func(t *testing.T) {
					local, source := nodeChainOpenVPNServerSourceFixture(t, count, "wg", network, layer)
					if _, err := NewNodeChainServerPolicy(startJSON(t, source)); err == nil {
						t.Fatal("generic Server admitted OpenVPN")
					}
					p, err := NewNodeChainOpenVPNServerPolicy(startJSON(t, source))
					if err != nil {
						t.Fatal(err)
					}
					capture := nodeChainServerCaptureFixture(t, p)
					config, state, err := p.ReadOpenVPNServerCapture(capture)
					if err != nil {
						t.Fatal(err)
					}
					if state.Device.Position != count || state.Middle.Remote.Network != network || len(state.Proofs) != count+1 || state.Middle.Tag != state.Proofs[count-1].Tag || state.Middle.ConfiguredMTU < 1280 || p.NativeCarrierRequired() != (count > 1) {
						t.Fatal("original suffix inventory changed", state)
					}
					graph := externalTestRead(t, config)
					middle := externalTestFind(t, graph, state.Middle.Tag)
					if middle["username"] != "original-server-provider" || strings.Contains(config, "local-private-password") || middle["type"] != "openvpn-client" {
						t.Fatal("native endpoint borrowed Local credentials")
					}
					if len(graph["inbounds"].([]any)) != 0 || p.nodes[count-1] != nil {
						t.Fatal("import acquired paired or listener authority")
					}
					final := externalTestFind(t, graph, state.Proofs[count].Tag)
					if final["detour"] != state.Middle.Tag || final["udp_over_tcp"] != nil {
						t.Fatal("original packet final replaced")
					}
					if layer == "aes-256-gcm+xor-whitening" && final["type"] != "routervpn-aes-xor" {
						t.Fatal("final whitening lost")
					}
					if p.descriptor.Members[count-1].OpenVPNPairSHA256 == "" || strings.Contains(startJSON(t, p.Descriptor()), "original-server-provider") {
						t.Fatal("private pair leaked or lost")
					}
					original, err := NewNodeChain(startJSON(t, local))
					if err != nil {
						t.Fatal(err)
					}
					if original.openVPNMiddle.source == p.openvpn.middle.source {
						t.Fatal("independent source collapsed")
					}
					state.Proofs[0].Tag = "foreign"
					_, fresh, err := p.ReadOpenVPNServerCapture(capture)
					if err != nil || fresh.Proofs[0].Tag == "foreign" {
						t.Fatal("proof inventory alias")
					}
					dns, err := p.DNSCapture(capture)
					if err != nil || dns.FinalTag != fresh.Proofs[count].Tag {
						t.Fatal("selected final DNS lost")
					}
				})
			}
		}
	}
}

func TestNodeChainOpenVPNServerRefusesForeignAuthority(t *testing.T) {
	for _, fault := range []string{"schema", "missing-pair", "wrong-private-key", "same-provider", "wrong-public-key", "wrong-transport", "local-private-key", "source-position", "source-identity", "copied-scope", "copied-middle", "copied-final", "changed-config", "lost-scope", "pair-digest", "foreign-capture"} {
		t.Run(fault, func(t *testing.T) {
			_, source := nodeChainOpenVPNServerSourceFixture(t, 2, "wg", "udp", "")
			p, err := NewNodeChainOpenVPNServerPolicy(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			capture := nodeChainServerCaptureFixture(t, p)
			mutatedSource := true
			switch fault {
			case "schema":
				source.Schema = 3
			case "missing-pair":
				source.OpenVPNPairing = nil
			case "wrong-private-key":
				source.OpenVPNPairing.PrivateKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{73}, 32))
			case "same-provider":
				source.OpenVPNPairing.Local.ProviderIdentity = source.OpenVPNPairing.Server.ProviderIdentity
			case "wrong-public-key":
				source.OpenVPNPairing.Server.PairingPublicKey = source.OpenVPNPairing.Local.PairingPublicKey
			case "wrong-transport":
				source.OpenVPNPairing.Local.Transport["mtu"] = float64(9000)
			case "local-private-key":
				var record nodeChainImportedInput
				_ = json.Unmarshal([]byte(source.Nodes[1]), &record)
				selected := externalTestRead(t, record.Capture)
				selected["profile"].(map[string]any)["external"].(map[string]any)["openvpn_pairing"] = nativeopenvpn.Pairing{PrivateKey: source.OpenVPNPairing.PrivateKey, Server: source.OpenVPNPairing.Local}
				record.Capture = startJSON(t, selected)
				source.Nodes[1] = startJSON(t, record)
			case "source-position":
				source.Nodes[0], source.Nodes[1] = source.Nodes[1], source.Nodes[0]
			case "source-identity":
				source.IdentitySources[1] = source.IdentitySources[0]
			default:
				mutatedSource = false
			}
			if mutatedSource {
				if _, err := NewNodeChainOpenVPNServerPolicy(startJSON(t, source)); err == nil {
					t.Fatal("foreign original source accepted")
				}
				return
			}
			switch fault {
			case "copied-scope":
				copy := *p.openvpn
				p.openvpn = &copy
			case "copied-middle":
				copy := *p.openvpn.middle
				p.openvpn.middle = &copy
			case "copied-final":
				copy := *p.nodes[2]
				p.nodes[2] = &copy
			case "changed-config":
				p.config += " "
			case "lost-scope":
				p.openvpn = nil
			case "pair-digest":
				p.openvpn.pairSHA = strings.Repeat("f", 64)
			case "foreign-capture":
				capture.Source.Members[1].OpenVPNPairSHA256 = strings.Repeat("f", 64)
			}
			if _, _, err := p.ReadOpenVPNServerCapture(capture); err == nil {
				t.Fatal("foreign owner accepted")
			}
		})
	}
}

// This engine doubles endpoint observation only. The original Server proof
// implementation still performs actual authenticated HTTP and verified TLS,
// exact selected DNS ownership and joined connection closure.
type nodeChainOpenVPNServerProofEngine struct {
	*nodeChainServerProofTestEngine
	state  nativeopenvpn.PacketObservation
	tag    string
	reads  int
	change func(*nodeChainOpenVPNServerProofEngine)
}

func (e *nodeChainOpenVPNServerProofEngine) OpenVPNMiddleStateContext(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
	e.reads++
	if e.change != nil {
		e.change(e)
	}
	if tag != e.tag || ctx.Err() != nil {
		return nativeopenvpn.PacketObservation{}, errors.New("original native middle lost")
	}
	return e.state, nil
}
func TestNodeChainOpenVPNServerRequiresConnectedNativeProof(t *testing.T) {
	for _, fault := range []string{"none", "missing-observer", "missing-state", "wrong-remote", "capacity", "generation", "connected-at", "capacity-change", "dns", "source", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			_, source := nodeChainOpenVPNServerSourceFixture(t, 2, "awg2-strong", "udp", "aes-256-gcm+xor-whitening")
			p, err := NewNodeChainOpenVPNServerPolicy(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			capture := nodeChainServerCaptureFixture(t, p)
			_, state, err := p.ReadOpenVPNServerCapture(capture)
			if err != nil {
				t.Fatal(err)
			}
			original := newNodeChainServerProofTestEngine(t, p, capture)
			e := &nodeChainOpenVPNServerProofEngine{nodeChainServerProofTestEngine: original, tag: state.Middle.Tag, state: nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: state.Middle.Remote, Generation: 1, ConnectedAt: 1}, MTU: uint32(state.Middle.ConfiguredMTU)}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var owner NodeChainServerProofEngine = e
			switch fault {
			case "missing-observer":
				owner = original
			case "missing-state":
				e.state = nativeopenvpn.PacketObservation{}
			case "wrong-remote":
				e.state.Remote.Remote.Port++
			case "capacity":
				e.state.MTU--
			case "generation":
				e.change = func(e *nodeChainOpenVPNServerProofEngine) {
					if e.reads == 3 {
						e.state.Remote.Generation++
					}
				}
			case "connected-at":
				e.change = func(e *nodeChainOpenVPNServerProofEngine) {
					if e.reads == 3 {
						e.state.Remote.ConnectedAt++
					}
				}
			case "capacity-change":
				e.change = func(e *nodeChainOpenVPNServerProofEngine) {
					if e.reads == 3 {
						e.state.MTU++
					}
				}
			case "dns":
				original.dnsFail = true
			case "source":
				original.changeOnPublic = true
			case "cancelled":
				cancel()
			}
			proof, err := p.prove(ctx, capture, owner, original.trust)
			if fault == "none" {
				if err != nil || !proof.DNSProven || !proof.PublicProven || len(proof.Prefixes) != 3 || e.reads < 8 {
					t.Fatal("actual proof omitted original connected owner", proof, e.reads, err)
				}
			} else if err == nil || !reflect.DeepEqual(proof, NodeChainServerProofResult{}) {
				t.Fatal("foreign native state published partial proof", fault, proof, err)
			}
		})
	}
}

// Reusable actual bundle/capture fixture for native and mobile source consumers.
// Both roles are independently compiled from original assets; neither source
// borrows a descriptor, provider password or packet identity from the other.
func nodeChainOpenVPNServerPlanFixture(t *testing.T, count int, mode, network, layer string) (NodeChainSource, map[string]any) {
	t.Helper()
	local, server := nodeChainOpenVPNServerSourceFixture(t, count, mode, network, layer)
	entry, err := ParseNodeLaunchInput(local.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	selection := func(node *NodeProfile, identity string) map[string]any {
		return map[string]any{"bundle": nodeChainServerPlanBundle(t, node, identity), "profile_id": node.profile["id"], "mode": node.mode}
	}
	plan := map[string]any{"schema": float64(5), "entry_node_id": entry.profile["node_proof_id"], "entry": selection(entry, local.IdentitySources[0])}
	rows := []any{}
	for i := 1; i < len(local.Nodes); i++ {
		if i == count {
			var l, s nodeChainImportedInput
			if json.Unmarshal([]byte(local.Nodes[i]), &l) != nil || json.Unmarshal([]byte(server.Nodes[i-1]), &s) != nil {
				t.Fatal("original OpenVPN captures")
			}
			rows = append(rows, map[string]any{"openvpn": map[string]any{"local": map[string]any{"config": l.Config, "capture": l.Capture}, "server": map[string]any{"config": s.Config, "capture": s.Capture}, "pairing": server.OpenVPNPairing}})
			continue
		}
		original, err := ParseNodeLaunchInput(local.Nodes[i])
		if err != nil {
			t.Fatal(err)
		}
		peer, err := ParseNodeLaunchInput(server.Nodes[i-1])
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, map[string]any{"paired": selection(original, local.IdentitySources[i]), "server_peer": map[string]any{"bundle": nodeChainServerPlanBundle(t, peer, server.IdentitySources[i-1]), "profile_id": peer.profile["id"]}})
	}
	plan["members"] = rows
	return local, plan
}
func TestNodeChainOpenVPNServerPlanIndependentOriginalPair(t *testing.T) {
	for i, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, network := range []string{"tcp", "udp"} {
			for _, count := range []int{1, 6} {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, network, count), func(t *testing.T) {
					layer := []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[i]
					local, plan := nodeChainOpenVPNServerPlanFixture(t, count, mode, network, layer)
					original := startJSON(t, plan)
					policy, err := NewNodeChainOpenVPNServerPlan(original)
					if err != nil {
						t.Fatal("independent original plan", err)
					}
					if _, err := NewNodeChainServerPlan(original); err == nil {
						t.Fatal("generic plan gained native authority")
					}
					if _, err := NewNodeChain(startJSON(t, local)); err != nil {
						t.Fatal(err)
					}
					if startJSON(t, plan) != original || policy.Descriptor().Schema != 5 || policy.Descriptor().Members[count-1].OpenVPNPairSHA256 == "" {
						t.Fatal("original pair changed")
					}
					replay, err := NewNodeChainOpenVPNServerPolicy(policy.Source())
					if err != nil || !reflect.DeepEqual(replay.Descriptor(), policy.Descriptor()) {
						t.Fatal("private original source replay changed", err)
					}
				})
			}
		}
	}
}
func TestNodeChainOpenVPNServerPlanRefusesRoleSubstitution(t *testing.T) {
	for _, fault := range []string{"local-as-server", "server-as-local", "pair-key", "pair-descriptor", "position", "ordinary-import", "schema", "borrowed-packet", "borrowed-final", "unknown-field"} {
		t.Run(fault, func(t *testing.T) {
			_, fixture := nodeChainOpenVPNServerPlanFixture(t, 2, "wg", "tcp", "")
			plan := externalTestRead(t, startJSON(t, fixture))
			rows := plan["members"].([]any)
			middle := rows[1].(map[string]any)["openvpn"].(map[string]any)
			switch fault {
			case "local-as-server":
				middle["server"] = middle["local"]
			case "server-as-local":
				middle["local"] = middle["server"]
			case "pair-key":
				middle["pairing"].(map[string]any)["private_key"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{73}, 32))
			case "pair-descriptor":
				middle["pairing"].(map[string]any)["local"] = middle["pairing"].(map[string]any)["server"]
			case "position":
				rows[0], rows[1] = rows[1], rows[0]
			case "ordinary-import":
				rows[1] = map[string]any{"imported": middle["local"]}
			case "schema":
				plan["schema"] = float64(1)
			case "borrowed-packet", "borrowed-final":
				i := 0
				if fault == "borrowed-final" {
					i = 2
				}
				row := rows[i].(map[string]any)
				paired := row["paired"].(map[string]any)
				row["server_peer"] = map[string]any{"bundle": paired["bundle"], "profile_id": paired["profile_id"]}
			case "unknown-field":
				middle["pairing"].(map[string]any)["private_local_key"] = "secret"
			}
			if _, err := NewNodeChainOpenVPNServerPlan(startJSON(t, plan)); err == nil {
				t.Fatal("substituted native role admitted")
			}
		})
	}
}

func TestNodeChainOpenVPNPairingFieldCannotEnterOtherFamilies(t *testing.T) {
	for _, schema := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			var policy *NodeChainServerPolicy
			var err error
			switch schema {
			case 1:
				policy, _ = nodeChainServerFixture(t, 3, "")
			case 2:
				_, policy, _ = nodeChainImportedServerFixture(t, "wg", "")
			case 3:
				_, plan := socksExecutionPrefixPlanFixture(t, 3, "wg", "password")
				policy, err = NewNodeChainSOCKSServerPlan(startJSON(t, plan))
			case 4:
				plan := connectServerPlanFixture(t, "wg", "http-connect")
				policy, err = NewNodeChainCONNECTServerPlan(startJSON(t, plan))
			}
			if err != nil || policy == nil {
				t.Fatal(err)
			}
			source := externalTestRead(t, policy.Source())
			source["openvpn_pairing"] = nil
			_, err = newNodeChainServerPolicyFamily(startJSON(t, source), nil, map[int]int{1: 0, 2: 0, 3: 3, 4: 4}[schema])
			if err == nil {
				t.Fatal("foreign typed pairing field entered original family")
			}
		})
	}
}
