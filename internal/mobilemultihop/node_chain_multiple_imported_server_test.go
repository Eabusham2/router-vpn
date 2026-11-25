package mobilemultihop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

var multipleImportedServerLayouts = append(append([]nodeChainImportedLayout(nil), nodeChainImportedLayouts...),
	nodeChainImportedLayout{"packet-first", 5, []int{2, 3}}, nodeChainImportedLayout{"first-import-then-packet", 4, []int{1}})

// Preserve complete Local originals and independently provision each paired
// Server peer. Imported rows retain their literal source without Router API or
// packet identity. This exports no transport readiness or measured capacity.
func multipleImportedServerPlanFixture(t *testing.T, layout nodeChainImportedLayout, mode, layer string) (map[string]any, NodeChainSource) {
	t.Helper()
	local := nodeChainMultipleImportedFixture(t, layout, mode, layer)
	if layout.name == "selected-private-stream" {
		pair := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "shadowsocks", "shadowsocks"}, make([]string, 4))
		identity := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg", "wg"}, make([]string, 4))
		for i := 1; i < len(local.Nodes); i++ {
			if local.IdentitySources[i] == "" {
				continue
			}
			slot := 2
			if i == len(local.Nodes)-1 {
				slot = 3
			}
			original := pair[slot]
			// These independent stream keys cannot collide with the fixture's
			// position-derived keys at deeper placements. The independent WG
			// companion remains a real original capture for this exact node.
			assets := externalTestRead(t, original.inputs.Files)
			graph := externalTestRead(t, string(mustDecodeChainAsset(t, assets["sing-box.json"].(string))))
			key := sha256.Sum256([]byte(fmt.Sprintf("private-stream-depth-peer-%d", slot)))
			graph["outbounds"].([]any)[0].(map[string]any)["password"] = base64.StdEncoding.EncodeToString(key[:])
			assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
			selected, err := NewNodeProfile("shadowsocks", startJSON(t, assets), startJSON(t, original.profile), "", "")
			if err != nil {
				t.Fatal(err)
			}
			local.Nodes[i], err = selected.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			local.IdentitySources[i] = identity[slot].inputs.Files
		}
	}

	entry, err := ParseNodeLaunchInput(local.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"schema": float64(6), "entry_node_id": entry.profile["node_proof_id"],
		"entry": map[string]any{"bundle": nodeChainServerPlanBundle(t, entry, local.IdentitySources[0]), "profile_id": entry.profile["id"], "mode": entry.mode}}
	rows := make([]any, 0, len(local.Nodes)-1)
	for i := 1; i < len(local.Nodes); i++ {
		if local.IdentitySources[i] == "" {
			var original nodeChainImportedInput
			if json.Unmarshal([]byte(local.Nodes[i]), &original) != nil {
				t.Fatal("original imported fixture")
			}
			rows = append(rows, map[string]any{"imported": map[string]any{"config": original.Config, "capture": original.Capture}})
			continue
		}
		node, err := ParseNodeLaunchInput(local.Nodes[i])
		if err != nil {
			t.Fatal(err)
		}
		bundle := nodeChainServerPlanBundle(t, node, local.IdentitySources[i])
		rows = append(rows, map[string]any{"paired": map[string]any{"bundle": bundle, "profile_id": node.profile["id"], "mode": node.mode},
			"server_peer": map[string]any{"bundle": nodeChainServerPlanPeerBundle(t, bundle, i), "profile_id": "server-" + node.profile["id"].(string)}})
	}
	plan["members"] = rows
	return plan, local
}

func multipleImportedServerFixture(t *testing.T, layout nodeChainImportedLayout, mode, layer string) (*NodeChainServerPolicy, *NodeChain, multihoprelay.NodeChainCapture) {
	t.Helper()
	plan, source := multipleImportedServerPlanFixture(t, layout, mode, layer)
	p, err := NewNodeChainMultipleImportedServerPlan(startJSON(t, plan))
	if err != nil {
		t.Fatal("original independent Server plan", err)
	}
	local, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal("original Local source", err)
	}
	d := p.Descriptor()
	digest, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	q := multihoprelay.NodeChainRequest{Schema: 6, SessionID: strings.Repeat("1", 32), EntryNodeID: d.EntryNodeID,
		SourceSHA256: d.SourceSHA256, DescriptorSHA256: digest, DNSPolicySHA256: d.DNSPolicySHA256,
		Epoch: strings.Repeat("2", 64), Peer: "10.77.0.2", AcquireExpiresAt: 1794484810, Port: 26240}
	for position, node := range local.nodes[:len(local.nodes)-1] {
		if node == nil || local.selectedPrivateStream(position) {
			continue
		}
		key, err := node.PacketClientPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		q.LocalPacketPositions = append(q.LocalPacketPositions, position)
		q.LocalPacketPublicKeys = append(q.LocalPacketPublicKeys, key)
	}
	for i := range d.Members {
		q.Users = append(q.Users, multihoprelay.NodeChainUser{Position: i + 1, Username: fmt.Sprintf("%048x", 101+i*2), Password: fmt.Sprintf("%048x", 102+i*2)})
	}
	c := multihoprelay.NodeChainCapture{Schema: 1, Request: q, Source: d, RegistrySHA256: digest, OwnerID: strings.Repeat("3", 64), Peer: q.Peer, Host: "10.77.0.1", BootstrapDeadline: time.Unix(1794484890, 0).UTC()}
	if err := c.Validate(); err != nil {
		t.Fatal("complete positional original capture", err)
	}
	return p, local, c
}

func TestNodeChainMultipleImportedServerPlanOriginalInventory(t *testing.T) {
	for _, layout := range multipleImportedServerLayouts {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(layout.name+"/"+layer, func(t *testing.T) {
				p, local, c := multipleImportedServerFixture(t, layout, "wg", layer)
				config, err := p.NativeConfig(c)
				if err != nil || config == "" || p.multiple == nil || !p.multiple.original() {
					t.Fatal("lost original source", err)
				}
				var source NodeChainServerSource
				if json.Unmarshal([]byte(p.Source()), &source) != nil || source.Schema != 6 || len(source.Nodes) != layout.count-1 {
					t.Fatal("suffix shape")
				}
				for i, member := range p.Descriptor().Members {
					if member.Position != i+1 || p.proofs[i].Position != i+1 {
						t.Fatal("position shifted")
					}
					if original := local.importedSSMemberAt(i + 1); original != nil {
						if source.Nodes[i] != original.input || source.IdentitySources[i] != "" || member.SourceSHA256 != original.source || member.ExpectedPublicIP != original.selection.ExpectedPublicIP || member.NodeID != "" || member.NodeKind != "external" || member.ProofKind != "public-path" {
							t.Fatal("imported original/role changed", i)
						}
						if p.proofTargets[i].API != "" || p.proofTargets[i].Token != "" || p.proofTargets[i].ExpectedPublicIP != original.selection.ExpectedPublicIP {
							t.Fatal("public proof acquired private credentials")
						}
					} else if i < len(p.nodes)-1 {
						key, _ := local.nodes[i+1].PacketClientPublicKey()
						if member.ClientPublicKey == key {
							t.Fatal("Local private packet identity reused for Server")
						}
					}
				}
				replay, err := NewNodeChainMultipleImportedServerPolicy(p.Source())
				if err != nil || !reflect.DeepEqual(replay.Descriptor(), p.Descriptor()) {
					t.Fatal("original suffix replay", err)
				}
				if replay.config != config || !reflect.DeepEqual(replay.dns, p.dns) {
					t.Fatal("selected DNS/config replay drift")
				}
				graph := externalTestRead(t, config)
				if len(graph["inbounds"].([]any)) != 0 || graph["route"].(map[string]any)["final"] != p.proofs[len(p.proofs)-1].Tag {
					t.Fatal("Server invented TUN/listener or lost final route")
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedServerPlanRefusals(t *testing.T) {
	for _, fault := range []string{"schema", "unknown", "entry-id", "entry-node", "missing-peer", "borrowed-peer", "duplicate-import", "import-at-final", "import-router-identity", "no-import", "extra-member", "missing-final", "source-schema", "source-extra", "source-identity", "source-reorder"} {
		t.Run(fault, func(t *testing.T) {
			plan, _ := multipleImportedServerPlanFixture(t, nodeChainImportedLayout{"mixed", 5, []int{1, 3}}, "wg", "")
			rows := plan["members"].([]any)
			if strings.HasPrefix(fault, "source-") {
				p, err := NewNodeChainMultipleImportedServerPlan(startJSON(t, plan))
				if err != nil {
					t.Fatal(err)
				}
				var s NodeChainServerSource
				_ = json.Unmarshal([]byte(p.Source()), &s)
				switch fault {
				case "source-schema":
					s.Schema = 2
				case "source-extra":
					s.Nodes = append(s.Nodes, s.Nodes[0])
					s.IdentitySources = append(s.IdentitySources, "")
				case "source-identity":
					s.IdentitySources[0] = s.IdentitySources[len(s.IdentitySources)-1]
				case "source-reorder":
					s.Nodes[0], s.Nodes[len(s.Nodes)-1] = s.Nodes[len(s.Nodes)-1], s.Nodes[0]
				}
				if _, err := NewNodeChainMultipleImportedServerPolicy(startJSON(t, s)); err == nil {
					t.Fatal("changed source accepted")
				}
				return
			}
			switch fault {
			case "schema":
				plan["schema"] = float64(1)
			case "unknown":
				plan["unbound"] = true
			case "entry-id":
				plan["entry"].(map[string]any)["profile_id"] = "foreign"
			case "entry-node":
				plan["entry_node_id"] = strings.Repeat("a", 64)
			case "missing-peer":
				delete(rows[1].(map[string]any), "server_peer")
			case "borrowed-peer":
				rows[1].(map[string]any)["server_peer"] = rows[1].(map[string]any)["paired"]
			case "duplicate-import":
				rows[2] = rows[0]
			case "import-at-final":
				rows[len(rows)-1] = rows[0]
			case "import-router-identity":
				rows[0].(map[string]any)["server_peer"] = rows[1].(map[string]any)["server_peer"]
			case "no-import":
				plan, _ = nodeChainServerPlanFixture(t, "wg", "", false)
				plan["schema"] = float64(6)
			case "extra-member":
				plan["members"] = append(rows, rows[0])
			case "missing-final":
				plan["members"] = rows[:len(rows)-1]
			}
			if _, err := NewNodeChainMultipleImportedServerPlan(startJSON(t, plan)); err == nil {
				t.Fatal("changed original operator plan accepted")
			}
		})
	}
}

func TestNodeChainMultipleImportedServerOriginalOwnerRefusals(t *testing.T) {
	for _, fault := range []string{"policy-copy", "scope-copy", "member-copy", "policy-substitute", "member-input", "member-order", "missing-member", "node-copy", "source", "config", "proof", "dns", "carrier"} {
		t.Run(fault, func(t *testing.T) {
			p, _, c := multipleImportedServerFixture(t, nodeChainImportedLayout{"mixed", 5, []int{1, 3}}, "wg", "")
			s := p.multiple
			switch fault {
			case "policy-copy":
				copy := *p
				p = &copy
			case "scope-copy":
				copy := *s
				p.multiple = &copy
			case "member-copy":
				copy := *s.members[0]
				s.members[0] = &copy
			case "policy-substitute":
				copy := *s.members[0].policy
				s.members[0].policy = &copy
			case "member-input":
				s.members[0].input += " "
			case "member-order":
				s.members[0], s.members[2] = s.members[2], s.members[0]
			case "missing-member":
				s.members[0] = nil
			case "node-copy":
				copy := *p.nodes[1]
				p.nodes[1] = &copy
			case "source":
				p.sourceJSON += " "
			case "config":
				p.config += " "
			case "proof":
				p.proofs[0].Tag = "foreign"
			case "dns":
				p.dns.ResolverTag = "foreign"
			case "carrier":
				p.carrier = &NodeChainServerCarrier{}
			}
			if _, err := p.NativeConfig(c); err == nil {
				t.Fatal("replacement original owner accepted")
			}
		})
	}
}

func TestNodeChainMultipleImportedServerLegacyAdmissionClosed(t *testing.T) {
	p, _, _ := multipleImportedServerFixture(t, nodeChainImportedLayout{"two", 4, []int{1, 2}}, "wg", "")
	for name, parse := range map[string]func(string) (*NodeChainServerPolicy, error){"generic": NewNodeChainServerPolicy, "socks": NewNodeChainSOCKSServerPolicy, "connect": NewNodeChainCONNECTServerPolicy, "openvpn": NewNodeChainOpenVPNServerPolicy} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse(p.Source()); err == nil {
				t.Fatal("unrelated source parser admitted schema6")
			}
		})
	}
	for _, imported := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy-", imported), func(t *testing.T) {
			plan, _ := nodeChainServerPlanFixture(t, "wg", "", imported)
			old, err := NewNodeChainServerPlan(startJSON(t, plan))
			if err != nil || old.multiple != nil {
				t.Fatal("legacy changed", err)
			}
			if _, err := NewNodeChainMultipleImportedServerPolicy(old.Source()); err == nil {
				t.Fatal("typed source adopted legacy")
			}
		})
	}
}

func multipleImportedServerMembers(p *NodeChainServerPolicy) []nodeChainGraphMember {
	result := make([]nodeChainGraphMember, len(p.nodes))
	for i, node := range p.nodes {
		if m := p.importedSSMemberAt(i); m != nil {
			result[i] = nodeChainGraphMember{profile: m.selection.Profile, source: m.source, mode: "shadowsocks", imported: true}
		} else {
			result[i] = nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode}
		}
	}
	return result
}

func TestNodeChainMultipleImportedServerFirstPacketMTU(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, positions := range [][]int{{1}, {1, 2}, {1, 3}} {
			t.Run(mode+fmt.Sprint(positions), func(t *testing.T) {
				p, _, capture := multipleImportedServerFixture(t, nodeChainImportedLayout{"first", 6, positions}, mode, "")
				first := p.multiple.firstPacket
				if first < 1 || !p.multiple.firstPhysicalPacket(first) || p.NativeCarrierRequired() {
					t.Fatal("first actual packet/source scope changed")
				}
				configured, err := nodeMultihopPredecessor(p.nodes[first])
				if err != nil {
					t.Fatal(err)
				}
				want, err := mtuNumber(configured.final["mtu"])
				native, nativeErr := p.NativeConfig(capture)
				if nativeErr != nil {
					t.Fatal(nativeErr)
				}
				graph := externalTestRead(t, native)
				got, actualErr := mtuNumber(externalTestFind(t, graph, p.proofs[first].Tag)["mtu"])
				if err != nil || actualErr != nil || got != want {
					t.Fatal("first packet substituted a measured or invented outer-interface cap", got, want, err, actualErr)
				}
				members := multipleImportedServerMembers(p)
				if p.multiple.validateCompilation(members, p.multiple.closures) != nil {
					t.Fatal("original compilation inventory changed")
				}
				if err := applyNodeChainImportedPacketMTU(members, p.multiple.closures, first); err == nil {
					t.Fatal("generic Local packet guard inferred an absent outer interface")
				}
				for i := first + 1; i < len(members); i++ {
					if p.multiple.firstPhysicalPacket(i) {
						t.Fatal("later packet bypassed original nested budget")
					}
					if NodeChainPrefixMode(members[i].mode) && members[i-1].imported {
						inner, err := mtuNumber(externalTestFind(t, graph, p.proofs[i].Tag)["mtu"])
						if err != nil || inner >= got {
							t.Fatal("later packet lost its real preceding packet envelope", inner, got, err)
						}
					}
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedServerMTUOwnerRefusals(t *testing.T) {
	for _, fault := range []string{"foreign-scope", "copied-closure", "reordered-closures", "wrong-source", "wrong-profile", "wrong-kind", "wrong-mode", "missing-member"} {
		t.Run(fault, func(t *testing.T) {
			p, _, _ := multipleImportedServerFixture(t, nodeChainImportedLayout{"first", 5, []int{1, 3}}, "wg", "")
			members, closures := multipleImportedServerMembers(p), append([]*externalPredecessor(nil), p.multiple.closures...)
			s := p.multiple
			switch fault {
			case "foreign-scope":
				other, _, _ := multipleImportedServerFixture(t, nodeChainImportedLayout{"same", 5, []int{1, 3}}, "wg", "")
				s = other.multiple
			case "copied-closure":
				copy := *closures[0]
				closures[0] = &copy
			case "reordered-closures":
				closures[0], closures[1] = closures[1], closures[0]
			case "wrong-source":
				members[0].source = strings.Repeat("a", 64)
			case "wrong-profile":
				members[0].profile = predecessorCopy(members[0].profile)
				members[0].profile["id"] = "foreign"
			case "wrong-kind":
				members[0].imported = false
			case "wrong-mode":
				members[0].mode = "wg"
			case "missing-member":
				members = members[1:]
			}
			if err := applyNodeChainMemberMTUWithServerScope(members, closures, s); err == nil {
				t.Fatal("MTU adopted foreign inventory")
			}
		})
	}
}

func TestNodeChainMultipleImportedServerPhysicalProjectionUnion(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _ := multipleImportedServerFixture(t, nodeChainImportedLayout{"first", 5, []int{1, 3}}, mode, "")
			expected, err := p.multiple.members[0].policy.DirectPhysicalEgress([]string{"tcp", "udp"})
			if err != nil {
				t.Fatal(err)
			}
			graph := externalTestRead(t, p.config)
			graph["route"].(map[string]any)["final"] = p.proofs[len(p.proofs)-1].Tag
			projections := make([][]PhysicalEgress, len(p.proofs))
			for i, proof := range p.proofs {
				projections[i], err = compiledPhysicalEgressWithDesktopProof(startJSON(t, graph), []string{"tcp", "udp"}, nil, proof.Tag)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := p.multiple.completePhysicalEgress(projections, expected)
			if err != nil || !nodeChainSamePhysical(got, expected) {
				t.Fatal("actual proof/application/DNS projections lost exact outer union", err)
			}
		})
	}
}

func TestNodeChainMultipleImportedServerPhysicalUnionRefusals(t *testing.T) {
	for _, fault := range []string{"missing-tcp", "missing-udp", "third-tuple", "wrong-port", "wrong-host", "wrong-network", "duplicate-tuple", "empty-projection", "missing-final", "extra-projection", "expected-subset", "expected-duplicate", "wrong-owner"} {
		t.Run(fault, func(t *testing.T) {
			p, _, _ := multipleImportedServerFixture(t, nodeChainImportedLayout{"first", 4, []int{1}}, "wg", "")
			expected, err := p.multiple.members[0].policy.DirectPhysicalEgress([]string{"tcp", "udp"})
			if err != nil || len(expected) != 2 {
				t.Fatal(err)
			}
			projections := make([][]PhysicalEgress, len(p.proofs))
			for i := range projections {
				projections[i] = append([]PhysicalEgress(nil), expected...)
			}
			switch fault {
			case "missing-tcp", "missing-udp":
				network := strings.TrimPrefix(fault, "missing-")
				for i := range projections {
					projections[i] = nil
					for _, v := range expected {
						if v.Network != network {
							projections[i] = append(projections[i], v)
						}
					}
				}
			case "third-tuple":
				v := expected[0]
				v.Port++
				projections[0] = append(projections[0], v)
			case "wrong-port":
				projections[0][0].Port++
			case "wrong-host":
				projections[0][0].Host = "203.0.113.250"
			case "wrong-network":
				projections[0][0].Network = "icmp"
			case "duplicate-tuple":
				projections[0] = append(projections[0], projections[0][0])
			case "empty-projection":
				projections[0] = nil
			case "missing-final":
				projections = projections[:len(projections)-1]
			case "extra-projection":
				projections = append(projections, expected)
			case "expected-subset":
				expected = expected[:1]
			case "expected-duplicate":
				expected[1] = expected[0]
			case "wrong-owner":
				copy := *p.multiple.members[0].policy
				p.multiple.members[0].policy = &copy
			}
			if _, err := p.multiple.completePhysicalEgress(projections, expected); err == nil {
				t.Fatal("incomplete/extra/foreign physical union accepted")
			}
		})
	}
}

func TestNodeChainMultipleImportedServerActualPublicProofs(t *testing.T) {
	for _, fault := range []string{"none", "first-ip", "second-ip", "wrong-position", "dead-first", "dns", "changed-owner", "private-id"} {
		t.Run(fault, func(t *testing.T) {
			p, _, c := multipleImportedServerFixture(t, nodeChainImportedLayout{"separate", 5, []int{1, 3}}, "wg", "")
			e := newNodeChainServerProofTestEngine(t, p, c)
			seen := []string{}
			e.beforeDial = func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
				for i, target := range p.proofTargets {
					if target.Proof.Tag != tag || target.Proof.NodeKind != "external" {
						continue
					}
					if fault == "dead-first" && i == 0 {
						return nil, errors.New("original imported route refused"), true
					}
					body := "ip=" + target.ExpectedPublicIP + "\n"
					if fault == "first-ip" && i == 0 || fault == "second-ip" && i == 2 {
						body = "ip=198.51.100.250\n"
					}
					if fault == "wrong-position" && i == 2 {
						body = "ip=" + p.proofTargets[0].ExpectedPublicIP + "\n"
					}
					e.mu.Lock()
					e.publicBody = body
					seen = append(seen, tag)
					e.mu.Unlock()
					return nil, nil, false
				}
				e.mu.Lock()
				e.publicBody = "ip=203.0.113.88\n"
				e.mu.Unlock()
				return nil, nil, false
			}
			e.dnsFail = fault == "dns"
			e.changeOnDNS = fault == "changed-owner"
			if fault == "private-id" {
				e.wrongPrefix = 1
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := p.prove(ctx, c, e, e.trust)
			if fault != "none" {
				if err == nil {
					t.Fatal("failed original public/private/DNS owner proved")
				}
				return
			}
			if err != nil || !result.DNSProven || !result.PublicProven || len(result.Prefixes) != 4 || result.ExitIP != "203.0.113.88" {
				t.Fatal("complete routed proof failed", err)
			}
			if !reflect.DeepEqual(seen, []string{p.proofs[0].Tag, p.proofs[2].Tag}) || e.dnsCalls != 1 {
				t.Fatal("an original public position or selected DNS omitted", seen)
			}
			for i, row := range result.Prefixes {
				if row.Proof != p.proofs[i] || row.ResponseMS <= 0 {
					t.Fatal("actual proof receipt lost original position")
				}
			}
		})
	}
}
