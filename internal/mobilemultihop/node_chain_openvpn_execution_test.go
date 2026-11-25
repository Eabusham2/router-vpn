package mobilemultihop

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"router-vpn/internal/nativeopenvpn"
	"testing"
	"time"
)

func openVPNExecutionFixture(t *testing.T, count int, mode, network, layer, execution, target string) (*NodeChain, *NodeChainExecutionPreparation, NodeChainExecutionSource) {
	t.Helper()
	fixtureCount := count
	if layer != "" {
		fixtureCount = 6
	}
	local, plan := nodeChainOpenVPNServerPlanFixture(t, fixtureCount, mode, network, layer)
	if fixtureCount != count {
		// Keep the original larger packet budget and each complete owned row.
		// Shorter positive fixtures must not violate the captured UDP MTU guard.
		local.Nodes = append(local.Nodes[:count:count], local.Nodes[fixtureCount:]...)
		local.IdentitySources = append(local.IdentitySources[:count:count], local.IdentitySources[fixtureCount:]...)
		members := plan["members"].([]any)
		plan["members"] = append(members[:count-1:count-1], members[fixtureCount-1:]...)
	}
	source, err := NewNodeChain(startJSON(t, local))
	if err != nil {
		t.Fatal(err)
	}
	if target != "" {
		source, err = ProjectNodeChain(source, target, 1280)
		if err != nil {
			t.Fatal(err)
		}
	}
	server, err := NewNodeChainOpenVPNServerPlan(startJSON(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	return source, openVPNExecutionPreparationFixture(t, source, execution), openVPNExecutionSourceFixture(t, source, server, execution)
}
func openVPNExecutionPreparationFixture(t *testing.T, source *NodeChain, execution string) *NodeChainExecutionPreparation {
	t.Helper()
	prep, err := NewNodeChainOpenVPNExecutionPreparation(source, execution)
	if err != nil {
		t.Fatal("typed preparation", err)
	}
	return prep
}

// The caller supplies its exact captured Local projection and independently
// compiled original Server descriptor. No credentials are reconstructed here.
func openVPNExecutionSourceFixture(t *testing.T, source *NodeChain, server *NodeChainServerPolicy, execution string) NodeChainExecutionSource {
	t.Helper()
	count := len(source.nodes) - 2

	capture := nodeChainServerCaptureFixture(t, server)
	request := capture.Request.Clone()
	request.LocalPacketPublicKeys = nil
	request.LocalPacketPositions = nil
	for i, node := range source.nodes[:count] {
		key, err := node.PacketClientPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, key)
		request.LocalPacketPositions = append(request.LocalPacketPositions, i)
	}
	request.Peer, request.Port = "10.80.0.2", 32003
	return NodeChainExecutionSource{Schema: 5, Execution: execution, LocalSource: source.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
}
func TestNodeChainOpenVPNExecutionPrefixesWG(t *testing.T) { testOpenVPNExecutionPrefixes(t, "wg") }
func TestNodeChainOpenVPNExecutionPrefixesFast(t *testing.T) {
	testOpenVPNExecutionPrefixes(t, "awg2-fast")
}
func TestNodeChainOpenVPNExecutionPrefixesStrong(t *testing.T) {
	testOpenVPNExecutionPrefixes(t, "awg2-strong")
}
func testOpenVPNExecutionPrefixes(t *testing.T, mode string) {
	for count := 1; count <= 6; count++ {
		for _, network := range []string{"tcp", "udp"} {
			for _, execution := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, network, execution), func(t *testing.T) {
					layer := []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[(count-1)%3]
					original, prep, source := openVPNExecutionFixture(t, count, mode, network, layer, execution, "")
					if !prep.RequiresOpenVPNExecutionObserver() {
						t.Fatal("native observer omitted")
					}
					retained, err := prep.OriginalOpenVPNSource()
					if err != nil || retained != original {
						t.Fatal("original Local owner replaced", err)
					}
					if _, err := NewNodeChainExecutionPreparation(source.LocalSource, execution); err == nil {
						t.Fatal("generic preparation admitted schema5")
					}
					if _, err := ParseNodeChainExecutionPreparation(prep.Source()); err == nil {
						t.Fatal("generic restoration admitted schema5")
					}
					if _, err := NewNodeChainExecutionPolicy(startJSON(t, source)); err == nil {
						t.Fatal("generic policy admitted schema5")
					}
					replay, err := ParseNodeChainOpenVPNExecutionPreparation(prep.Source())
					if err != nil || replay.Config() != prep.Config() || replay.local == original {
						t.Fatal("sealed independent replay changed", err)
					}
					policy, err := NewNodeChainOpenVPNExecutionPolicy(prep, startJSON(t, source))
					if err != nil {
						t.Fatal("typed policy", err)
					}
					if _, err := policy.LaunchInput(); err == nil {
						t.Fatal("generic launch admitted schema5")
					}
					projection, err := prep.BindExecution(policy)
					if err != nil {
						t.Fatal("same-owner projection", err)
					}
					if _, err := replay.BindExecution(policy); err == nil {
						t.Fatal("equal-content source borrowed original binding")
					}
					before, closed, after := externalTestRead(t, original.Config()), externalTestRead(t, prep.Config()), externalTestRead(t, projection.Config())
					for _, proof := range original.ProofInventory() {
						if !reflect.DeepEqual(externalTestFind(t, before, proof.Tag), externalTestFind(t, closed, proof.Tag)) || !reflect.DeepEqual(externalTestFind(t, before, proof.Tag), externalTestFind(t, after, proof.Tag)) {
							t.Fatal("native original member replaced", proof.Position)
						}
					}
					if after["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
						t.Fatal("application gate bypassed")
					}
					middle := externalTestFind(t, after, original.proofs[count].Tag)
					final := externalTestFind(t, after, original.proofs[count+1].Tag)
					if middle["type"] != "openvpn-client" || final["detour"] != middle["tag"] || final["udp_over_tcp"] != nil {
						t.Fatal("OpenVPN packet transport changed")
					}
					for _, choice := range []string{"local", "server"} {
						proofs, err := projection.ProofInventory(choice)
						if err != nil || len(proofs) != count+2 || proofs[count].Kind != "public-path" {
							t.Fatal("original proof inventory lost", err)
						}
						want := original.proofs[count].SourceSHA256
						if choice == "server" {
							want = source.Server.Members[count-1].SourceSHA256
						}
						if proofs[count].SourceSHA256 != want {
							t.Fatal("independent provider proof borrowed opposite source")
						}
						dns, err := projection.DNSCapture(choice)
						if err != nil || dns.DNS.FinalTag != SelectorTag || dns.DNS.ResolverTag != original.dns.ResolverTag {
							t.Fatal("selected final DNS changed", err)
						}
					}
					physical, err := projection.PhysicalEgress()
					originalPhysical, _ := original.PhysicalEgress()
					if err != nil || !reflect.DeepEqual(physical, originalPhysical) {
						t.Fatal("new physical authority", err)
					}
				})
			}
		}
	}
}
func TestNodeChainOpenVPNExecutionRetainsSealedMobileProjection(t *testing.T) {
	for _, target := range []string{"ios", "android"} {
		for _, count := range []int{1, 6} {
			t.Run(fmt.Sprintf("%s/%d", target, count), func(t *testing.T) {
				original, prep, input := openVPNExecutionFixture(t, count, "awg2-strong", "udp", "aes-256-gcm+xor-whitening", "auto", target)
				launch, err := original.LaunchInput()
				if err != nil || prep.source.OpenVPNLocalLaunch != launch {
					t.Fatal("original sealed Local launch lost", err)
				}
				reopened, err := ParseNodeChainOpenVPNExecutionPreparation(prep.Source())
				if err != nil || reopened.local.projection != original.projection || reopened.Config() != prep.Config() {
					t.Fatal("sealed projection stripped", err)
				}
				policy, err := NewNodeChainOpenVPNExecutionPolicy(prep, startJSON(t, input))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = prep.BindExecution(policy); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

type openVPNExecutionTestObserver struct {
	source *NodeChain
	state  nativeopenvpn.PacketObservation
	tag    string
	hook   func()
}

func (e *openVPNExecutionTestObserver) ObserveOpenVPNExecutionContext(ctx context.Context, source *NodeChain) error {
	if e.hook != nil {
		e.hook()
	}
	if source != e.source {
		return nodeChainExecutionError
	}
	return ctx.Err()
}
func (e *openVPNExecutionTestObserver) OpenVPNMiddleStateContext(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
	if tag != e.tag {
		return nativeopenvpn.PacketObservation{}, nodeChainExecutionError
	}
	return e.state, ctx.Err()
}
func TestNodeChainOpenVPNExecutionRejectsForeignConnectedOwner(t *testing.T) {
	for _, fault := range []string{"none", "missing-observer", "copied-binding", "copied-source", "missing-binding", "missing-pair", "pair-value", "capture-value", "member-value", "config", "proof", "changed-seal", "schema", "foreign-pair", "provider-source", "remote", "capacity", "generation", "connected-at"} {
		t.Run(fault, func(t *testing.T) {
			original, prep, input := openVPNExecutionFixture(t, 2, "wg", "tcp", "", "auto", "")
			capture, _ := original.OpenVPNMiddleCapture()
			observer := &openVPNExecutionTestObserver{source: original, tag: capture.Tag, state: nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: capture.Remote, Generation: 1, ConnectedAt: 1}, MTU: uint32(capture.ConfiguredMTU)}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := prep.observeOpenVPNExecutionContext(ctx, observer); err != nil {
				t.Fatal(err)
			}
			var engine any = observer
			policyFault := false
			switch fault {
			case "missing-observer":
				engine = struct{}{}
			case "copied-binding":
				prep.openvpn = nodeChainOpenVPNBindingOwnershipCopy(prep.openvpn)
			case "copied-source":
				prep.openvpn.source = nodeChainOwnershipCopy(original)
			case "missing-binding":
				prep.openvpn = nil
			case "missing-pair":
				prep.openvpn.pairSHA = ""
			case "pair-value":
				prep.openvpn.server.ProviderIdentity.Username = "foreign"
			case "capture-value":
				prep.openvpn.capture.ConfiguredMTU++
			case "member-value":
				original.openVPNMiddle.selection.Profile["id"] = "foreign"
			case "config":
				original.config += " "
			case "proof":
				original.proofs[0].Tag = "foreign"
			case "changed-seal":
				prep.source.OpenVPNLocalLaunch += " "
			case "schema":
				input.Schema = 4
				policyFault = true
			case "foreign-pair":
				input.Server.Members[1].OpenVPNPairSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				input.Request.DescriptorSHA256, _ = input.Server.Digest()
				policyFault = true
			case "provider-source":
				input.Server.Members[1].SourceSHA256 = original.proofs[2].SourceSHA256
				input.Request.DescriptorSHA256, _ = input.Server.Digest()
				policyFault = true
			case "remote":
				observer.state.Remote.Remote.Port++
			case "capacity":
				observer.state.MTU++
			case "generation":
				observer.state.Remote.Generation++
			case "connected-at":
				observer.state.Remote.ConnectedAt++
			}
			if policyFault {
				if _, err := NewNodeChainOpenVPNExecutionPolicy(prep, startJSON(t, input)); err == nil {
					t.Fatal("foreign provider discovery admitted")
				}
				return
			}
			err := prep.observeOpenVPNExecutionContext(ctx, engine)
			if fault == "none" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("foreign connected source admitted")
			}
		})
	}
}

func TestNodeChainOpenVPNExecutionHeldReceiptRetainsCallerDeadline(t *testing.T) {
	source, prep, _ := openVPNExecutionFixture(t, 1, "wg", "udp", "", "server", "")
	capture, _ := source.OpenVPNMiddleCapture()
	observer := &openVPNExecutionTestObserver{source: source, tag: capture.Tag, state: nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: capture.Remote, Generation: 1, ConnectedAt: 1}, MTU: uint32(capture.ConfiguredMTU)}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	prep.openvpn.mu.Lock()
	err := prep.observeOpenVPNExecutionContext(ctx, observer)
	prep.openvpn.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held receipt lost caller deadline", err)
	}
	retry, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := prep.observeOpenVPNExecutionContext(retry, observer); err != nil {
		t.Fatal("original receipt retry", err)
	}
}
