package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func extendedSelectedLayout(n int) nodeChainImportedLayout {
	positions := make([]int, n-2)
	for i := range positions {
		positions[i] = i + 1
	}
	return nodeChainImportedLayout{"extended", n, positions}
}

func TestNodeChainExtendedSelectedOriginal(t *testing.T) {
	for _, count := range []int{9, 16} {
		layout := extendedSelectedLayout(count)
		for _, requested := range []struct{ mode, winner string }{{"server", "server"}, {"auto", "server"}, {"auto", "local"}} {
			t.Run(fmt.Sprintf("%d/%s/%s", count, requested.mode, requested.winner), func(t *testing.T) {
				f := multipleImportedExecutionRuntimeFixture(t, layout, requested.mode)
				if requested.mode == "auto" {
					if requested.winner == "local" {
						f.engine.serverDelay = 200 * time.Millisecond
					} else {
						f.engine.localDelay = 200 * time.Millisecond
					}
				}
				ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
				defer stop()
				if err := f.runtime.Run(ctx); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := f.runtime.CloseContext(ctx); err != nil {
						t.Error(err)
					}
				}()
				assertMultipleImportedExecutionProgress(t, f)
				before := f.runtime.Progress()
				if before.Execution != requested.winner {
					t.Fatalf("got %q, want originally measured %q", before.Execution, requested.winner)
				}
				projection := f.runtime.projection
				original, err := projection.preparation.OriginalMultipleImportedSource()
				if err != nil || original.ExtendedLocalNodeCount() != count || projection.preparation.ExtendedOriginalNodeCount() != count || projection.preparation.ExtendedOriginalStatusLimit() != original.ExtendedLocalStatusLimit() {
					t.Fatal("original capture", err)
				}
				for i, member := range projection.policy.source.Server.Members[:count-2] {
					if member.SourceSHA256 != original.importedSSMemberAt(i+1).source {
						t.Fatal("changed original private source", i+1)
					}
				}
				plan, err := projection.MTUPlan()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = projection.PlanForMTU(projection.Config(), plan.Original); err != nil {
					t.Fatal("live MTU", err)
				}
				o := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
				m, err := f.runtime.NewHopMeasurementContext(ctx, o)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := m.Close(); err != nil {
						t.Error(err)
					}
				}()
				raw, err := m.SelectedCaptureContext(ctx)
				if err != nil || original.ValidateMultipleImportedLatencyCapture(raw) != nil {
					t.Fatal("selected receipt lost original source", err)
				}
				pub, _, err := projection.ImportedPublicMeasurementCaptures(before.Execution)
				if err != nil || len(pub) != count-2 || original.ValidateMultipleImportedLatencyCapture(strings.Replace(raw, pub[len(pub)-1].SourceSHA256, strings.Repeat("f", 64), 1)) == nil {
					t.Fatal("late source identity escaped validation", err)
				}
				after := f.runtime.Progress()
				if after.Execution != before.Execution || !reflect.DeepEqual(before.Comparison, after.Comparison) {
					t.Fatal("reading a selected capture repeated comparison")
				}
			})
		}
	}
}

func TestNodeChainExtendedSelectedControlBounds(t *testing.T) {
	_, _, c := multipleImportedServerFixture(t, extendedSelectedLayout(16), "wg", "")
	q := c.Request.Clone()
	previous := multihoprelay.NodeChainLease{Request: q, NodeID: c.Source.EntryNodeID, OwnerID: c.OwnerID, Host: c.Host, Port: q.Port, Users: append([]multihoprelay.NodeChainUser(nil), q.Users...), RegistrySHA256: c.RegistrySHA256, DNSPolicySHA256: c.Source.DNSPolicySHA256, Phase: multihoprelay.NodeChainPending, ExpiresAt: c.BootstrapDeadline.Add(time.Minute), BootstrapDeadline: c.BootstrapDeadline}
	status := multihoprelay.NodeChainLeaseStatus{Lease: previous}
	status.Lease.Phase = multihoprelay.NodeChainReady
	raw, err := multihoprelay.MarshalNodeChainStatus(status)
	if err != nil {
		t.Fatal(err)
	}
	var update multihoprelay.NodeChainStatusUpdate
	if len(raw) > multihoprelay.MaxControlResponseBytes || exactJSON(raw, &update, multihoprelay.MaxControlResponseBytes) != nil {
		t.Fatal("unbounded response")
	}
	restored, err := update.RestoreLease(previous)
	if err != nil || !reflect.DeepEqual(restored, status) {
		t.Fatal("lease readback", err)
	}
	for name, mutate := range map[string]func(*multihoprelay.NodeChainLease){
		"password": func(l *multihoprelay.NodeChainLease) { l.Users[len(l.Users)-1].Password = strings.Repeat("f", 48) },
		"request": func(l *multihoprelay.NodeChainLease) {
			l.Request.Users[len(l.Request.Users)-1].Username = strings.Repeat("f", 48)
		},
		"owner":    func(l *multihoprelay.NodeChainLease) { l.OwnerID = strings.Repeat("f", 64) },
		"expiry":   func(l *multihoprelay.NodeChainLease) { l.ExpiresAt = l.ExpiresAt.Add(time.Millisecond) },
		"deadline": func(l *multihoprelay.NodeChainLease) { l.BootstrapDeadline = l.BootstrapDeadline.Add(time.Millisecond) },
	} {
		t.Run(name, func(t *testing.T) {
			another := previous
			another.Request = previous.Request.Clone()
			another.Users = append([]multihoprelay.NodeChainUser(nil), previous.Users...)
			mutate(&another)
			if _, err := update.RestoreLease(another); err == nil {
				t.Fatal("foreign acknowledgement adopted")
			}
		})
	}
}

func TestExtendedOriginalSealRechecksLiveProofsAndSource(t *testing.T) {
	f := multipleImportedExecutionRuntimeFixture(t, extendedSelectedLayout(16), "server")
	preparation := f.runtime.projection.preparation
	original, err := preparation.OriginalMultipleImportedSource()
	if err != nil || original.ExtendedLocalNodeCount() != 16 {
		t.Fatal("missing sealed original", err)
	}
	proof := original.proofs[13]
	original.proofs[13].SourceSHA256 = strings.Repeat("a", 64)
	if preparation.ExtendedOriginalNodeCount() != 0 || original.ExtendedLocalNodeCount() != 0 {
		t.Fatal("changed late original proof retained admission")
	}
	original.proofs[13] = proof
	member := original.importedSSMemberAt(13)
	member.policy.capture.Profile["unexpected"] = true
	if preparation.ExtendedOriginalNodeCount() != 0 || original.ExtendedLocalNodeCount() != 0 {
		t.Fatal("changed original private source retained admission")
	}
	delete(member.policy.capture.Profile, "unexpected")
	if preparation.ExtendedOriginalNodeCount() != 16 {
		t.Fatal("unmodified original no longer matches")
	}
}

func TestExtendedOriginalChecksControlRequestCapacityBeforeBinding(t *testing.T) {
	for _, count := range []int{16, 96} {
		_, prep, source := multipleImportedExecutionFixture(t, extendedSelectedLayout(count), "wg", "", "server", "")
		if prep.ExtendedOriginalNodeCount() != count {
			t.Fatal("missing original source count", count)
		}
		exact, err := nodeChainStatusRequest(source.Request, strings.Repeat("1", 64))
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := json.Marshal(source.Server)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("original %d nodes, %d-byte lease status request, %d-byte server descriptor, %d-byte Last limit", count, len(exact), len(descriptor), nodeChainExecutionLastLimit)
		policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
		if count == 16 {
			if err != nil || policy == nil || len(exact) > multihoprelay.NodeChainLeaseRequestMaximumBytes {
				t.Fatal("qualified wire", err)
			}
			continue
		}
		if policy != nil || !errors.Is(err, errNodeChainControlCapacity) || len(exact) <= multihoprelay.NodeChainLeaseRequestMaximumBytes || !strings.Contains(err.Error(), fmt.Sprint(len(exact), "-byte")) {
			t.Fatal("oversize original admitted before binding", err)
		}
		discovery := NodeChainExecutionDiscovery{Challenge: multihoprelay.ExternalPacketChallenge{Peer: source.Request.Peer, Epoch: source.Request.Epoch, ExpiresAt: source.Request.AcquireExpiresAt}, Sources: []multihoprelay.NodeChainDescriptor{source.Server}, FirstPort: source.FirstPort, LastPort: source.LastPort}
		if _, err := prep.policyForDiscovery(source.Server, discovery, source.Request.Port); !errors.Is(err, errNodeChainControlCapacity) {
			t.Fatal("authenticated discovery swallowed exact budget refusal", err)
		}
	}
}

func TestExtendedOriginalChecksReadyCapacityBeforeAcquisition(t *testing.T) {
	for _, width := range []int{64, 128} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			const count = 24
			plan, local := multipleImportedServerPlanFixture(t, extendedSelectedLayout(count), "wg", "")
			members := plan["members"].([]any)
			for i := 1; i < count-1; i++ {
				var input nodeChainImportedInput
				if err := json.Unmarshal([]byte(local.Nodes[i]), &input); err != nil {
					t.Fatal(err)
				}
				selected := externalTestRead(t, input.Capture)
				id := strings.Repeat("n", width-3) + fmt.Sprintf("%03d", i)
				selected["exit_id"] = id
				selected["profile"].(map[string]any)["id"] = id
				input.Capture = startJSON(t, selected)
				local.Nodes[i] = startJSON(t, input)
				members[i-1].(map[string]any)["imported"].(map[string]any)["capture"] = input.Capture
			}
			original, err := NewNodeChain(startJSON(t, local))
			if err != nil {
				t.Fatal("original source", err)
			}
			prep, err := NewNodeChainMultipleImportedExecutionPreparation(original, "server")
			if err != nil || prep.ExtendedOriginalNodeCount() != count {
				t.Fatal("original selected preparation", err)
			}
			server, err := NewNodeChainMultipleImportedServerPlan(startJSON(t, plan))
			if err != nil {
				t.Fatal("original provisioned descriptor", err)
			}
			d := server.Descriptor()
			entry, err := nodeMultihopPredecessor(original.nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			ip, err := netip.ParsePrefix(entry.final["address"].([]any)[0].(string))
			if err != nil {
				t.Fatal(err)
			}
			discovery := NodeChainExecutionDiscovery{NodeID: d.EntryNodeID, FirstPort: 32000, LastPort: 32007,
				Challenge: multihoprelay.ExternalPacketChallenge{Peer: ip.Addr().String(), Epoch: strings.Repeat("2", 64), ExpiresAt: time.Now().Add(30 * time.Second).Unix()}, Sources: []multihoprelay.NodeChainDescriptor{d}}
			policy, err := prep.policyForDiscovery(d, discovery, 32003)
			if width == 128 {
				if policy != nil || !errors.Is(err, errNodeChainControlCapacity) || !strings.Contains(err.Error(), "ready worker IPC (limit 8192 bytes)") {
					t.Fatal("oversized ready response admitted or wrong capacity error", err)
				}
				t.Log(err)
				return
			}
			if err != nil {
				t.Fatal("nearby original should fit", err)
			}
			raw, err := nodeChainStatusRequest(policy.Request(), strings.Repeat("3", 64))
			if err != nil || len(raw) > multihoprelay.NodeChainLeaseRequestMaximumBytes {
				t.Fatal("nearby original request size", len(raw), err)
			}
			if _, err := prep.BindExecution(policy); err != nil {
				t.Fatal("matching nearby original", err)
			}
			t.Logf("same 24-member original topology, %d-byte nonce request", len(raw))
		})
	}
}
