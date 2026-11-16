package mobilemultihop

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"router-vpn/internal/nativeopenvpn"
	"router-vpn/internal/routechoice"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// HTTP/TLS, Manager leases and shared comparison execute; the original native
// OpenVPN endpoint/routing observation is an explicit boundary double.
func (e *nodeChainExecutionRuntimeEngine) ObserveOpenVPNExecutionContext(ctx context.Context, original *NodeChain) error {
	if ctx == nil || ctx.Err() != nil || e.projection == nil || e.projection.preparation.openvpn == nil || original != e.projection.preparation.openvpn.source {
		return nodeChainExecutionError
	}
	return original.validateCapture()
}
func (e *nodeChainExecutionRuntimeEngine) OpenVPNMiddleStateContext(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
	if ctx == nil || ctx.Err() != nil || e.projection == nil || e.projection.preparation.openvpn == nil {
		return nativeopenvpn.PacketObservation{}, nodeChainExecutionError
	}
	capture, err := e.projection.preparation.openvpn.source.OpenVPNMiddleCapture()
	if err != nil || tag != capture.Tag {
		return nativeopenvpn.PacketObservation{}, nodeChainExecutionError
	}
	return nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: capture.Remote, Generation: 1, ConnectedAt: 1}, MTU: uint32(capture.ConfiguredMTU)}, nil
}
func openVPNExecutionRuntimeFixture(t *testing.T, execution string) *nodeChainExecutionRuntimeFixture {
	t.Helper()
	_, prep, source := openVPNExecutionFixture(t, 1, "wg", "tcp", "", execution, "")
	return newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, prep)
}
func TestNodeChainOpenVPNExecutionRuntimeServerOwnsOriginalLease(t *testing.T) {
	f := openVPNExecutionRuntimeFixture(t, "server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	p := f.runtime.Progress()
	if !p.Ready || p.Execution != "server" || !p.DNSProven || !p.PublicProven || len(p.Comparison.Measurements) != 0 || p.Comparison.Final == nil {
		t.Fatal("missing selected proof", p)
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	f.runner.mu.Lock()
	defer f.runner.mu.Unlock()
	if len(f.runner.workers) == 0 {
		t.Fatal("missing original Manager lease")
	}
	for _, worker := range f.runner.workers {
		if worker.Alive() {
			t.Fatal("joined stop left native worker alive")
		}
	}
}
func TestNodeChainOpenVPNExecutionRestoreKeepsOriginalChoice(t *testing.T) {
	testNodeChainExecutionRestoreKeepsWinner(t, openVPNExecutionRuntimeFixture(t, "auto"))
}

func TestNodeChainOpenVPNExecutionCompareKeepsSharedTargetAndFreshWinner(t *testing.T) {
	f := openVPNExecutionRuntimeFixture(t, "auto")
	var mu sync.Mutex
	var trials []*nodeChainExecutionTrial
	f.engine.beforeDNS = func(context.Context) {
		f.runtime.mu.Lock()
		trial := f.runtime.active
		f.runtime.mu.Unlock()
		mu.Lock()
		if len(trials) == 0 || trials[len(trials)-1] != trial {
			trials = append(trials, trial)
		}
		mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	p := f.runtime.Progress()
	if !p.Ready || !p.Complete || !p.DNSProven || !p.PublicProven || len(p.Prefixes) != 3 || len(p.Comparison.Measurements) != 2 || p.Comparison.Winner == nil || p.Comparison.Final == nil {
		t.Fatal("incomplete original comparison", p)
	}
	for _, m := range append(p.Comparison.Measurements, *p.Comparison.Final) {
		if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != (m.LastNodeMS+m.ExternalMS)/2 {
			t.Fatal("comparison lost two-response average", m)
		}
	}
	measured := p.Comparison.Measurements
	if measured[0].Candidate != f.runtime.candidate("local") || measured[1].Candidate != f.runtime.candidate("server") {
		t.Fatal("candidate identities changed")
	}
	winner := measured[0]
	if *measured[1].ScoreMS < *winner.ScoreMS {
		winner = measured[1]
	}
	if *p.Comparison.Winner != winner.Candidate || p.Comparison.Final.Candidate != winner.Candidate || p.Execution != string(winner.Candidate.Execution) {
		t.Fatal("comparison did not retain lowest eligible score")
	}
	mu.Lock()
	captured := append([]*nodeChainExecutionTrial(nil), trials...)
	mu.Unlock()
	if len(captured) != 3 || captured[0].execution != "local" || captured[1].execution != "server" || captured[2].execution != p.Execution || captured[0].id == captured[1].id || captured[0].id == captured[2].id || captured[1].id == captured[2].id {
		t.Fatal("winner borrowed retired trial")
	}
	f.engine.mu.Lock()
	calls := append([]string(nil), f.engine.publicCalls...)
	opens := f.engine.opens
	f.engine.mu.Unlock()
	if len(calls) != 9 || opens != 1 {
		t.Fatal("missing original middle/final/external proof or unproved activation", calls, opens)
	}
	target := strings.Split(strings.TrimPrefix(p.Comparison.Target, "https://"), "/")[0]
	for _, index := range []int{2, 5, 8} {
		if !strings.HasSuffix(calls[index], "/"+target) {
			t.Fatal("comparison changed random external target between candidates or reproof", calls)
		}
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestNodeChainOpenVPNExecutionCompareTimeoutIsIneligible(t *testing.T) {
	f := openVPNExecutionRuntimeFixture(t, "auto")
	local, _ := f.runtime.projection.ProofInventory("local")
	tag := local[len(local)-1].Tag
	var attempts atomic.Int32
	f.engine.beforeDial = func(_ context.Context, actual, address string) (net.Conn, error, bool) {
		if actual == tag && (address == "1.1.1.1:443" || address == "1.0.0.1:443") && attempts.Add(1) == 2 {
			return nil, context.DeadlineExceeded, true
		}
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	p := f.runtime.Progress()
	if !p.Ready || len(p.Comparison.Measurements) != 2 || p.Comparison.Measurements[0].Eligible || p.Comparison.Measurements[0].ScoreMS != nil || p.Comparison.Measurements[0].Failure == "" || p.Comparison.Winner == nil || p.Comparison.Winner.Execution != routechoice.Server || p.Comparison.Final == nil || !p.Comparison.Final.Eligible {
		t.Fatal("timed out local probe acquired a score or won", p)
	}
}

func TestNodeChainOpenVPNExecutionPrefixRuntimeAndStop(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, execution), func(t *testing.T) {
				_, prep, source := openVPNExecutionFixture(t, count-2, "wg", "udp", "", execution, "")
				f := newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, prep)
				// Match the existing complete imported-prefix lifecycle fixture.
				// Individual runtime/proof/observation deadlines remain unchanged.
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if err := f.runtime.Run(ctx); err != nil {
					t.Fatal("complete original OpenVPN runtime", err)
				}
				if !f.runtime.Progress().Ready {
					t.Fatal("complete original runtime not ready")
				}
				owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
				measurement, err := f.runtime.NewHopMeasurementContext(ctx, owner)
				if err != nil {
					t.Fatal("complete original selected measurement", err)
				}
				latency, err := measurement.NewLatencyBenchmarkContext(ctx, func(call context.Context) error { return f.runtime.HealthyContext(call) })
				if err != nil {
					t.Fatal("complete original latency capture", err)
				}
				if err = latency.Close(); err != nil {
					t.Fatal(err)
				}
				if err = measurement.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := f.runtime.CaptureRestoreContext(ctx); err != nil {
					t.Fatal("complete original restore receipt", err)
				}
				if err := f.runtime.CloseContext(ctx); err != nil {
					t.Fatal("complete original joined stop", err)
				}
				f.runner.mu.Lock()
				defer f.runner.mu.Unlock()
				if len(f.runner.workers) == 0 {
					t.Fatal("original Manager not acquired")
				}
				for _, worker := range f.runner.workers {
					if worker.Alive() {
						t.Fatal("original worker survived joined stop")
					}
				}
			})
		}
	}
}

func TestNodeChainOpenVPNExecutionDiscoveryKeepsTypedSourceAndRestoreProposal(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "restore"}[restore], func(t *testing.T) {
			f := openVPNExecutionRuntimeFixture(t, "auto")
			prep := f.runtime.projection.preparation
			engine := &socksExecutionDiscoveryEngine{nodeChainExecutionRuntimeEngine: f.engine, preparation: prep}
			owner, err := NewNodeChainExecutionDiscoveryOwner(prep, engine)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			t.Cleanup(func() {
				if err := owner.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			discovery, err := owner.Discover(ctx)
			if err != nil {
				t.Fatal("original authenticated entry discovery", err)
			}
			if len(discovery.Sources) != 1 || discovery.Sources[0].Schema != 5 {
				t.Fatal("discovery lost typed server descriptor")
			}
			var projection *NodeChainExecutionProjection
			if restore {
				projection, err = owner.PlanOriginalContext(ctx, f.runtime.projection.policy)
			} else {
				projection, err = owner.PlanContext(ctx, "", 32003)
			}
			if err != nil || projection.preparation != prep || projection.policy.openvpn != prep.openvpn || projection.policy.source.Schema != 5 || projection.policy.local != prep.openvpn.source || !reflect.DeepEqual(projection.policy.Request().LocalPacketPositions, []int{0}) {
				t.Fatal("discovery replaced original typed source or packet positions", err)
			}
			if restore && (projection.Source() != f.runtime.projection.Source() || !reflect.DeepEqual(projection.policy.Front(), f.runtime.projection.policy.Front()) || projection.Config() != f.runtime.projection.Config()) {
				t.Fatal("restoration replaced original private proposal")
			}
			if err := owner.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.PlanContext(ctx, "", 32003); err == nil {
				t.Fatal("closed original discovery reopened")
			}
		})
	}
}

func TestNodeChainOpenVPNExecutionLastReopensOnlyAfterFreshDiscovery(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			old := openVPNExecutionRuntimeFixture(t, "auto")
			old.engine.localDelay, old.engine.serverDelay = 200*time.Millisecond, time.Millisecond
			if winner == "local" {
				old.engine.localDelay, old.engine.serverDelay = time.Millisecond, 200*time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			if err := old.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			last, err := old.runtime.CaptureLastContext(ctx)
			if err != nil || last.Execution() != winner {
				t.Fatal("original Last", err)
			}
			if err := old.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			prep, err := ParseNodeChainOpenVPNExecutionPreparation(old.runtime.projection.preparation.Source())
			if err != nil {
				t.Fatal(err)
			}
			last, err = ParseNodeChainExecutionLast(last.JSON(), prep)
			if err != nil {
				t.Fatal(err)
			}
			fresh := newNodeChainExecutionRuntimeFixtureFromPreparation(t, old.runtime.projection.policy.source, prep)
			engine := &socksExecutionDiscoveryEngine{nodeChainExecutionRuntimeEngine: fresh.engine, preparation: prep}
			owner, err := NewNodeChainExecutionDiscoveryOwner(prep, engine)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := owner.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			if _, err := owner.PlanLastContext(ctx, last); err == nil {
				t.Fatal("Last bypassed fresh discovery")
			}
			if _, err := owner.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			plan, err := owner.PlanLastContext(ctx, last)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewNodeChainExecutionLastRuntime(ctx, plan, fresh.engine); err == nil {
				t.Fatal("Last bypassed original discovery join")
			}
			if err := owner.Close(ctx); err != nil {
				t.Fatal(err)
			}
			projection, err := plan.Projection()
			if err != nil {
				t.Fatal(err)
			}
			e := fresh.engine
			e.mu.Lock()
			previous := e.projection
			for _, choice := range []string{"local", "server"} {
				before, _ := previous.ProofInventory(choice)
				after, _ := projection.ProofInventory(choice)
				for i, proof := range before {
					if i == len(before)-2 {
						e.peers[after[i].Tag+"/1.1.1.1:443"] = e.publicPeer
						continue
					}
					api, _ := privateAPI(predecessorText(previous.policy.local.nodes[i].profile, "router_api"))
					e.peers[after[i].Tag+"/"+api.Host] = e.peers[proof.Tag+"/"+api.Host]
				}
			}
			e.projection = projection
			e.identity.SourceSHA256, e.identity.ConfigSHA256 = projection.SourceSHA256(), projection.ConfigSHA256()
			e.mu.Unlock()
			runtime, err := NewNodeChainExecutionLastRuntime(ctx, plan, e)
			if err != nil {
				t.Fatal(err)
			}
			runtime.testTLS = fresh.trust
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := runtime.CloseContext(cleanup); err != nil {
					t.Error(err)
				}
			})
			if err := runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			p := runtime.Progress()
			if !p.Ready || p.Execution != winner || p.Comparison.Target != last.Target() || len(p.Comparison.Measurements) != 0 || p.Comparison.Final == nil {
				t.Fatal("Last reran comparison or lost fresh proof", p)
			}
			if runtime.projection.policy.Request().SessionID == old.runtime.projection.policy.Request().SessionID {
				t.Fatal("Last borrowed original lease")
			}
			if err := runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeChainOpenVPNExecutionMissingObserverRefusedBeforeDiscovery(t *testing.T) {
	f := openVPNExecutionRuntimeFixture(t, "server")
	missing := socksExecutionMissingObserver{f.engine, f.engine}
	if _, err := NewNodeChainExecutionRuntime(f.runtime.projection, missing); err == nil {
		t.Fatal("native runtime omitted original OpenVPN observer")
	}
	if _, err := NewNodeChainExecutionDiscoveryOwner(f.runtime.projection.preparation, missing); err == nil {
		t.Fatal("discovery omitted original OpenVPN observer")
	}
}
func TestNodeChainOpenVPNExecutionRuntimeRefusesChangedProofOrOwner(t *testing.T) {
	for _, fault := range []string{"public", "dns", "final", "foreign-source", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			f := openVPNExecutionRuntimeFixture(t, "server")
			switch fault {
			case "public":
				f.engine.wrongPublic = true
			case "dns":
				f.engine.failDNS = true
			case "final":
				f.engine.wrongPrefix = 2
			case "foreign-source":
				original := f.runtime.projection.preparation.openvpn.source
				fresh, err := NewNodeChain(original.sourceJSON)
				if err != nil {
					t.Fatal(err)
				}
				f.runtime.projection.preparation.openvpn.source = fresh
				defer func() { f.runtime.projection.preparation.openvpn.source = original }()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if fault == "cancelled" {
				cancel()
			}
			if err := f.runtime.Run(ctx); err == nil {
				t.Fatal("unproved or cancelled original execution admitted")
			}
			f.engine.mu.Lock()
			open := f.engine.open || f.engine.opens != 0
			f.engine.mu.Unlock()
			if open || f.runtime.Progress().Ready {
				t.Fatal("failed original proof opened application")
			}
		})
	}
}

func TestNodeChainOpenVPNExecutionRetainsFailedOriginalStop(t *testing.T) {
	f := openVPNExecutionRuntimeFixture(t, "server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	f.runner.failStop.Store(true)
	short, done := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err := f.runtime.CloseContext(short)
	done()
	if err == nil {
		t.Fatal("failed original Stop marked joined")
	}
	if f.runtime.Progress().Ready {
		t.Fatal("failed cleanup retained application readiness")
	}
	f.runner.mu.Lock()
	alive := false
	for _, worker := range f.runner.workers {
		alive = alive || worker.Alive()
	}
	f.runner.mu.Unlock()
	if !alive {
		t.Fatal("failed original Stop handle discarded")
	}
	f.runner.failStop.Store(false)
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("original Stop retry", err)
	}
	f.runner.mu.Lock()
	defer f.runner.mu.Unlock()
	for _, worker := range f.runner.workers {
		if worker.Alive() {
			t.Fatal("original worker not joined")
		}
	}
}
