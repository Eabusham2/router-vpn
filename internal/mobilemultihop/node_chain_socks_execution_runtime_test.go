package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/routechoice"
)

// The actual HTTP/TLS proof clients, Manager leases, controller, comparison and
// restore receipts execute. Native routing/registry/DNS and remote worker I/O
// remain explicit modeled boundaries; this does not claim encrypted acceptance.
func (e *nodeChainExecutionRuntimeEngine) ObserveSOCKSExecutionContext(ctx context.Context, original *NodeChainSOCKSSource) error {
	if ctx == nil || ctx.Err() != nil || e.projection == nil || e.projection.preparation.socks == nil || original != e.projection.preparation.socks.source {
		return nodeChainExecutionError
	}
	return original.validate()
}
func socksExecutionRuntimeFixture(t *testing.T, execution string) *nodeChainExecutionRuntimeFixture {
	t.Helper()
	_, _, source := socksExecutionFixture(t, "wg", "password", execution)
	return newNodeChainExecutionRuntimeFixtureFromSource(t, source)
}
func TestNodeChainSOCKSExecutionRuntimeServerUsesOriginalLeaseAndJoinedStop(t *testing.T) {
	f := socksExecutionRuntimeFixture(t, "server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	p := f.runtime.Progress()
	if !p.Ready || p.Execution != "server" || len(p.Comparison.Measurements) != 0 || p.Comparison.Final == nil {
		t.Fatal("explicit server reran comparison or omitted proof", p)
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
			t.Fatal("joined stop left original server worker alive")
		}
	}
}
func TestNodeChainSOCKSExecutionCompareKeepsSharedTargetAndFreshWinner(t *testing.T) {
	f := socksExecutionRuntimeFixture(t, "auto")
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
func TestNodeChainSOCKSExecutionCompareTimeoutIsIneligible(t *testing.T) {
	f := socksExecutionRuntimeFixture(t, "auto")
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
func TestNodeChainSOCKSExecutionRestoreKeepsOriginalChoice(t *testing.T) {
	testNodeChainExecutionRestoreKeepsWinner(t, socksExecutionRuntimeFixture(t, "auto"))
}

type socksExecutionMissingObserver struct {
	NodeChainExecutionEngine
	NodeChainExecutionSelectionEpochEngine
}

func TestNodeChainSOCKSExecutionMissingObserverRefusedBeforeDiscovery(t *testing.T) {
	f := socksExecutionRuntimeFixture(t, "server")
	missing := socksExecutionMissingObserver{f.engine, f.engine}
	if _, err := NewNodeChainExecutionRuntime(f.runtime.projection, missing); err == nil {
		t.Fatal("native runtime omitted original SOCKS observer")
	}
	if _, err := NewNodeChainExecutionDiscoveryOwner(f.runtime.projection.preparation, missing); err == nil {
		t.Fatal("discovery omitted original SOCKS observer")
	}
}
func TestNodeChainSOCKSExecutionRuntimeRefusesChangedProofOrOwner(t *testing.T) {
	for _, fault := range []string{"public", "dns", "final", "foreign-source", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			f := socksExecutionRuntimeFixture(t, "server")
			switch fault {
			case "public":
				f.engine.wrongPublic = true
			case "dns":
				f.engine.failDNS = true
			case "final":
				f.engine.wrongPrefix = 2
			case "foreign-source":
				original := f.runtime.projection.preparation.socks.source
				fresh, err := NewNodeChainSOCKSSource(original.sourceJSON)
				if err != nil {
					t.Fatal(err)
				}
				f.runtime.projection.preparation.socks.source = fresh
				defer func() { f.runtime.projection.preparation.socks.source = original }()
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

// Changed equal-content source cannot gain observer authority by implementing
// the interface alone; native adapters must compare their original pointer.
func TestNodeChainSOCKSExecutionObserverFailureRetainsCaller(t *testing.T) {
	original, p, _ := socksExecutionFixture(t, "wg", "password", "auto")
	failure := errors.New("original association join pending")
	observer := &socksExecutionObserverFixture{source: original, failure: failure}
	if err := p.observeSOCKSExecutionContext(context.Background(), observer); !errors.Is(err, failure) {
		t.Fatal("observer replaced original failure", err)
	}
}

type socksExecutionDiscoveryEngine struct {
	*nodeChainExecutionRuntimeEngine
	preparation *NodeChainExecutionPreparation
}

func (e *socksExecutionDiscoveryEngine) ObserveChainContext(ctx context.Context) (NodeChainIdentity, error) {
	identity, err := e.nodeChainExecutionRuntimeEngine.ObserveChainContext(ctx)
	if err != nil {
		return identity, err
	}
	identity.SourceSHA256, identity.ConfigSHA256 = e.preparation.SourceSHA256(), e.preparation.ConfigSHA256()
	return identity, nil
}
func TestNodeChainSOCKSExecutionDiscoveryKeepsTypedSourceAndRestoreProposal(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "restore"}[restore], func(t *testing.T) {
			f := socksExecutionRuntimeFixture(t, "auto")
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
			if len(discovery.Sources) != 1 || discovery.Sources[0].Schema != 3 {
				t.Fatal("discovery lost typed server descriptor")
			}
			var projection *NodeChainExecutionProjection
			if restore {
				projection, err = owner.PlanOriginalContext(ctx, f.runtime.projection.policy)
			} else {
				projection, err = owner.PlanContext(ctx, "", 32003)
			}
			if err != nil || projection.preparation != prep || projection.policy.socks != prep.socks || projection.policy.source.Schema != 3 || projection.policy.local.socksSource != prep.socks.source || !reflect.DeepEqual(projection.policy.Request().LocalPacketPositions, []int{0}) {
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
