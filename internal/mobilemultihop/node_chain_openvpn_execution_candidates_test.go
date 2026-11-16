package mobilemultihop

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
	"router-vpn/internal/routechoice"
)

// The native boundary double keeps construction ownership independent from the
// actual Local provider state. All discovery, Manager, TLS proof and comparison
// operations below still execute through the existing authenticated fixture.
type openVPNCandidateEngine struct {
	*nodeChainExecutionRuntimeEngine
	ownerFailure   bool
	stateFailure   error
	failAfterFirst bool
	stateCalls     atomic.Int32
	generation     atomic.Uint64
}

func (e *openVPNCandidateEngine) ObserveOpenVPNExecutionContext(ctx context.Context, source *NodeChain) error {
	if e.ownerFailure {
		return errors.New("original native OpenVPN owner refused")
	}
	return e.nodeChainExecutionRuntimeEngine.ObserveOpenVPNExecutionContext(ctx, source)
}
func (e *openVPNCandidateEngine) OpenVPNMiddleStateContext(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
	call := e.stateCalls.Add(1)
	if e.stateFailure != nil && (!e.failAfterFirst || call > 1) {
		return nativeopenvpn.PacketObservation{}, e.stateFailure
	}
	state, err := e.nodeChainExecutionRuntimeEngine.OpenVPNMiddleStateContext(ctx, tag)
	state.Remote.Generation += e.generation.Load()
	return state, err
}

func TestNodeChainOpenVPNExecutionIndependentCandidateConnection(t *testing.T) {
	for _, fault := range []string{"server-pending-local", "compare-local-auth-failure", "compare-local-lost-connection", "both-candidates-fail", "server-foreign-owner"} {
		t.Run(fault, func(t *testing.T) {
			choice := "auto"
			if fault == "server-pending-local" || fault == "server-foreign-owner" {
				choice = "server"
			}
			f := openVPNExecutionRuntimeFixture(t, choice)
			e := &openVPNCandidateEngine{nodeChainExecutionRuntimeEngine: f.engine, stateFailure: errors.New("original Local provider authentication refused")}
			switch fault {
			case "server-pending-local":
				e.stateFailure = nativeopenvpn.ErrRemotePending
			case "compare-local-lost-connection":
				e.failAfterFirst = true
			case "both-candidates-fail":
				f.engine.wrongPublic = true
			case "server-foreign-owner":
				e.ownerFailure = true
			}
			f.runtime.engine = e
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := f.runtime.Run(ctx)
			refused := fault == "both-candidates-fail" || fault == "server-foreign-owner"
			if refused {
				if err == nil || f.runtime.Progress().Ready {
					t.Fatal("unproved candidate or foreign native owner admitted")
				}
				f.engine.mu.Lock()
				opened := f.engine.opens
				f.engine.mu.Unlock()
				if opened != 0 {
					t.Fatal("unproved Server opened application")
				}
			} else {
				if err != nil {
					t.Fatal("independent Server depended on Local provider", err)
				}
				p := f.runtime.Progress()
				if !p.Ready || p.Execution != "server" || !p.DNSProven || !p.PublicProven || p.Comparison.Final == nil || !p.Comparison.Final.Eligible {
					t.Fatal("Server lacked its own complete proof", p)
				}
				if choice == "auto" {
					if len(p.Comparison.Measurements) != 2 || p.Comparison.Measurements[0].Candidate.Execution != routechoice.Local || p.Comparison.Measurements[0].Eligible || p.Comparison.Measurements[0].ScoreMS != nil || p.Comparison.Measurements[0].Failure == "" || !p.Comparison.Measurements[1].Eligible || p.Comparison.Winner == nil || p.Comparison.Winner.Execution != routechoice.Server {
						t.Fatal("failed Local candidate acquired authority or suppressed Server", p.Comparison)
					}
				}
				if err := f.runtime.HealthyContext(ctx); err != nil {
					t.Fatal("proved Server later depended on Local provider", err)
				}
			}
			if choice == "server" && e.stateCalls.Load() != 0 {
				t.Fatal("Server read unrelated Local connected authority")
			}
			if choice == "auto" && e.stateCalls.Load() == 0 {
				t.Fatal("Local candidate bypassed its own connected state")
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal("original cleanup", err)
			}
			f.runner.mu.Lock()
			defer f.runner.mu.Unlock()
			for _, worker := range f.runner.workers {
				if worker.Alive() {
					t.Fatal("independent candidate left original worker alive")
				}
			}
		})
	}
}

type openVPNCandidateDiscoveryEngine struct {
	*socksExecutionDiscoveryEngine
	ownerFailure bool
	stateCalls   atomic.Int32
}

func (e *openVPNCandidateDiscoveryEngine) ObserveOpenVPNExecutionContext(ctx context.Context, source *NodeChain) error {
	if e.ownerFailure {
		return errors.New("original discovery native owner refused")
	}
	return e.nodeChainExecutionRuntimeEngine.ObserveOpenVPNExecutionContext(ctx, source)
}
func (e *openVPNCandidateDiscoveryEngine) OpenVPNMiddleStateContext(context.Context, string) (nativeopenvpn.PacketObservation, error) {
	e.stateCalls.Add(1)
	return nativeopenvpn.PacketObservation{}, nativeopenvpn.ErrRemotePending
}
func TestNodeChainOpenVPNExecutionDiscoveryRetainsOwnerWithoutLocalConnection(t *testing.T) {
	for _, fault := range []string{"pending-local", "foreign-owner"} {
		t.Run(fault, func(t *testing.T) {
			f := openVPNExecutionRuntimeFixture(t, "auto")
			prep := f.runtime.projection.preparation
			e := &openVPNCandidateDiscoveryEngine{socksExecutionDiscoveryEngine: &socksExecutionDiscoveryEngine{nodeChainExecutionRuntimeEngine: f.engine, preparation: prep}, ownerFailure: fault == "foreign-owner"}
			owner, err := NewNodeChainExecutionDiscoveryOwner(prep, e)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := owner.Close(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = owner.Discover(ctx)
			if fault == "foreign-owner" {
				if err == nil {
					t.Fatal("discovery omitted native construction owner")
				}
				return
			}
			if err != nil {
				t.Fatal("entry discovery depended on unrelated Local provider", err)
			}
			plan, err := owner.PlanContext(ctx, "", 32003)
			if err != nil || plan.preparation != prep || plan.policy.openvpn != prep.openvpn {
				t.Fatal("discovery lost original typed preparation", err)
			}
			if e.stateCalls.Load() != 0 {
				t.Fatal("discovery acquired Local connected authority")
			}
		})
	}
}

func TestNodeChainOpenVPNExecutionLocalWinnerRetainsConnectedReceipt(t *testing.T) {
	f := openVPNExecutionRuntimeFixture(t, "auto")
	f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 200*time.Millisecond
	e := &openVPNCandidateEngine{nodeChainExecutionRuntimeEngine: f.engine}
	f.runtime.engine = e
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if f.runtime.Progress().Execution != "local" || e.stateCalls.Load() == 0 {
		t.Fatal("Local winner lacked original connected proof")
	}
	e.generation.Store(1)
	if err := f.runtime.HealthyContext(ctx); err == nil {
		t.Fatal("Local winner borrowed replacement connected receipt")
	}
	if f.runtime.Progress().Ready {
		t.Fatal("changed Local connection retained readiness")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
}
