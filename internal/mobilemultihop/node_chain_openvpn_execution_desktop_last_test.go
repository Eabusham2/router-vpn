package mobilemultihop

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Saved-record controls are source-only. Actual loopback proof/lease revalidation follows below; native routing remains an explicit boundary double.
func TestDesktopOpenVPNExecutionSavedChoiceBinding(t *testing.T) {
	original, prep, request := desktopOpenVPNExecutionFixture(t, 1, "wg", "tcp", "", "darwin", "auto", 0)
	policy, err := NewNodeChainOpenVPNExecutionPolicy(prep, startJSON(t, request))
	if err != nil {
		t.Fatal(err)
	}
	p, err := prep.BindExecution(policy)
	if err != nil {
		t.Fatal(err)
	}
	source := p.policy.source
	digest, err := source.Server.Digest()
	if err != nil {
		t.Fatal(err)
	}
	last := NodeChainExecutionLast{record: nodeChainExecutionLastRecord{Schema: 1, LocalSourceSHA256: prep.LocalSourceSHA256(), LocalInputSHA256: externalDigest([]byte(prep.LocalSource())), Setting: p.Execution(), Execution: "server", Target: Targets[0], Descriptor: source.Server, DescriptorSHA256: digest, DNSPolicySHA256: source.Request.DNSPolicySHA256, EntryHost: p.policy.front.Host, Peer: source.Request.Peer, FirstPort: source.FirstPort, LastPort: source.LastPort, Port: source.Request.Port, DesktopTargetOS: "darwin"}}
	last.record.Digest = nodeChainExecutionLastDigest(last.record)
	raw, _ := json.Marshal(last.record)
	last.raw = string(raw)
	if err = last.ValidateOpenVPNDesktopProjection(p); err != nil {
		t.Fatal(err)
	}
	if last.ValidateDesktopProjection(p) == nil {
		t.Fatal("typed last borrowed paired projection")
	}
	fresh, err := NewDesktopNodeChainPolicy(original.original, strings.Repeat("f", 32), "darwin", 1280)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewDesktopNodeChainOpenVPNExecutionLastPreparation(fresh, "auto", last.JSON())
	if err != nil {
		t.Fatal("fresh session/MTU source restore", err)
	}
	saved, ok, err := restored.OpenVPNDesktopLast()
	if err != nil || !ok || saved.JSON() != last.JSON() {
		t.Fatal("saved choice changed", err)
	}
	parsed, err := ParseDesktopNodeChainOpenVPNExecutionPreparation(restored.Source())
	if err != nil || parsed.Config() != restored.Config() {
		t.Fatal("saved child source", err)
	}
	if _, _, err = restored.DesktopLast(); err == nil {
		t.Fatal("paired Last opened")
	}
	for _, fault := range []string{"target", "choice", "source", "setting"} {
		t.Run(fault, func(t *testing.T) {
			changed := last.record
			switch fault {
			case "target":
				changed.DesktopTargetOS = "linux"
			case "choice":
				changed.Execution = "auto"
			case "source":
				changed.LocalInputSHA256 = strings.Repeat("f", 64)
			case "setting":
				changed.Setting = "server"
			}
			changed.Digest = nodeChainExecutionLastDigest(changed)
			raw, _ := json.Marshal(changed)
			if _, err := NewDesktopNodeChainOpenVPNExecutionLastPreparation(fresh, "auto", string(raw)); err == nil {
				t.Fatal("foreign saved choice accepted")
			}
		})
	}
}

func TestDesktopOpenVPNExecutionLastRuntimeReproof(t *testing.T) {
	for _, choice := range []string{"server", "local"} {
		t.Run(choice, func(t *testing.T) { testDesktopOpenVPNExecutionLastRuntimeReproof(t, choice) })
	}
	t.Run("changed-native-owner", testDesktopOpenVPNExecutionLastRefusesNativeChange)
}

func testDesktopOpenVPNExecutionLastRuntimeReproof(t *testing.T, choice string) {
	desktop, prep, source := desktopOpenVPNExecutionFixture(t, 1, "wg", "tcp", "", "linux", "auto", 0)
	original := desktop.original
	f := newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, prep)
	projection := f.runtime.projection
	f.engine.identity = NodeChainIdentity{"desktop-openvpn-box", desktop.metadata.SessionID, "network", projection.SourceSHA256(), projection.ConfigSHA256()}
	if choice == "local" {
		f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 200*time.Millisecond
	} else {
		f.engine.localDelay, f.engine.serverDelay = 200*time.Millisecond, time.Millisecond
	}
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if err = f.runtime.Run(ctx); err != nil {
		t.Fatal("original desktop proof", err)
	}
	last, err := f.runtime.CaptureOpenVPNDesktopLastContext(ctx)
	if err != nil || last.Execution() != choice {
		t.Fatal("captured desktop Last did not retain the proved concrete choice", choice, err)
	}
	oldSession := projection.policy.Request().SessionID
	if err = f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	// Retire the old native boundary double separately from the actual shared
	// worker/lease join; a real host must supply its original Box close receipt.
	f.engine.mu.Lock()
	f.engine.alive = false
	f.engine.mu.Unlock()
	fresh, err := NewDesktopNodeChainPolicy(original, strings.Repeat("d", 32), "linux", 1280)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewDesktopNodeChainOpenVPNExecutionLastPreparation(fresh, "auto", last.JSON())
	if err != nil {
		t.Fatal(err)
	}
	nextPolicy, err := NewNodeChainOpenVPNExecutionPolicy(next, startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	nextProjection, err := next.BindExecution(nextPolicy)
	if err != nil {
		t.Fatal(err)
	}
	engine := cloneNodeChainExecutionRuntimeEngine(f.engine)
	engine.projection = nextProjection
	engine.identity = NodeChainIdentity{"fresh-box", strings.Repeat("d", 32), "fresh-network", next.SourceSHA256(), next.ConfigSHA256()}
	owner, err := NewNodeChainExecutionDiscoveryOwner(next, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	if _, err = owner.Discover(ctx); err != nil {
		t.Fatal("fresh discovery", err)
	}
	plan, err := owner.PlanLastContext(ctx, last)
	if err != nil {
		t.Fatal("fresh saved plan", err)
	}
	if err = owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	nextProjection, err = plan.Projection()
	if err != nil {
		t.Fatal(err)
	}
	if nextProjection.policy.Request().SessionID == oldSession {
		t.Fatal("reused retired lease identity")
	}
	// Remap only the explicit fixture dial table to fresh compiled tags; the
	// same original HTTP/TLS peer handlers and private identities remain captured.
	for _, selected := range []string{"local", "server"} {
		oldProofs, _ := engine.projection.ProofInventory(selected)
		newProofs, _ := nextProjection.ProofInventory(selected)
		for i, proof := range oldProofs {
			for key, value := range engine.peers {
				if strings.HasPrefix(key, proof.Tag+"/") {
					engine.peers[newProofs[i].Tag+strings.TrimPrefix(key, proof.Tag)] = value
				}
			}
		}
	}
	engine.projection = nextProjection
	engine.identity.SourceSHA256 = nextProjection.SourceSHA256()
	engine.identity.ConfigSHA256 = nextProjection.ConfigSHA256()
	runtime, err := NewNodeChainExecutionLastRuntime(ctx, plan, engine)
	if err != nil {
		t.Fatal(err)
	}
	runtime.testTLS = f.trust
	defer runtime.CloseContext(context.Background())
	if err = runtime.Run(ctx); err != nil {
		t.Fatal("fresh saved proof", err)
	}
	progress := runtime.Progress()
	if !progress.Ready || progress.Execution != last.Execution() || progress.Comparison.Target != last.Target() || len(progress.Comparison.Measurements) != 0 || len(engine.selections) != 1 || len(engine.dnsCalls) == 0 {
		t.Fatal("saved choice reranked or lost selected proof", progress)
	}
	again, err := runtime.CaptureOpenVPNDesktopLastContext(ctx)
	if err != nil || again.JSON() != last.JSON() {
		t.Fatal("saved bindings changed", err)
	}
}

// Same four/eight-node lifecycle and 20-second operation bound as the shared
// complete-prefix matrix. Physical routing remains the explicit fixture double.
func TestDesktopOpenVPNExecutionPrefixRuntimeAndStop(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, choice := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, choice), func(t *testing.T) {
				original, prep, source := desktopOpenVPNExecutionFixture(t, count-2, "wg", "udp", "", "linux", choice, 0)
				f := newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, prep)
				f.engine.identity = NodeChainIdentity{"original-desktop-openvpn", original.metadata.SessionID, "network", f.runtime.projection.SourceSHA256(), f.runtime.projection.ConfigSHA256()}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if err := f.runtime.Run(ctx); err != nil {
					t.Fatal("original desktop runtime", err)
				}
				if !f.runtime.Progress().Ready {
					t.Fatal("desktop original path unproved")
				}
				measurement, err := f.runtime.NewHopMeasurementContext(ctx, &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime})
				if err != nil {
					t.Fatal("selected original measurement", err)
				}
				if err := measurement.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := f.runtime.CaptureOpenVPNDesktopLastContext(ctx); err != nil {
					t.Fatal("original selected Last", err)
				}
				if err := f.runtime.CloseContext(ctx); err != nil {
					t.Fatal("original joined stop", err)
				}
				f.runner.mu.Lock()
				defer f.runner.mu.Unlock()
				for _, worker := range f.runner.workers {
					if worker.Alive() {
						t.Fatal("original worker not joined")
					}
				}
			})
		}
	}
}

// The native boundary is an explicit double. Its original desktop-native
// pointer changes during Last's actual observation, without racing writes to
// immutable policy fields or pretending to supply an OS endpoint proof.
type desktopOpenVPNLastMutationEngine struct {
	*nodeChainExecutionRuntimeEngine
	preparation    *NodeChainExecutionPreparation
	native         atomic.Pointer[NodeChain]
	replacement    *NodeChain
	armed, changed atomic.Bool
}

func (e *desktopOpenVPNLastMutationEngine) ObserveOpenVPNExecutionContext(ctx context.Context, source *NodeChain) error {
	if err := e.nodeChainExecutionRuntimeEngine.ObserveOpenVPNExecutionContext(ctx, source); err != nil {
		return err
	}
	if e.armed.CompareAndSwap(true, false) {
		e.native.Store(e.replacement)
		e.changed.Store(true)
	}
	if e.native.Load() != e.preparation.openvpn.desktop.native {
		return nodeChainExecutionError
	}
	return ctx.Err()
}
func testDesktopOpenVPNExecutionLastRefusesNativeChange(t *testing.T) {
	original, prep, source := desktopOpenVPNExecutionFixture(t, 1, "wg", "tcp", "", "linux", "server", 0)
	f := newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, prep)
	f.engine.identity = NodeChainIdentity{"original-desktop-openvpn", original.metadata.SessionID, "network", f.runtime.projection.SourceSHA256(), f.runtime.projection.ConfigSHA256()}
	replacement := *original.chain
	engine := &desktopOpenVPNLastMutationEngine{nodeChainExecutionRuntimeEngine: f.engine, preparation: prep, replacement: &replacement}
	engine.native.Store(original.chain)
	f.runtime.engine = engine
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal("original desktop Server", err)
	}
	engine.armed.Store(true)
	last, err := f.runtime.CaptureOpenVPNDesktopLastContext(ctx)
	if err == nil || last.JSON() != "" || !engine.changed.Load() || f.runtime.Progress().Ready {
		t.Fatal("Last accepted a replacement original native source", err)
	}
	// Restore only the original boundary double so failed-capture cleanup can
	// join the original worker. This grants no new record or application path.
	engine.native.Store(original.chain)
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("original failed Last cleanup", err)
	}
}
