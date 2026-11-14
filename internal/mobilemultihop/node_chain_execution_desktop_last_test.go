package mobilemultihop

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// This is a source/command fixture, not native proof acceptance. The runtime
// Last tests independently capture real loopback proof/lease results.
func desktopExecutionSavedChoiceFixture(t *testing.T, p *NodeChainExecutionProjection, execution string) NodeChainExecutionLast {
	t.Helper()
	source := p.policy.source
	digest, err := source.Server.Digest()
	if err != nil {
		t.Fatal(err)
	}
	last := NodeChainExecutionLast{record: nodeChainExecutionLastRecord{Schema: 1, LocalSourceSHA256: p.preparation.LocalSourceSHA256(),
		LocalInputSHA256: externalDigest([]byte(p.preparation.LocalSource())), Setting: p.Execution(), Execution: execution, Target: Targets[0],
		Descriptor: source.Server, DescriptorSHA256: digest, DNSPolicySHA256: source.Request.DNSPolicySHA256,
		EntryHost: p.policy.front.Host, Peer: source.Request.Peer, FirstPort: source.FirstPort, LastPort: source.LastPort,
		Port: source.Request.Port, DesktopTargetOS: p.preparation.desktop.Metadata().TargetOS}}
	last.record.Digest = nodeChainExecutionLastDigest(last.record)
	raw, err := json.Marshal(last.record)
	if err != nil {
		t.Fatal(err)
	}
	last.raw = string(raw)
	if last.validateProjection(p) != nil {
		t.Fatal("invalid source fixture")
	}
	return last
}

// Shipping HTTP/TLS discovery, proof, lease and LastRuntime execute here.
// Native routing/TUN and server worker receipts remain explicit boundary
// doubles, as in the original execution fixture; this is not device acceptance.
func TestDesktopNodeChainExecutionLastFreshlyProvesAuthenticatedSavedChoice(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			old := newNodeChainExecutionRuntimeFixture(t, "auto")
			desktopExecutionRuntimeProjection(t, old)
			// The shared peer handlers close over the original generic tags;
			// desktop projection replaces those tags. Delay the actual retained
			// desktop final route at its dial boundary, without altering selection.
			old.engine.localDelay, old.engine.serverDelay = time.Millisecond, time.Millisecond
			slower := "local"
			if winner == "local" {
				slower = "server"
			}
			slowProofs, _ := old.engine.projection.ProofInventory(slower)
			slowTag := slowProofs[len(slowProofs)-1].Tag
			lastNode := old.engine.projection.policy.local.nodes[len(slowProofs)-1]
			lastAPI, _ := privateAPI(predecessorText(lastNode.profile, "router_api"))
			old.engine.beforeDial = func(call context.Context, tag, address string) (net.Conn, error, bool) {
				if tag == slowTag && (address == lastAPI.Host || address == "1.1.1.1:443" || address == "1.0.0.1:443") {
					select {
					case <-call.Done():
						return nil, call.Err(), true
					case <-time.After(200 * time.Millisecond):
					}
				}
				return nil, nil, false
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			if err := old.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			last, err := old.runtime.CaptureLastContext(ctx)
			if err != nil || last.Execution() != winner {
				t.Fatal("original desktop did not prove selected winner", winner, last.Execution(), err)
			}
			oldSession := old.runtime.projection.policy.Request().SessionID
			if err := old.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			fresh := newNodeChainExecutionRuntimeFixture(t, "auto")
			source := desktopExecutionRuntimeProjection(t, fresh)
			original, _, _ := desktopExecutionProjection(t, source, "linux", strings.Repeat("b", 32), 1400)
			prep, err := NewDesktopNodeChainExecutionLastPreparation(original, "auto", last.JSON())
			if err != nil {
				t.Fatal(err)
			}
			fresh.engine.mu.Lock()
			fresh.engine.identity = NodeChainIdentity{"fresh-desktop-box", original.Metadata().SessionID, "fresh-network", prep.SourceSHA256(), prep.ConfigSHA256()}
			fresh.engine.mu.Unlock()
			owner, err := NewNodeChainExecutionDiscoveryOwner(prep, fresh.engine)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := owner.Close(cleanup); err != nil {
					t.Error(err)
				}
			})
			if _, err := owner.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			plan, err := owner.PlanLastContext(ctx, last)
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.Close(ctx); err != nil {
				t.Fatal(err)
			}
			projection := nodeChainExecutionAdoptLastFixture(t, fresh, plan)
			if projection.preparation != prep || projection.policy.Request().SessionID == oldSession {
				t.Fatal("saved choice reused old preparation or server credentials")
			}
			runtime, err := NewNodeChainExecutionLastRuntime(ctx, plan, fresh.engine)
			if err != nil {
				t.Fatal(err)
			}
			runtime.testTLS, fresh.runtime = fresh.trust, runtime
			if err := runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			progress := runtime.Progress()
			fresh.engine.mu.Lock()
			selections, dns, proofs := len(fresh.engine.selections), len(fresh.engine.dnsCalls), len(fresh.engine.proofCalls)
			fresh.engine.mu.Unlock()
			if !progress.Ready || progress.Execution != winner || progress.Comparison.Target != last.Target() || len(progress.Comparison.Measurements) != 0 || selections != 1 || dns == 0 || proofs < len(original.Metadata().Prefixes) {
				t.Fatal("saved desktop choice reran Compare or skipped selected proof", progress, selections, dns, proofs)
			}
			fresh.mu.Lock()
			leases := 0
			for _, request := range fresh.requests {
				if request.method == "PUT" {
					leases++
					if request.session == oldSession {
						t.Error("saved desktop choice reused retired server lease")
					}
				}
			}
			fresh.mu.Unlock()
			if winner == "server" && leases != 1 || winner == "local" && leases != 0 {
				t.Fatal("saved desktop choice used wrong authenticated lease", leases)
			}
			again, err := runtime.CaptureLastContext(ctx)
			if err != nil || again.JSON() != last.JSON() {
				t.Fatal("freshly proved saved choice changed original binding", err)
			}
		})
	}
}

func TestDesktopNodeChainExecutionLastPreparationPinsChoiceWithoutChangingPhysicalGraph(t *testing.T) {
	for _, target := range []string{"linux", "windows"} {
		for _, winner := range []string{"local", "server"} {
			t.Run(target+"/"+winner, func(t *testing.T) {
				p, _, _ := desktopExecutionReadyFixture(t, target, "auto", winner)
				last := desktopExecutionSavedChoiceFixture(t, p, winner)
				original := p.preparation.desktop
				next, err := NewDesktopNodeChainExecutionLastPreparation(original, "auto", last.JSON())
				if err != nil {
					t.Fatal(err)
				}
				if next.SourceSHA256() == p.preparation.SourceSHA256() || next.Source() == p.preparation.Source() || next.Config() != p.preparation.Config() || next.ConfigSHA256() != p.preparation.ConfigSHA256() {
					t.Fatal("saved winner was not independently authenticated or changed native construction graph")
				}
				physical, err := next.DesktopPhysicalPolicy()
				owner, ownerErr := physical.OriginalDesktopPolicy()
				if err != nil || ownerErr != nil || owner != original {
					t.Fatal("saved winner replaced original physical policy", err, ownerErr)
				}
				parsed, err := ParseDesktopNodeChainExecutionPreparation(next.Source())
				if err != nil || parsed.Config() != next.Config() || parsed.SourceSHA256() != next.SourceSHA256() {
					t.Fatal(err)
				}
				captured, present, err := parsed.DesktopLast()
				if err != nil || !present || captured.JSON() != last.JSON() || captured.Execution() != winner || captured.Target() != last.Target() {
					t.Fatal("child lost exact saved winner or target", err)
				}
				discovery, _ := next.Discovery()
				dns, _ := next.DNSCapture()
				if discovery.SourceSHA256 != next.SourceSHA256() || dns.DNS.SourceSHA256 != next.SourceSHA256() {
					t.Fatal("discovery or DNS borrowed fresh Compare source")
				}
				projection, err := next.BindExecution(p.policy)
				if err != nil {
					t.Fatal(err)
				}
				transition, _ := projection.Transition()
				if transition.PreparationSourceSHA256 != next.SourceSHA256() {
					t.Fatal("transition lost saved choice")
				}
			})
		}
	}
}

func TestDesktopNodeChainExecutionLastPreparationRejectsForeignChoice(t *testing.T) {
	p, _, _ := desktopExecutionReadyFixture(t, "linux", "auto", "local")
	last := desktopExecutionSavedChoiceFixture(t, p, "local")
	for _, saved := range []string{"", last.JSON() + " ", strings.Replace(last.JSON(), `"execution":"local"`, `"execution":"server"`, 1)} {
		if _, err := NewDesktopNodeChainExecutionLastPreparation(p.preparation.desktop, "auto", saved); err == nil {
			t.Fatal("altered saved choice accepted")
		}
	}
	if _, err := NewDesktopNodeChainExecutionLastPreparation(p.preparation.desktop, "server", last.JSON()); err == nil {
		t.Fatal("Compare winner relabeled as explicit Server")
	}
	var source NodeChainExecutionPreparationSource
	if json.Unmarshal([]byte(p.preparation.Source()), &source) != nil {
		t.Fatal("fixture")
	}
	source.DesktopLast, source.Desktop = last.JSON(), nil
	if _, err := ParseNodeChainExecutionPreparation(startJSON(t, source)); err == nil {
		t.Fatal("generic source borrowed desktop restore choice")
	}
	if _, present, err := p.preparation.DesktopLast(); err != nil || present {
		t.Fatal("fresh preparation acquired restore choice", err)
	}
}

func TestDesktopNodeChainExecutionLastCannotEnterOrdinaryCompare(t *testing.T) {
	p, _, _ := desktopExecutionReadyFixture(t, "linux", "auto", "local")
	last := desktopExecutionSavedChoiceFixture(t, p, "local")
	prep, err := NewDesktopNodeChainExecutionLastPreparation(p.preparation.desktop, "auto", last.JSON())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := prep.BindExecution(p.policy)
	if err != nil {
		t.Fatal(err)
	}
	engine := &nodeChainExecutionRuntimeEngine{beforeObserve: func(context.Context) { t.Fatal("saved choice entered an unbound native trial") }}
	runtime, err := NewNodeChainExecutionRuntime(projection, engine)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Run(context.Background()) == nil {
		t.Fatal("saved choice admitted ordinary Compare runtime")
	}
	owner, err := NewNodeChainExecutionDiscoveryOwner(prep, engine)
	if err != nil {
		t.Fatal(err)
	}
	foreign := desktopExecutionSavedChoiceFixture(t, p, "server")
	if _, err := owner.PlanLastContext(context.Background(), foreign); err == nil {
		t.Fatal("source-bound winner replaced by another Last plan")
	}
}

func TestDesktopNodeChainExecutionLastKeepsChoiceAcrossMTUReproof(t *testing.T) {
	p, _, _ := desktopExecutionReadyFixture(t, "linux", "auto", "local")
	last := desktopExecutionSavedChoiceFixture(t, p, "local")
	prep, err := NewDesktopNodeChainExecutionLastPreparation(p.preparation.desktop, "auto", last.JSON())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := prep.BindExecution(p.policy)
	if err != nil {
		t.Fatal(err)
	}
	// Only the source-choice guard is exercised here; actual restore creation
	// separately requires the original runtime's positive joined retirement.
	runtime := &NodeChainExecutionRuntime{projection: projection, restore: &NodeChainExecutionRestoreCapture{execution: "local"}}
	runtime.restore.result.Target = last.Target()
	if !runtime.desktopSavedChoiceCurrent() {
		t.Fatal("captured MTU reproof lost the saved winner")
	}
	runtime.restore.execution = "server"
	if runtime.desktopSavedChoiceCurrent() {
		t.Fatal("MTU reproof changed saved winner")
	}
	runtime.restore.execution, runtime.restore.result.Target = "local", Targets[1]
	if runtime.desktopSavedChoiceCurrent() {
		t.Fatal("MTU reproof changed common target")
	}
}
