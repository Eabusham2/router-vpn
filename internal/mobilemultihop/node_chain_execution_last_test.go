package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func nodeChainExecutionLastFixture(t *testing.T, winner string) (*nodeChainExecutionRuntimeFixture, NodeChainExecutionLast, context.Context) {
	t.Helper()
	f := newNodeChainExecutionRuntimeFixture(t, "auto")
	// Both candidates still complete the real loopback proof/probe inventory.
	// Separate their explicit fixture response delays enough that compilation
	// contention cannot accidentally change the choice this case is exercising.
	f.engine.localDelay, f.engine.serverDelay = 200*time.Millisecond, time.Millisecond
	if winner == "local" {
		f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 200*time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	last, err := f.runtime.CaptureLastContext(ctx)
	if err != nil || last.Execution() != winner {
		t.Fatal("fixture did not capture the proved concrete choice", last.Execution(), err)
	}
	return f, last, ctx
}

func nodeChainExecutionAdoptLastFixture(t *testing.T, f *nodeChainExecutionRuntimeFixture, plan NodeChainExecutionLastPlan) *NodeChainExecutionProjection {
	t.Helper()
	projection, err := plan.Projection()
	if err != nil {
		t.Fatal(err)
	}
	e := f.engine
	e.mu.Lock()
	previous := e.projection
	for _, execution := range []string{"local", "server"} {
		oldProofs, _ := previous.ProofInventory(execution)
		newProofs, _ := projection.ProofInventory(execution)
		for i, proof := range oldProofs {
			api, _ := privateAPI(predecessorText(previous.policy.local.nodes[i].profile, "router_api"))
			e.peers[newProofs[i].Tag+"/"+api.Host] = e.peers[proof.Tag+"/"+api.Host]
		}
	}
	e.projection = projection
	e.identity.SourceSHA256, e.identity.ConfigSHA256 = projection.SourceSHA256(), projection.ConfigSHA256()
	e.mu.Unlock()
	return projection
}

func TestNodeChainExecutionLastPersistsOnlyBindingsAndFreshlyProvesChoice(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			old, last, ctx := nodeChainExecutionLastFixture(t, winner)
			original := old.runtime.projection.policy
			file := filepath.Join(t.TempDir(), "ordered-last.json")
			if err := os.WriteFile(file, []byte(last.JSON()), 0600); err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"api_token", "password", "username", "private_key", "owner_id", "session_id", "acquire_expires_at", "proof_at", original.source.Request.SessionID, original.source.Request.Users[0].Password} {
				if strings.Contains(last.JSON(), forbidden) {
					t.Fatal("Last persisted live/private runtime authority", forbidden)
				}
			}
			if err := old.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			old.engine.mu.Lock()
			old.engine.alive = false
			old.engine.mu.Unlock()
			last = NodeChainExecutionLast{} // reconstruct from private storage and fresh sources
			fresh := newNodeChainExecutionRuntimeFixture(t, "auto")
			prep := fresh.runtime.projection.preparation
			bytes, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			last, err = ParseNodeChainExecutionLast(string(bytes), prep)
			if err != nil || last.Execution() != winner {
				t.Fatal("durable Last did not retain the original source/choice", err)
			}
			fresh.engine.mu.Lock()
			fresh.engine.identity = NodeChainIdentity{"cold-box", "cold-session", "cold-network", prep.SourceSHA256(), prep.ConfigSHA256()}
			fresh.engine.localDelay, fresh.engine.serverDelay = time.Millisecond, time.Millisecond
			fresh.engine.mu.Unlock()
			owner, err := NewNodeChainExecutionDiscoveryOwner(prep, fresh.engine)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
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
			projection, err := plan.Projection()
			if err != nil {
				t.Fatal(err)
			}
			request := projection.policy.Request()
			if request.SessionID == original.source.Request.SessionID || reflect.DeepEqual(request.Users, original.source.Request.Users) || request.Port != original.source.Request.Port || projection.policy.front.Host != original.front.Host {
				t.Fatal("Last reused old frontend authority or silently replanned its listener")
			}
			if plan.RequireJoinedContext(ctx) == nil {
				t.Fatal("open discovery granted Last runtime ownership")
			}
			if err := owner.Close(ctx); err != nil {
				t.Fatal(err)
			}
			nodeChainExecutionAdoptLastFixture(t, fresh, plan) // explicit native adoption boundary double
			runtime, err := NewNodeChainExecutionLastRuntime(ctx, plan, fresh.engine)
			if err != nil {
				t.Fatal(err)
			}
			runtime.testTLS, fresh.runtime = fresh.trust, runtime
			if _, err := NewNodeChainExecutionLastRuntime(ctx, plan, fresh.engine); err == nil {
				t.Fatal("Last plan was reused by a second runtime")
			}
			if err := runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			progress := runtime.Progress()
			fresh.engine.mu.Lock()
			selections, dns, proofCount := append([]string(nil), fresh.engine.selections...), append([]string(nil), fresh.engine.dnsCalls...), len(fresh.engine.proofCalls)
			fresh.engine.mu.Unlock()
			proofs, _ := projection.ProofInventory(winner)
			if !progress.Ready || progress.Execution != winner || progress.Comparison.Target != last.Target() || len(progress.Comparison.Measurements) != 0 ||
				len(selections) != 1 || selections[0] != proofs[len(proofs)-1].Tag || len(dns) == 0 || proofCount < len(proofs) {
				t.Fatal("Last replayed Compare or replaced fresh selected proof", progress, selections, dns, proofCount)
			}
			fresh.mu.Lock()
			puts := 0
			for _, request := range fresh.requests {
				if request.method == "PUT" {
					puts++
					if request.session == original.source.Request.SessionID {
						t.Fatal("Last replayed old lease session")
					}
				}
			}
			fresh.mu.Unlock()
			if winner == "server" && puts != 1 || winner == "local" && puts != 0 {
				t.Fatal("Last used wrong remote execution", puts)
			}
			if _, err := runtime.CaptureLastContext(ctx); err != nil {
				t.Fatal("fresh successful Last could not be retained", err)
			}
		})
	}
}

func TestNodeChainExecutionLastRejectsMalformedAndChangedOriginalSource(t *testing.T) {
	f, original, ctx := nodeChainExecutionLastFixture(t, "server")
	prep := f.runtime.projection.preparation
	for _, fault := range []string{"schema", "setting", "unsupported-choice", "target", "port", "pool", "host", "peer", "digest", "local-source", "local-input", "descriptor-shape", "dns", "target-os"} {
		t.Run(fault, func(t *testing.T) {
			last := original
			last.record.Descriptor = last.record.Descriptor.Clone()
			switch fault {
			case "schema":
				last.record.Schema++
			case "setting":
				last.record.Setting = "local"
			case "unsupported-choice":
				last.record.Execution = "auto"
			case "target":
				last.record.Target = "https://unowned.example/"
			case "port":
				last.record.Port = last.record.LastPort + 1
			case "pool":
				last.record.LastPort = last.record.FirstPort + 64
			case "host":
				last.record.EntryHost = "10.99.0.1"
			case "peer":
				last.record.Peer = "127.0.0.1"
			case "digest":
				last.record.Digest = strings.Repeat("a", 64)
			case "local-source":
				last.record.LocalSourceSHA256 = strings.Repeat("b", 64)
			case "local-input":
				last.record.LocalInputSHA256 = strings.Repeat("c", 64)
			case "descriptor-shape":
				last.record.Descriptor.Members[0].Mode = "unsupported"
			case "dns":
				last.record.DNSPolicySHA256 = strings.Repeat("d", 64)
			case "target-os":
				last.record.DesktopTargetOS = "darwin"
			}
			if fault != "digest" {
				last.record.Digest = nodeChainExecutionLastDigest(last.record)
			}
			raw, _ := json.Marshal(last.record)
			if _, err := ParseNodeChainExecutionLast(string(raw), prep); err == nil {
				t.Fatal("changed Last record acquired original source authority", fault)
			}
		})
	}
	for _, raw := range []string{original.raw + " ", "{\"extra\":true," + original.raw[1:], "{\"schema\":1," + original.raw[1:], strings.Repeat(" ", nodeChainExecutionLastLimit+1)} {
		if _, err := ParseNodeChainExecutionLast(raw, prep); err == nil {
			t.Fatal("noncanonical/ambiguous Last record admitted")
		}
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.runtime.CaptureLastContext(ctx); err == nil {
		t.Fatal("closed owner minted durable successful Last")
	}
	var empty NodeChainExecutionLast
	if empty.JSON() != "" || empty.Execution() != "" || empty.Target() != "" || empty.LocalSourceSHA256() != "" {
		t.Fatal("zero Last record granted state")
	}
}

func TestNodeChainExecutionLastFreshDiscoveryKeepsExactOriginalInventory(t *testing.T) {
	f, last, ctx := nodeChainExecutionLastFixture(t, "server")
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing-source", "changed-mode", "pool", "peer", "dns", "late-network"} {
		t.Run(fault, func(t *testing.T) {
			o, e, _, _ := nodeChainExecutionDiscoveryTestFixture(t, func(d *NodeChainExecutionDiscovery) {
				switch fault {
				case "missing-source":
					d.Sources[0].SourceSHA256 = strings.Repeat("a", 64)
				case "changed-mode":
					d.Sources[0].Members[0].Mode = "awg2-strong"
				case "pool":
					d.LastPort++
				case "peer":
					d.Challenge.Peer = "10.80.0.3"
				case "dns":
					d.Sources[0].DNSPolicySHA256 = strings.Repeat("b", 64)
				}
			}, nil)
			if _, err := o.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			if fault == "late-network" {
				e.mu.Lock()
				e.identity.NetworkID = "replacement"
				e.mu.Unlock()
			}
			if _, err := o.PlanLastContext(ctx, last); err == nil {
				t.Fatal("Last silently replaced original discovery/source inventory", fault)
			}
		})
	}
}

func TestNodeChainExecutionLastPlanRetainsEnteredDiscoveryUntilJoined(t *testing.T) {
	f, last, ctx := nodeChainExecutionLastFixture(t, "server")
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	o, e, _, _ := nodeChainExecutionDiscoveryTestFixture(t, nil, nil)
	if _, err := o.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	plan, err := o.PlanLastContext(ctx, last)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	e.observe = func(context.Context) { enteredOnce.Do(func() { close(entered); <-release }) }
	call, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- o.io.observe(call) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original discovery observation not entered")
	}
	short, stop := context.WithTimeout(ctx, 25*time.Millisecond)
	if err := o.Close(short); err == nil {
		t.Fatal("entered discovery was abandoned")
	}
	stop()
	short, stop = context.WithTimeout(ctx, 25*time.Millisecond)
	if err := plan.RequireJoinedContext(short); err == nil {
		t.Fatal("closed flag replaced original discovery I/O join")
	}
	stop()
	cancel()
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("original observation did not join")
	}
	if err := o.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := plan.RequireJoinedContext(ctx); err != nil {
		t.Fatal("joined original discovery could not admit exact plan", err)
	}
	if _, err := NewNodeChainExecutionLastRuntime(ctx, NodeChainExecutionLastPlan{}, f.engine); err == nil {
		t.Fatal("caller-built plan admitted")
	}
	plan.state.discoverySHA = strings.Repeat("a", 64)
	if _, err := plan.Projection(); err == nil {
		t.Fatal("changed captured discovery retained Last authority")
	}
}

func TestNodeChainExecutionLastCapturesOnlyCurrentProvedOwner(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.runtime.CaptureLastContext(nil); err == nil {
		t.Fatal("nil caller accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := f.runtime.CaptureLastContext(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller admitted", err)
	}
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	f.engine.epoch += 2
	f.engine.mu.Unlock()
	if _, err := f.runtime.CaptureLastContext(ctx); err == nil {
		t.Fatal("away-and-back selection minted Last")
	}
}

func TestNodeChainExecutionLastKeepsDesktopTargetAcrossFreshSession(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	source := desktopExecutionRuntimeProjection(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	last, err := f.runtime.CaptureLastContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, fresh, _ := desktopExecutionProjection(t, source, "linux", strings.Repeat("b", 32), 1400)
	if _, err := ParseNodeChainExecutionLast(last.JSON(), fresh); err != nil {
		t.Fatal("Last rejected newly sealed original physical target", err)
	}
	_, wrong, _ := desktopExecutionProjection(t, source, "darwin", strings.Repeat("c", 32), 1400)
	if _, err := ParseNodeChainExecutionLast(last.JSON(), wrong); err == nil {
		t.Fatal("Last silently changed original physical platform")
	}
	generic, err := NewNodeChainExecutionPreparation(source.LocalSource, source.Execution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNodeChainExecutionLast(last.JSON(), generic); err == nil {
		t.Fatal("Last substituted generic owner for original physical target")
	}
}

func TestNodeChainExecutionLastRejectsAnotherPreparationAndUnprovedNativePath(t *testing.T) {
	old, last, ctx := nodeChainExecutionLastFixture(t, "server")
	if err := old.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"preparation-owner", "native-dns"} {
		t.Run(fault, func(t *testing.T) {
			fresh := newNodeChainExecutionRuntimeFixture(t, "auto")
			prep := fresh.runtime.projection.preparation
			fresh.engine.identity = NodeChainIdentity{"fresh-box", "fresh-session", "fresh-network", prep.SourceSHA256(), prep.ConfigSHA256()}
			owner, err := NewNodeChainExecutionDiscoveryOwner(prep, fresh.engine)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
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
			nodeChainExecutionAdoptLastFixture(t, fresh, plan)
			runtime, err := NewNodeChainExecutionLastRuntime(ctx, plan, fresh.engine)
			if err != nil {
				t.Fatal(err)
			}
			runtime.testTLS, fresh.runtime = fresh.trust, runtime
			fresh.engine.mu.Lock()
			if fault == "preparation-owner" {
				fresh.engine.identity.EngineID = "replacement-box"
			} else {
				fresh.engine.failDNS = true
			}
			fresh.engine.mu.Unlock()
			if err := runtime.Run(ctx); err == nil {
				t.Fatal("saved Last replaced original preparation or fresh native proof", fault)
			}
			if runtime.Progress().Ready {
				t.Fatal("Last record restored Ready without current native proof")
			}
			fresh.engine.mu.Lock()
			open, stops, selections := fresh.engine.open, fresh.engine.stops, len(fresh.engine.selections)
			fresh.engine.mu.Unlock()
			if open || stops != 0 {
				t.Fatal("failed Last proof abandoned original cleanup", open, stops)
			}
			if fault == "preparation-owner" && selections != 0 {
				t.Fatal("foreign preparation entered selected execution")
			}
			if fault == "native-dns" {
				fresh.mu.Lock()
				puts, deletes := 0, 0
				for _, q := range fresh.requests {
					if q.method == "PUT" {
						puts++
					}
					if q.method == "DELETE" {
						deletes++
					}
				}
				fresh.mu.Unlock()
				if puts != 1 || deletes != 1 {
					t.Fatal("failed fresh Last proof did not join exact lease", puts, deletes)
				}
			}
		})
	}
}

func TestNodeChainExecutionLastRequiresFreshServerReceipt(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	var reject atomic.Bool
	f.mutateStatus = func(status *multihoprelay.NodeChainLeaseStatus) {
		if reject.Load() {
			status.Receipt.Nonce = strings.Repeat("f", 64)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	reject.Store(true)
	if _, err := f.runtime.CaptureLastContext(ctx); err == nil {
		t.Fatal("cached Ready minted Last without a fresh server receipt")
	}
}

func TestNodeChainExecutionLastRetainsLateNativeObservationUntilClose(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	entered, release := make(chan struct{}), make(chan struct{})
	var armed atomic.Bool
	var once, unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f.engine.beforeObserve = func(context.Context) {
		if armed.Load() {
			once.Do(func() { close(entered); <-release })
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	done := make(chan error, 1)
	go func() { _, err := f.runtime.CaptureLastContext(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original Last observation did not enter")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	if err := f.runtime.CloseContext(closeCtx); err == nil {
		t.Fatal("runtime acknowledged cleanup before original Last observation returned")
	}
	stop()
	unblock()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("late retired Last observation published record")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original Last observation did not join")
	}
	closeCtx, stop = context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := f.runtime.CloseContext(closeCtx); err != nil {
		t.Fatal("original Last observation join did not release cleanup", err)
	}
}
