package mobilemultihop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
	"router-vpn/internal/routechoice"
)

// The existing fixture explicitly retires its native boundary double by
// setting alive=false after shared Close. This is not a native Box-close proof.
func (e *nodeChainExecutionRuntimeEngine) OpenVPNExecutionRetiredContext(ctx context.Context, original *NodeChain) error {
	if ctx == nil || ctx.Err() != nil || e.projection == nil || e.projection.preparation.openvpn == nil || original != e.projection.preparation.openvpn.source || original.validateCapture() != nil {
		return nodeChainExecutionError
	}
	e.mu.Lock()
	closed := !e.alive && !e.open
	e.mu.Unlock()
	if !closed {
		return errors.New("original native OpenVPN fixture has not joined")
	}
	return ctx.Err()
}

// Only endpoint, native retirement and MTU reader state are explicit boundary
// models. The real Manager, TLS proof transport, Compare and opaque Restore run.
type openVPNRestoreReceiptEngine struct {
	*nodeChainExecutionRuntimeEngine
	nativeJoined  atomic.Bool
	retireCalls   atomic.Int32
	stateCalls    atomic.Int32
	generation    atomic.Uint64
	connectedAt   atomic.Int64
	capacity      atomic.Uint32
	ownerFailure  atomic.Bool
	retireFailure atomic.Bool
	retireWait    atomic.Bool
	retireCancel  context.CancelFunc
	retireSecond  func()
	mtu           *nodeChainExecutionMTUEngine
}

func (e *openVPNRestoreReceiptEngine) ObserveOpenVPNExecutionContext(ctx context.Context, original *NodeChain) error {
	if e.ownerFailure.Load() {
		return errors.New("replacement OpenVPN construction owner changed")
	}
	return e.nodeChainExecutionRuntimeEngine.ObserveOpenVPNExecutionContext(ctx, original)
}

func (e *openVPNRestoreReceiptEngine) OpenVPNExecutionRetiredContext(ctx context.Context, original *NodeChain) error {
	if e.retireCalls.Add(1) == 2 && e.retireSecond != nil {
		e.retireSecond()
	}
	if e.retireCancel != nil {
		e.retireCancel()
		return nil // A late nil must not authorize the cancelled caller.
	}
	if e.retireWait.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	if e.retireFailure.Load() || !e.nativeJoined.Load() {
		return errors.New("original native OpenVPN close receipt is not successful")
	}
	return e.nodeChainExecutionRuntimeEngine.OpenVPNExecutionRetiredContext(ctx, original)
}

func (e *openVPNRestoreReceiptEngine) OpenVPNMiddleStateContext(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
	e.stateCalls.Add(1)
	state, err := e.nodeChainExecutionRuntimeEngine.OpenVPNMiddleStateContext(ctx, tag)
	state.Remote.Generation += e.generation.Load()
	state.Remote.ConnectedAt += e.connectedAt.Load()
	state.MTU += e.capacity.Load()
	return state, err
}

func (e *openVPNRestoreReceiptEngine) AdmitExecutionMTUResumeContext(ctx context.Context, binding NodeChainExecutionMTUResumeBinding) error {
	if e.mtu == nil || !binding.OwnsEngine(e) {
		return nodeChainExecutionError
	}
	return e.mtu.AdmitExecutionMTUResumeContext(ctx, binding)
}

type openVPNExecutionWithoutRetirement struct {
	NodeChainExecutionEngine
	native *openVPNRestoreReceiptEngine
}

func (e *openVPNExecutionWithoutRetirement) ObserveOpenVPNExecutionContext(ctx context.Context, original *NodeChain) error {
	return e.native.ObserveOpenVPNExecutionContext(ctx, original)
}

func (e *openVPNExecutionWithoutRetirement) OpenVPNMiddleStateContext(ctx context.Context, tag string) (nativeopenvpn.PacketObservation, error) {
	return e.native.OpenVPNMiddleStateContext(ctx, tag)
}

func (e *openVPNExecutionWithoutRetirement) SelectionEpochContext(ctx context.Context) (uint64, error) {
	return e.native.SelectionEpochContext(ctx)
}

func openVPNLocalRestoreFixture(t *testing.T, count int, network string) (*nodeChainExecutionRuntimeFixture, *openVPNRestoreReceiptEngine, context.Context) {
	t.Helper()
	return openVPNLocalRestoreFixtureOwned(t, count, network, nil)
}

func openVPNLocalRestoreFixtureOwned(t *testing.T, count int, network string, wrap func(*openVPNRestoreReceiptEngine) NodeChainExecutionEngine) (*nodeChainExecutionRuntimeFixture, *openVPNRestoreReceiptEngine, context.Context) {
	t.Helper()
	_, prep, source := openVPNExecutionFixture(t, count, "wg", network, "", "auto", "")
	f := newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, prep)
	f.engine.localDelay, f.engine.serverDelay = time.Millisecond, time.Millisecond
	serverProofs, err := f.runtime.projection.ProofInventory("server")
	if err != nil {
		t.Fatal(err)
	}
	var serverRefusals atomic.Int32
	// This fixture needs a proved Local winner, not a scheduling race between
	// two small delays. The real Server trial acquires its authenticated lease,
	// then receives the existing TLS fixture's private-address refusal. Compare
	// must disqualify that actual response without assigning a zero score.
	// Existing two-valid-candidate scoring tests remain separate and unchanged.
	f.engine.beforeDial = func(_ context.Context, tag, address string) (net.Conn, error, bool) {
		if address == "1.1.1.1:443" || address == "1.0.0.1:443" {
			refuse := tag == serverProofs[len(serverProofs)-2].Tag || tag == serverProofs[len(serverProofs)-1].Tag
			f.engine.mu.Lock()
			f.engine.wrongPublic = refuse
			f.engine.mu.Unlock()
			if refuse {
				serverRefusals.Add(1)
			}
		}
		return nil, nil, false
	}
	e := &openVPNRestoreReceiptEngine{nodeChainExecutionRuntimeEngine: f.engine}
	f.runtime.engine = e
	if wrap != nil {
		f.runtime.engine = wrap(e)
	}
	// Like the existing OpenVPN Last/mobile restore fixtures, this caller owns
	// both complete old and replacement lifecycles. Runtime/probe clocks stay
	// unchanged; the original single-owner 10/20-second fixtures are untouched.
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal("original Compare", err)
	}
	progress := f.runtime.Progress()
	if !progress.Ready || progress.Execution != "local" || len(progress.Comparison.Measurements) != 2 || progress.Comparison.Final == nil {
		t.Fatal("fixture did not prove original Local winner", progress)
	}
	local, server := progress.Comparison.Measurements[0], progress.Comparison.Measurements[1]
	if !local.Eligible || local.ScoreMS == nil || local.Candidate.Execution != routechoice.Local || server.Eligible || server.ScoreMS != nil || server.Failure == "" || server.Candidate.Execution != routechoice.Server || serverRefusals.Load() == 0 {
		t.Fatal("actual Server refusal gained a score or Local proof was fabricated", progress.Comparison)
	}
	f.mu.Lock()
	puts, deletes := 0, 0
	for _, request := range f.requests {
		if request.method == "PUT" {
			puts++
		}
		if request.method == "DELETE" {
			deletes++
		}
	}
	f.mu.Unlock()
	if puts != 1 || deletes != 1 {
		t.Fatal("Server refusal did not acquire and join its original lease", puts, deletes)
	}
	f.runner.mu.Lock()
	defer f.runner.mu.Unlock()
	if len(f.runner.workers) == 0 {
		t.Fatal("Server refusal skipped the actual Manager worker")
	}
	for _, worker := range f.runner.workers {
		if worker.Alive() {
			t.Fatal("failed Server retained its original worker")
		}
	}
	return f, e, ctx
}

func openVPNRetireRestoreFixture(t *testing.T, f *nodeChainExecutionRuntimeFixture, old *openVPNRestoreReceiptEngine, ctx context.Context) NodeChainExecutionRestoreCapture {
	t.Helper()
	capture, err := f.runtime.CaptureRestoreContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("original shared cleanup", err)
	}
	old.mu.Lock()
	old.alive = false
	old.mu.Unlock()
	old.nativeJoined.Store(true)
	return capture
}

func openVPNFreshRestoreFixture(t *testing.T, f *nodeChainExecutionRuntimeFixture, capture NodeChainExecutionRestoreCapture) (*NodeChainExecutionRuntime, *openVPNRestoreReceiptEngine) {
	t.Helper()
	next := &openVPNRestoreReceiptEngine{nodeChainExecutionRuntimeEngine: cloneNodeChainExecutionRuntimeEngine(f.engine)}
	next.generation.Store(30)
	next.connectedAt.Store(40)
	runtime, err := NewNodeChainExecutionRestoreRuntime(capture, next)
	if err != nil {
		t.Fatal(err)
	}
	runtime.testTLS = f.trust
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := runtime.CloseContext(cleanup); err != nil {
			t.Error("restored owner cleanup", err)
		}
	})
	return runtime, next
}

func TestNodeChainOpenVPNExecutionRestoreFreshLocalReceipt(t *testing.T) {
	for _, count := range []int{1, 2, 6} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("%d-%s", count+2, network), func(t *testing.T) {
				f, old, ctx := openVPNLocalRestoreFixture(t, count, network)
				prep := f.runtime.projection.preparation
				prep.openvpn.mu.Lock()
				originalState := *prep.openvpn.connected
				prep.openvpn.mu.Unlock()
				capture, err := f.runtime.CaptureRestoreContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := NewNodeChainExecutionRestoreRuntime(capture, cloneNodeChainExecutionRuntimeEngine(f.engine)); err == nil {
					t.Fatal("fresh Local receipt preceded original shared join")
				}
				capture = openVPNRetireRestoreFixture(t, f, old, ctx)
				restored, next := openVPNFreshRestoreFixture(t, f, capture)
				f.mu.Lock()
				requests := len(f.requests)
				f.mu.Unlock()
				if err := restored.Run(ctx); err != nil {
					t.Fatal("fresh Local native generation could not restore the proved choice", err)
				}
				progress := restored.Progress()
				if !progress.Ready || progress.Execution != "local" || progress.Comparison.Target != capture.result.Target || !reflect.DeepEqual(progress.Comparison.Measurements, capture.result.Measurements) || progress.Comparison.Final == nil || !progress.Comparison.Final.Eligible {
					t.Fatal("restore lost original Local choice/target/proof", progress)
				}
				next.mu.Lock()
				selections := append([]string(nil), next.selections...)
				next.mu.Unlock()
				f.mu.Lock()
				newRequests := append([]struct{ method, session string }(nil), f.requests[requests:]...)
				f.mu.Unlock()
				if len(selections) != 1 || len(newRequests) != 0 || old.retireCalls.Load() != 2 || next.stateCalls.Load() == 0 {
					t.Fatal("restore reran Compare, acquired a Server lease, or skipped native ownership", selections, newRequests, old.retireCalls.Load(), next.stateCalls.Load())
				}
				receipt := restored.openvpnRestore
				if receipt == nil || receipt.preparation != prep || receipt.engine != next || receipt.identity != next.identity || receipt.binding != prep.openvpn {
					t.Fatal("fresh receipt lost exact replacement engine/preparation")
				}
				for _, fault := range []string{"self", "engine", "preparation", "binding"} {
					foreign := &nodeChainOpenVPNExecutionConnectedReceipt{preparation: prep, binding: prep.openvpn, engine: next, identity: next.identity}
					foreign.self = foreign
					switch fault {
					case "self":
						foreign.self = receipt
					case "engine":
						foreign.engine = cloneNodeChainExecutionRuntimeEngine(next.nodeChainExecutionRuntimeEngine)
					case "preparation":
						foreign.preparation = nil
					case "binding":
						foreign.binding = nil
					}
					if err := foreign.validate(prep, next); err == nil {
						t.Fatal("copied/foreign replacement receipt gained authority", fault)
					}
				}
				receipt.mu.Lock()
				state := *receipt.connected
				receipt.mu.Unlock()
				prep.openvpn.mu.Lock()
				retainedOriginal := *prep.openvpn.connected
				prep.openvpn.mu.Unlock()
				if retainedOriginal != originalState || state.Remote.Generation != 31 || state.Remote.ConnectedAt != 41 || state.MTU != originalState.MTU {
					t.Fatal("fresh receipt replaced old anchor or borrowed stale native observation", originalState, retainedOriginal, state)
				}
				if err := restored.HealthyContext(ctx); err != nil {
					t.Fatal("restored Local lost its own connected receipt", err)
				}
				before := next.stateCalls.Load()
				if err := f.runtime.HealthyContext(ctx); err == nil || next.stateCalls.Load() != before {
					t.Fatal("retired original observation reached replacement owner")
				}
				if err := prep.observeOpenVPNExecutionContext(ctx, next); err == nil {
					t.Fatal("ordinary preparation observation reset its original anchor")
				}
			})
		}
	}
}

func TestNodeChainOpenVPNExecutionRestoreRefusesUnjoinedOrForeignOwner(t *testing.T) {
	for _, fault := range []string{"native-not-joined", "native-close-error", "missing-retirement-observer", "new-owner", "same-engine-id", "same-session-id", "same-engine-pointer", "network-during-retirement", "owner-during-retirement", "cancelled-retirement", "retirement-deadline"} {
		t.Run(fault, func(t *testing.T) {
			var wrap func(*openVPNRestoreReceiptEngine) NodeChainExecutionEngine
			if fault == "missing-retirement-observer" {
				wrap = func(e *openVPNRestoreReceiptEngine) NodeChainExecutionEngine {
					return &openVPNExecutionWithoutRetirement{NodeChainExecutionEngine: e, native: e}
				}
			}
			f, old, ctx := openVPNLocalRestoreFixtureOwned(t, 1, "tcp", wrap)
			capture := openVPNRetireRestoreFixture(t, f, old, ctx)
			restored, next := openVPNFreshRestoreFixture(t, f, capture)
			call := ctx
			switch fault {
			case "native-not-joined":
				old.nativeJoined.Store(false)
			case "native-close-error":
				old.retireFailure.Store(true)
			case "new-owner":
				next.ownerFailure.Store(true)
			case "same-engine-id":
				next.identity.EngineID = capture.identity.EngineID
			case "same-session-id":
				next.identity.SessionID = capture.identity.SessionID
			case "network-during-retirement":
				old.retireSecond = func() {
					next.mu.Lock()
					next.identity.NetworkID += "-replacement"
					next.mu.Unlock()
				}
			case "owner-during-retirement":
				old.retireSecond = func() { next.ownerFailure.Store(true) }
			case "same-engine-pointer":
				// A new set of strings on the same retained native object is not
				// replacement ownership, even after original shared cleanup.
				old.mu.Lock()
				old.alive = true
				old.identity = next.identity
				old.mu.Unlock()
				restored.engine = old
			case "cancelled-retirement":
				var cancel context.CancelFunc
				call, cancel = context.WithCancel(ctx)
				defer cancel()
				old.retireCancel = cancel
			case "retirement-deadline":
				var cancel context.CancelFunc
				call, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
				old.retireWait.Store(true)
			}
			err := restored.Run(call)
			if err == nil || restored.Progress().Ready || restored.openvpnRestore != nil || next.stateCalls.Load() != 0 {
				t.Fatal("unjoined, foreign or cancelled owner minted a fresh Local receipt", err)
			}
			if fault == "retirement-deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("old native retirement exceeded caller deadline", err)
			}
			if fault == "cancelled-retirement" && !errors.Is(err, context.Canceled) {
				t.Fatal("late native retirement erased caller cancellation", err)
			}
			next.mu.Lock()
			opened := next.opens
			next.mu.Unlock()
			if opened != 0 {
				t.Fatal("refused restore opened application traffic")
			}
		})
	}
}

func TestNodeChainOpenVPNExecutionRestoredLocalRetainsFreshReceipt(t *testing.T) {
	for _, fault := range []string{"generation", "connected-at", "capacity", "held-receipt", "cancelled-held-receipt"} {
		t.Run(fault, func(t *testing.T) {
			f, old, ctx := openVPNLocalRestoreFixture(t, 1, "tcp")
			capture := openVPNRetireRestoreFixture(t, f, old, ctx)
			restored, next := openVPNFreshRestoreFixture(t, f, capture)
			if err := restored.Run(ctx); err != nil {
				t.Fatal(err)
			}
			receipt := restored.openvpnRestore
			switch fault {
			case "generation":
				next.generation.Add(1)
			case "connected-at":
				next.connectedAt.Add(1)
			case "capacity":
				next.capacity.Add(1)
			case "held-receipt", "cancelled-held-receipt":
				receipt.mu.Lock()
				call, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
				expected := context.DeadlineExceeded
				if fault == "cancelled-held-receipt" {
					cancel()
					expected = context.Canceled
				}
				err := restored.HealthyContext(call)
				cancel()
				receipt.mu.Unlock()
				if !errors.Is(err, expected) {
					t.Fatal("held fresh receipt exceeded original caller deadline", err)
				}
				if err := restored.HealthyContext(ctx); err != nil {
					t.Fatal("cancelled observation damaged retained replacement", err)
				}
				return
			}
			if err := restored.HealthyContext(ctx); err == nil || restored.Progress().Ready {
				t.Fatal("restored Local borrowed a changed connected receipt", err)
			}
		})
	}
}

func TestNodeChainOpenVPNExecutionOrdinaryRuntimeCannotMintFreshLocalReceipt(t *testing.T) {
	for _, freshValues := range []bool{false, true} {
		t.Run(fmt.Sprintf("fresh-values-%t", freshValues), func(t *testing.T) {
			f, old, ctx := openVPNLocalRestoreFixture(t, 1, "tcp")
			_ = openVPNRetireRestoreFixture(t, f, old, ctx)
			next := &openVPNRestoreReceiptEngine{nodeChainExecutionRuntimeEngine: cloneNodeChainExecutionRuntimeEngine(f.engine)}
			if freshValues {
				next.generation.Store(30)
				next.connectedAt.Store(40)
			}
			runtime, err := NewNodeChainExecutionRuntime(f.runtime.projection, next)
			if err != nil {
				t.Fatal(err)
			}
			runtime.testTLS = f.trust
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := runtime.CloseContext(cleanup); err != nil {
					t.Error(err)
				}
			}()
			if err := runtime.Run(ctx); err != nil {
				t.Fatal("independent Server must remain eligible", err)
			}
			progress := runtime.Progress()
			if runtime.openvpnRestore != nil || old.retireCalls.Load() != 0 || !progress.Ready || progress.Execution != "server" || len(progress.Comparison.Measurements) != 2 || progress.Comparison.Measurements[0].Candidate.Execution != routechoice.Local || progress.Comparison.Measurements[0].Eligible || progress.Comparison.Measurements[0].ScoreMS != nil {
				t.Fatal("ordinary constructor silently granted a fresh Local receipt", progress)
			}
		})
	}
}

func TestNodeChainOpenVPNExecutionRestoreMTUResumeRetainsFreshReceipt(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed-generation-%t", changed), func(t *testing.T) {
			f, old, ctx := openVPNLocalRestoreFixture(t, 1, "tcp")
			capture := openVPNRetireRestoreFixture(t, f, old, ctx)
			restored, next := openVPNFreshRestoreFixture(t, f, capture)
			next.mtu = &nodeChainExecutionMTUEngine{nodeChainExecutionRuntimeEngine: next.nodeChainExecutionRuntimeEngine}
			if err := restored.Run(ctx); err != nil {
				t.Fatal(err)
			}
			receipt := restored.openvpnRestore
			binding, err := restored.PauseMTUContext(ctx)
			if err != nil || binding.ValidateClosedContext(ctx) != nil {
				t.Fatal("original restored reader pause", err)
			}
			if err := next.mtu.change(ctx, binding); err != nil {
				t.Fatal(err)
			}
			resume, err := NewNodeChainExecutionMTUResumeRuntime(ctx, binding)
			if err != nil || resume.openvpnRestore != receipt {
				t.Fatal("same-Box MTU resume replaced connected receipt", err)
			}
			resume.testTLS = f.trust
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := resume.CloseContext(cleanup); err != nil {
					t.Error(err)
				}
			}()
			if changed {
				next.generation.Add(1)
			}
			err = resume.Run(ctx)
			if changed {
				if err == nil || resume.Progress().Ready {
					t.Fatal("reader MTU transition granted a different OpenVPN connection")
				}
			} else if err != nil || !resume.Progress().Ready || resume.Progress().Execution != "local" || resume.openvpnRestore != receipt {
				t.Fatal("same-Box MTU resume lost proved Local receipt", err)
			}
			if old.retireCalls.Load() != 2 || next.retireCalls.Load() != 0 {
				t.Fatal("same-Box reader resume claimed native endpoint retirement")
			}
		})
	}
}
