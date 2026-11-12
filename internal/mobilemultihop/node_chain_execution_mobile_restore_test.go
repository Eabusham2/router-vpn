package mobilemultihop

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These methods are explicit native reader/retirement boundary doubles. Real
// shared source compilation, runtime, TLS, authenticated Manager and cleanup
// execute. They do not replace the bridge's required Instance.Close receipt.
type nodeChainExecutionReadbackEngine struct {
	*nodeChainExecutionRuntimeEngine
	readMu        sync.Mutex
	issued        NodeChainExecutionTUNReadback
	retired       bool
	denyRetired   bool
	forbidCapture bool
	captures      atomic.Int32
	beforeCapture func(context.Context)
}

func (e *nodeChainExecutionReadbackEngine) CaptureExecutionTUNReadbackContext(ctx context.Context, identity NodeChainIdentity) (NodeChainExecutionTUNReadback, error) {
	e.captures.Add(1)
	if e.beforeCapture != nil {
		e.beforeCapture(ctx)
	}
	e.readMu.Lock()
	defer e.readMu.Unlock()
	if e.forbidCapture || e.retired || identity != e.issued.Identity {
		return NodeChainExecutionTUNReadback{}, errors.New("original reader cannot be observed")
	}
	return e.issued, ctx.Err()
}

func (e *nodeChainExecutionReadbackEngine) ExecutionTUNReadbackRetiredContext(ctx context.Context, original NodeChainExecutionTUNReadback) error {
	e.readMu.Lock()
	defer e.readMu.Unlock()
	e.mu.Lock()
	open := e.open
	e.mu.Unlock()
	if !e.retired || e.denyRetired || open || original != e.issued {
		return errors.New("exact issued native reader retirement is not joined")
	}
	return ctx.Err()
}

func nodeChainExecutionReadbackFixture(t *testing.T, target, execution string, localWinner bool) (*nodeChainExecutionRuntimeFixture, *nodeChainExecutionReadbackEngine, context.Context) {
	return nodeChainExecutionReadbackConfiguredFixture(t, target, execution, localWinner, false)
}

func nodeChainExecutionReadbackConfiguredFixture(t *testing.T, target, execution string, localWinner, probe bool) (*nodeChainExecutionRuntimeFixture, *nodeChainExecutionReadbackEngine, context.Context) {
	t.Helper()
	f := newNodeChainExecutionRuntimeFixture(t, execution)
	if probe {
		nodeChainExecutionReadbackMeasurementProjection(t, f)
	}
	bound, err := f.runtime.projection.MTUPlan()
	if err != nil || bound.Original == 1400 || bound.Ceiling < 1400 {
		t.Fatal("fixture must have a distinct effective native MTU", bound, err)
	}
	name := "tun42"
	if target == "ios" {
		name = "utun42"
	}
	e := &nodeChainExecutionReadbackEngine{nodeChainExecutionRuntimeEngine: f.engine,
		issued: NodeChainExecutionTUNReadback{Identity: f.engine.identity, TargetOS: target, TUNTag: bound.TUNTag,
			ReaderNonce: strings.Repeat("c", 64), ReaderGeneration: 3, InterfaceName: name, InterfaceIndex: 42, MTU: 1400}}
	f.runtime.engine = e
	if localWinner {
		f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 200*time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	return f, e, ctx
}

func nodeChainExecutionReadbackRetire(t *testing.T, f *nodeChainExecutionRuntimeFixture, e *nodeChainExecutionReadbackEngine, ctx context.Context) {
	t.Helper()
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	e.readMu.Lock()
	e.retired, e.forbidCapture = true, true
	e.readMu.Unlock()
	// Native/host teardown is a separate boundary. From now on the retained
	// retirement query must not inspect closed managers or read the OS again.
	e.mu.Lock()
	e.alive = false
	e.mu.Unlock()
}

func TestMobileNodeChainExecutionRestoreKeepsActualMTUAndOriginalChoice(t *testing.T) {
	for _, target := range []string{"android", "ios"} {
		t.Run(target, func(t *testing.T) {
			setting, winner := "server", "server"
			if target == "ios" {
				setting, winner = "auto", "local"
			}
			f, e, ctx := nodeChainExecutionReadbackFixture(t, target, setting, winner == "local")
			prior := f.runtime.Progress()
			if prior.Execution != winner {
				t.Fatal("fixture did not prove its intended original choice", prior.Execution)
			}
			capture, err := f.runtime.CaptureMobileRestoreContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := capture.NewPreparationContext(ctx); err == nil {
				t.Fatal("typed restore bypassed original shared cleanup")
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := capture.NewPreparationContext(ctx); err == nil {
				t.Fatal("shared closed flag replaced exact native reader retirement")
			}
			nodeChainExecutionReadbackRetire(t, f, e, ctx)
			observations := e.captures.Load()
			prep, err := capture.NewPreparationContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			original := capture.restore.projection
			if prep.Source() != original.preparation.Source() || prep.SourceSHA256() != original.preparation.SourceSHA256() ||
				prep.LocalSource() != original.preparation.LocalSource() || prep.LocalSourceSHA256() != original.preparation.LocalSourceSHA256() ||
				prep.ConfigSHA256() == original.preparation.ConfigSHA256() || len(startObject(t, prep.Source())) != 3 {
				t.Fatal("typed restore relabeled config or changed ordinary original source")
			}
			before, after := startObject(t, original.preparation.Config()), startObject(t, prep.Config())
			before["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(capture.readback.MTU)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("mobile restore changed more than captured system TUN MTU")
			}
			readback, err := prep.MobileRestoreReadback()
			if err != nil || readback != capture.readback {
				t.Fatal("typed preparation lost exact original reader observation", err)
			}
			ordinary, err := ParseNodeChainExecutionPreparation(prep.Source())
			if err != nil || ordinary.ConfigSHA256() != original.preparation.ConfigSHA256() || ordinary.ConfigSHA256() == prep.ConfigSHA256() {
				t.Fatal("ordinary parsing reopened private nonzero mobile restore MTU", err)
			}
			if _, err := ordinary.MobileRestoreReadback(); err == nil {
				t.Fatal("ordinary source minted native readback authority")
			}
			injected := startObject(t, prep.Source())
			injected["mobile"] = map[string]any{"restored_mtu": 1280, "target_os": target}
			if _, err := ParseNodeChainExecutionPreparation(startJSON(t, injected)); err == nil {
				t.Fatal("serialized mobile MTU bypassed opaque restore handling")
			}
			logical, err := capture.SourceContext(ctx)
			if err != nil || logical != original.Source() {
				t.Fatal("restore changed original execution source", err)
			}
			projection, err := prep.BindExecution(original.policy)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := projection.MTUPlan()
			oldBound, _ := original.MTUPlan()
			if err != nil || bound.Original != capture.readback.MTU || bound.Ceiling != oldBound.Ceiling || !reflect.DeepEqual(bound.Prefixes, oldBound.Prefixes) {
				t.Fatal("mobile restore changed original prefix envelope", bound, err)
			}
			next := cloneNodeChainExecutionRuntimeEngine(f.engine)
			next.projection = projection
			next.identity.ConfigSHA256 = projection.ConfigSHA256()
			restored, err := NewMobileNodeChainExecutionRestoreRuntime(ctx, capture, projection, next)
			if err != nil {
				t.Fatal(err)
			}
			restored.testTLS = f.trust
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := restored.CloseContext(cleanup); err != nil {
					t.Error(err)
				}
			})
			if err := restored.Run(ctx); err != nil {
				t.Fatal(err)
			}
			progress := restored.Progress()
			if !progress.Ready || progress.Execution != winner || progress.Comparison.Target != prior.Comparison.Target ||
				!reflect.DeepEqual(progress.Comparison.Measurements, prior.Comparison.Measurements) ||
				restored.identity.SourceSHA256 != capture.readback.Identity.SourceSHA256 || restored.identity.ConfigSHA256 != projection.ConfigSHA256() ||
				restored.identity.ConfigSHA256 == capture.readback.Identity.ConfigSHA256 {
				t.Fatal("mobile restore changed saved result or substituted actual config identity")
			}
			next.mu.Lock()
			selections, dnsProofs := len(next.selections), len(next.dnsCalls)
			next.mu.Unlock()
			if selections != 1 || dnsProofs == 0 {
				t.Fatal("mobile restore reran Compare or skipped fresh selected proof", selections, dnsProofs)
			}
			if e.captures.Load() != observations {
				t.Fatal("retired observation queried original closed native reader")
			}
		})
	}
}

func TestMobileNodeChainExecutionRestoreRejectsChangedReadback(t *testing.T) {
	f, e, ctx := nodeChainExecutionReadbackFixture(t, "android", "server", false)
	original := e.issued
	bound, _ := f.runtime.projection.MTUPlan()
	for name, mutate := range map[string]func(*NodeChainExecutionTUNReadback){
		"source":     func(v *NodeChainExecutionTUNReadback) { v.Identity.SourceSHA256 = strings.Repeat("f", 64) },
		"config":     func(v *NodeChainExecutionTUNReadback) { v.Identity.ConfigSHA256 = strings.Repeat("f", 64) },
		"engine":     func(v *NodeChainExecutionTUNReadback) { v.Identity.EngineID = "foreign" },
		"network":    func(v *NodeChainExecutionTUNReadback) { v.Identity.NetworkID = "foreign" },
		"desktop":    func(v *NodeChainExecutionTUNReadback) { v.TargetOS = "linux" },
		"tun":        func(v *NodeChainExecutionTUNReadback) { v.TUNTag = "foreign" },
		"nonce":      func(v *NodeChainExecutionTUNReadback) { v.ReaderNonce = strings.Repeat("F", 64) },
		"generation": func(v *NodeChainExecutionTUNReadback) { v.ReaderGeneration = 0 },
		"interface":  func(v *NodeChainExecutionTUNReadback) { v.InterfaceName = "tun\n42" },
		"index":      func(v *NodeChainExecutionTUNReadback) { v.InterfaceIndex = 0 },
		"minimum":    func(v *NodeChainExecutionTUNReadback) { v.MTU = 1279 },
		"ceiling":    func(v *NodeChainExecutionTUNReadback) { v.MTU = bound.Ceiling + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			e.readMu.Lock()
			e.issued = changed
			e.readMu.Unlock()
			if err := f.runtime.projection.validateTUNReadback(changed, original.Identity); err == nil {
				t.Fatal("shared validation accepted changed native readback", name)
			}
			if _, err := f.runtime.CaptureMobileRestoreContext(ctx); err == nil {
				t.Fatal("changed or malformed native readback minted restore", name)
			}
		})
	}
	e.readMu.Lock()
	e.issued = original
	e.readMu.Unlock()
	capture, err := f.runtime.CaptureMobileRestoreContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodeChainExecutionReadbackRetire(t, f, e, ctx)
	e.readMu.Lock()
	e.issued.ReaderGeneration++
	e.readMu.Unlock()
	if _, err := capture.NewPreparationContext(ctx); err == nil {
		t.Fatal("replacement reader generation retired the original captured observation")
	}
	e.readMu.Lock()
	e.issued = original
	e.readMu.Unlock()
	if _, err := capture.NewPreparationContext(ctx); err != nil {
		t.Fatal("exact original retired readback could not be retried", err)
	}
}

func TestMobileNodeChainExecutionRestoreRejectsDifferentSourceOrUnprojectedGraph(t *testing.T) {
	f, e, ctx := nodeChainExecutionReadbackFixture(t, "android", "server", false)
	capture, err := f.runtime.CaptureMobileRestoreContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodeChainExecutionReadbackRetire(t, f, e, ctx)
	prep, err := capture.NewPreparationContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed := capture.restore.projection.policy.source
	changed.Request.Users = append(changed.Request.Users[:0:0], changed.Request.Users...)
	changed.Request.Users[0].Password = strings.Repeat("e", 48)
	foreign, err := NewNodeChainExecutionPolicy(startJSON(t, changed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prep.BindExecution(foreign); err == nil {
		t.Fatal("typed mobile restore replaced original front credentials")
	}
	next := cloneNodeChainExecutionRuntimeEngine(f.engine)
	if _, err := NewMobileNodeChainExecutionRestoreRuntime(ctx, capture, capture.restore.projection, next); err == nil {
		t.Fatal("ordinary original graph replaced captured effective mobile MTU")
	}
	projection, err := prep.BindExecution(capture.restore.projection.policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"engine", "session"} {
		reused := cloneNodeChainExecutionRuntimeEngine(f.engine)
		reused.projection = projection
		reused.identity.ConfigSHA256 = projection.ConfigSHA256()
		if field == "engine" {
			reused.identity.EngineID = capture.readback.Identity.EngineID
		} else {
			reused.identity.SessionID = capture.readback.Identity.SessionID
		}
		runtime, err := NewMobileNodeChainExecutionRestoreRuntime(ctx, capture, projection, reused)
		if err != nil {
			t.Fatal(err)
		}
		runtime.testTLS = f.trust
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := runtime.CloseContext(cleanup); err != nil {
				t.Error(err)
			}
		})
		if err := runtime.Run(ctx); err == nil {
			t.Fatal("mobile full restore reused original native engine or session", field)
		}
		if err := runtime.CloseContext(ctx); err != nil {
			t.Fatal(err)
		}
		reused.mu.Lock()
		selections := len(reused.selections)
		reused.mu.Unlock()
		if selections != 0 {
			t.Fatal("reused native owner entered mobile restore trials", field)
		}
	}
	other := capture
	other.readback.MTU++
	if _, err := NewMobileNodeChainExecutionRestoreRuntime(ctx, other, projection, next); err == nil {
		t.Fatal("caller scalar replaced issued native MTU observation")
	}
	var empty NodeChainExecutionMobileRestoreCapture
	if _, err := empty.NewPreparationContext(ctx); err == nil {
		t.Fatal("empty mobile capture minted preparation")
	}
	if _, err := empty.SourceContext(ctx); err == nil {
		t.Fatal("empty mobile capture returned logical source")
	}
}

func TestMobileNodeChainExecutionReadbackPreservesFinalFixedPolicy(t *testing.T) {
	projection := nodeChainExecutionMTUProjection(t, nodeChainExecutionMTUSource(t, 3, false, true))
	bound, err := projection.MTUPlan()
	if err != nil || bound.Ceiling <= bound.Original {
		t.Fatal("fixture must separate final Fixed value from graph ceiling", bound, err)
	}
	identity := NodeChainIdentity{"fixed-native-engine", "fixed-native-session", "fixed-network", projection.SourceSHA256(), projection.ConfigSHA256()}
	value := NodeChainExecutionTUNReadback{Identity: identity, TargetOS: "ios", TUNTag: bound.TUNTag,
		ReaderNonce: strings.Repeat("d", 64), ReaderGeneration: 1, InterfaceName: "utun77", InterfaceIndex: 77, MTU: bound.Original}
	if err := projection.validateTUNReadback(value, identity); err != nil {
		t.Fatal("original Fixed native readback was refused", err)
	}
	value.MTU++
	if err := projection.validateTUNReadback(value, identity); err == nil {
		t.Fatal("native readback changed final Fixed policy within packet ceiling")
	}
}

func TestMobileNodeChainExecutionRestoreRetainsCanceledNativeReadback(t *testing.T) {
	f, e, ctx := nodeChainExecutionReadbackFixture(t, "android", "server", false)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	e.beforeCapture = func(context.Context) { close(entered); <-release }
	call, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { _, err := f.runtime.CaptureMobileRestoreContext(call); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("mobile native readback did not enter")
	}
	cancel()
	if err := f.runtime.CloseContext(ctx); err == nil {
		t.Fatal("runtime acknowledged native close while mobile readback remained entered")
	}
	unblock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("late canceled readback minted mobile restore", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled mobile readback did not join")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("joined mobile readback blocked original cleanup", err)
	}
}
