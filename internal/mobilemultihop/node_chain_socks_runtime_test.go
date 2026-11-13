package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

// Native manager/outbound/packet pointers are explicit doubles in this shared
// fixture. The existing paired HTTP authentication and public TLS peer execute
// unchanged. Actual encrypted SOCKS associations and Box.Close belong to the
// separate pinned-native owner gate.
type nodeChainSOCKSTestEngine struct {
	*nodeChainTestEngine
	ownerMu                                      sync.Mutex
	source                                       *NodeChainSOCKSSource
	config                                       string
	meta                                         NodeChainSOCKSSourceMetadata
	manager, middle, lower                       *int
	originalManager, originalMiddle, originalLower *int
	retired                                      bool
	middlePeer                                   string
	middleCalls                                  atomic.Int32
	dialCalls                                    atomic.Int32
	observer                                     func(context.Context) error
	dialHook                                     func(context.Context, string, string) (net.Conn, error, bool)
	nativeClosed                                 atomic.Bool
}

func newNodeChainSOCKSRuntimeFixture(t *testing.T, mode string) (*NodeChainSOCKSRuntime, *nodeChainSOCKSTestEngine) {
	t.Helper()
	source, err := NewNodeChainSOCKSSource(startJSON(t, nodeChainSOCKSFixture(t, mode, "", "password")))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewNodeChainSOCKSRuntime(source)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the original paired peers and their strict API/token/TLS checks.
	// Only the native test dial table changes to the already-compiled positional
	// tags; no source, graph, credential, proof identity or sealed receipt changes.
	base := newNodeChainTestEngine(t, source.pair)
	originalFinal, final := source.pair.FinalTag(), runtime.chain.FinalTag()
	base.peers[final], base.expected[final] = base.peers[originalFinal], base.expected[originalFinal]
	delete(base.peers, originalFinal)
	delete(base.expected, originalFinal)
	base.chain = runtime.chain
	base.identity.SourceSHA256, base.identity.ConfigSHA256 = runtime.chain.SourceSHA256(), runtime.chain.ConfigSHA256()
	runtime.chain.runtime.testTLS = source.pair.runtime.testTLS
	config, meta, err := source.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	engine := &nodeChainSOCKSTestEngine{
		nodeChainTestEngine: base, source: source, config: config, meta: meta,
		manager: new(int), middle: new(int), lower: new(int), middlePeer: base.publicPeer,
	}
	engine.originalManager, engine.originalMiddle, engine.originalLower = engine.manager, engine.middle, engine.lower
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := runtime.CloseContext(ctx); err != nil {
			t.Error("original typed proof cleanup did not join", err)
		}
	})
	return runtime, engine
}

func (e *nodeChainSOCKSTestEngine) ObserveSOCKSMiddleContext(ctx context.Context, source *NodeChainSOCKSSource) error {
	e.middleCalls.Add(1)
	e.ownerMu.Lock()
	valid := source == e.source && !e.retired && e.manager == e.originalManager &&
		e.middle == e.originalMiddle && e.lower == e.originalLower
	config, meta, observer := e.config, e.meta, e.observer
	e.ownerMu.Unlock()
	if !valid || ctx.Err() != nil {
		return errors.New("original native SOCKS owner changed")
	}
	actual, receipt, err := source.ReadValidated()
	if err != nil || actual != config || !reflect.DeepEqual(receipt, meta) {
		return nodeChainSOCKSSourceError
	}
	if observer != nil {
		if err := observer(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (e *nodeChainSOCKSTestEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	e.dialCalls.Add(1)
	e.ownerMu.Lock()
	hook, peer := e.dialHook, e.middlePeer
	e.ownerMu.Unlock()
	if hook != nil {
		if conn, err, handled := hook(ctx, tag, address); handled {
			return conn, err
		}
	}
	if tag == e.chain.proofs[1].Tag {
		if address != "1.1.1.1:443" && address != hopmeasure.PublicAddress {
			return nil, errors.New("SOCKS middle cannot adopt a private proof target")
		}
		e.mu.Lock()
		dead := e.dead == 1
		e.mu.Unlock()
		if dead {
			return nil, errors.New("original SOCKS middle route stopped")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", peer)
	}
	return e.nodeChainTestEngine.Dial(ctx, tag, address)
}

func TestNodeChainSOCKSRuntimeUsesOriginalProofLifecycle(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			runtime, engine := newNodeChainSOCKSRuntimeFixture(t, mode)
			original, meta, err := runtime.source.ReadValidated()
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.Run(context.Background(), engine); err != nil {
				t.Fatal(err)
			}
			if err := runtime.HealthyContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			progress := runtime.Progress()
			if !progress.Ready || !progress.Complete || progress.Stage != "selected" ||
				!progress.DNSProven || !progress.PublicProven || len(progress.Prefixes) != 3 ||
				progress.Prefixes[1].Kind != "public-path" || progress.Prefixes[1].Label == "" {
				t.Fatal("typed SOCKS source bypassed complete original proofs", progress)
			}
			for _, proof := range progress.Prefixes {
				if !proof.Proven || proof.ResponseMS <= 0 {
					t.Fatal("typed SOCKS path published an unmeasured prefix", proof)
				}
			}
			engine.mu.Lock()
			privateCalls, dnsCalls := len(engine.calls), engine.dnsCalls
			engine.mu.Unlock()
			if privateCalls != 4 || dnsCalls != 1 || engine.dialCalls.Load() != 7 || engine.middleCalls.Load() == 0 {
				t.Fatal("typed path changed original HTTP/TLS proof inventory", privateCalls, dnsCalls, engine.dialCalls.Load())
			}
			after, receipt, err := runtime.source.ReadValidated()
			if err != nil || original != after || !reflect.DeepEqual(meta, receipt) ||
				runtime.chain.DNSCapture() != meta.DNS {
				t.Fatal("runtime changed selected source, final DNS or configured MTU", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			if runtime.Progress().Ready || runtime.HealthyContext(ctx) == nil ||
				runtime.Run(ctx, engine) == nil || engine.nativeClosed.Load() {
				t.Fatal("shared retirement fabricated reuse or native DOWN")
			}
		})
	}
}

func TestNodeChainSOCKSRuntimeRequiresExactNativeMiddle(t *testing.T) {
	for _, fault := range []string{"missing-interface", "source-object", "config", "metadata", "manager", "middle", "lower", "retired"} {
		t.Run(fault, func(t *testing.T) {
			runtime, engine := newNodeChainSOCKSRuntimeFixture(t, "wg")
			switch fault {
			case "source-object":
				raw, err := runtime.source.Source()
				if err != nil {
					t.Fatal(err)
				}
				engine.source, err = NewNodeChainSOCKSSource(raw)
				if err != nil {
					t.Fatal(err)
				}
			case "config":
				engine.config += " "
			case "metadata":
				engine.meta.Proofs[1].Tag = "foreign"
			case "manager":
				engine.manager = new(int)
			case "middle":
				engine.middle = new(int)
			case "lower":
				engine.lower = new(int)
			case "retired":
				engine.retired = true
			}
			var err error
			if fault == "missing-interface" {
				// Even the private underlying controller must not accept an
				// ordinary engine when the typed source needs this observer.
				err = runtime.chain.Run(context.Background(), engine.nodeChainTestEngine)
			} else {
				err = runtime.Run(context.Background(), engine)
			}
			engine.mu.Lock()
			selected, calls := engine.selected, len(engine.calls)
			engine.mu.Unlock()
			if err == nil || runtime.Progress().Ready || selected != "" || calls != 0 || engine.dialCalls.Load() != 0 {
				t.Fatal("missing original SOCKS owner reached native selection or proof", fault, err, selected, calls)
			}
		})
	}
}

func TestNodeChainSOCKSRuntimeRetiresChangedOwner(t *testing.T) {
	for _, fault := range []string{"manager", "middle", "lower", "retired", "engine", "session", "network", "source-hash", "config-hash", "selection"} {
		t.Run(fault, func(t *testing.T) {
			runtime, engine := newNodeChainSOCKSRuntimeFixture(t, "wg")
			if err := runtime.Run(context.Background(), engine); err != nil {
				t.Fatal(err)
			}
			engine.ownerMu.Lock()
			switch fault {
			case "manager":
				engine.manager = new(int)
			case "middle":
				engine.middle = new(int)
			case "lower":
				engine.lower = new(int)
			case "retired":
				engine.retired = true
			}
			engine.ownerMu.Unlock()
			engine.mu.Lock()
			switch fault {
			case "engine":
				engine.identity.EngineID = "replacement-engine"
			case "session":
				engine.identity.SessionID = "replacement-session"
			case "network":
				engine.identity.NetworkID = "replacement-network"
			case "source-hash":
				engine.identity.SourceSHA256 = strings.Repeat("a", 64)
			case "config-hash":
				engine.identity.ConfigSHA256 = strings.Repeat("b", 64)
			case "selection":
				engine.selected = "replacement-route"
			}
			engine.mu.Unlock()
			if runtime.HealthyContext(context.Background()) == nil || runtime.Progress().Ready {
				t.Fatal("changed original SOCKS owner remained healthy", fault)
			}
		})
	}
}

func TestNodeChainSOCKSRuntimePreservesProofRefusals(t *testing.T) {
	for _, fault := range []string{"first-private", "middle-route", "middle-public-ip", "final-private", "final-dns", "changed-source"} {
		t.Run(fault, func(t *testing.T) {
			runtime, engine := newNodeChainSOCKSRuntimeFixture(t, "wg")
			switch fault {
			case "first-private":
				engine.wrong = 0
			case "middle-route":
				engine.dead = 1
			case "middle-public-ip":
				engine.publicBody = "ip=198.51.100.7\n"
			case "final-private":
				engine.wrong = 1 // Original paired peer fixture's final position.
			case "final-dns":
				engine.dnsFail = true
			case "changed-source":
				runtime.source.middle.selection.Profile["api_token"] = "not-a-paired-node"
			}
			if err := runtime.Run(context.Background(), engine); err == nil || runtime.Progress().Ready {
				t.Fatal("typed SOCKS path admitted a failed original proof", fault, err)
			}
		})
	}
}

func TestNodeChainSOCKSRuntimeJoinsOriginalCancellation(t *testing.T) {
	for _, phase := range []string{"middle-observer", "middle-dial"} {
		t.Run(phase, func(t *testing.T) {
			runtime, engine := newNodeChainSOCKSRuntimeFixture(t, "wg")
			entered, release := make(chan struct{}), make(chan struct{})
			var once, releaseOnce sync.Once
			var closes atomic.Int32
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			if phase == "middle-observer" {
				engine.observer = func(ctx context.Context) error {
					once.Do(func() { close(entered); <-release })
					return ctx.Err()
				}
			} else {
				engine.dialHook = func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
					if tag != runtime.chain.proofs[1].Tag {
						return nil, nil, false
					}
					once.Do(func() { close(entered); <-release })
					client, peer := net.Pipe()
					_ = peer.Close()
					return &nodeChainCloseCount{client, &closes}, nil, true
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- runtime.Run(ctx, engine) }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("original SOCKS callback was not reached")
			}
			cancel()
			short, finish := context.WithTimeout(context.Background(), 20*time.Millisecond)
			err := runtime.CloseContext(short)
			finish()
			if !errors.Is(err, context.DeadlineExceeded) || runtime.Progress().Ready {
				t.Fatal("shared close abandoned original SOCKS work", err)
			}
			unblock()
			joined, finish := context.WithTimeout(context.Background(), 2*time.Second)
			defer finish()
			if err := runtime.CloseContext(joined); err != nil {
				t.Fatal("same original SOCKS work did not join on retry", err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("late cancelled SOCKS callback revived readiness")
				}
			case <-joined.Done():
				t.Fatal("original typed Run did not join")
			}
			if phase == "middle-dial" && closes.Load() != 1 || engine.nativeClosed.Load() {
				t.Fatal("shared close replaced its socket or claimed native retirement", closes.Load())
			}
		})
	}
}

type nodeChainSOCKSMeasurementFixture struct {
	runtime  *NodeChainSOCKSRuntime
	active   atomic.Bool
	released atomic.Int32
}

func (o *nodeChainSOCKSMeasurementFixture) MeasurementSOCKSContext(ctx context.Context) (*NodeChainSOCKSRuntime, error) {
	return o.runtime, ctx.Err()
}
func (o *nodeChainSOCKSMeasurementFixture) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if ctx.Err() != nil || !o.active.CompareAndSwap(false, true) {
		return nil, errors.New("original SOCKS measurement activity occupied")
	}
	return func() { o.released.Add(1); o.active.Store(false) }, nil
}

func TestNodeChainSOCKSRuntimeMeasurementKeepsPublicScopeAndDrain(t *testing.T) {
	runtime, engine := newNodeChainSOCKSRuntimeFixture(t, "wg")
	owner := &nodeChainSOCKSMeasurementFixture{runtime: runtime}
	if _, err := runtime.NewHopMeasurementContext(context.Background(), owner); err == nil {
		t.Fatal("unproved typed SOCKS source acquired measurement")
	}
	if err := runtime.Run(context.Background(), engine); err != nil {
		t.Fatal(err)
	}
	adapter := nodeChainSOCKSMeasurementOwner{runtime.source, owner}
	measured := &nodeChainMeasurementEngine{source: runtime.chain, owner: adapter, identity: engine.identity}
	before := engine.dialCalls.Load()
	for _, input := range [][2]string{
		{runtime.chain.proofs[1].Tag, "10.80.0.1:8787"},
		{runtime.chain.proofs[0].Tag, hopmeasure.PublicAddress},
		{"proxy", hopmeasure.PublicAddress},
	} {
		connection, err := measured.Dial(context.Background(), input[0], input[1])
		if err == nil || connection != nil {
			t.Fatal("SOCKS measurement escaped its original public scope", input)
		}
	}
	if engine.dialCalls.Load() != before {
		t.Fatal("foreign measurement reached the native dialer")
	}
	connection, err := measured.Dial(context.Background(), runtime.chain.proofs[1].Tag, hopmeasure.PublicAddress)
	if err != nil || connection == nil {
		t.Fatal("original public middle target was not routed", err)
	}
	_ = connection.Close()
	// Execute an actual measurement worker, then hold its native return across
	// cancellation. The test requires activity retention until that worker and
	// its returned socket join, not a synthetic successful public benchmark.
	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	var closes atomic.Int32
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	engine.ownerMu.Lock()
	engine.dialHook = func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
		if tag != runtime.chain.proofs[0].Tag {
			return nil, nil, false
		}
		once.Do(func() { close(entered); <-release })
		client, peer := net.Pipe()
		_ = peer.Close()
		return &nodeChainCloseCount{client, &closes}, nil, true
	}
	engine.ownerMu.Unlock()
	service, err := runtime.NewHopMeasurementContext(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unblock(); _ = service.Close() })
	request := strings.Repeat("d", 32)
	if err := service.Start(request, 65536); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actual original measurement worker did not enter")
	}
	service.Cancel(request)
	done := make(chan error, 1)
	go func() { done <- service.Drain(request) }()
	select {
	case err := <-done:
		t.Fatal("measurement drain abandoned its original returned socket", err)
	case <-time.After(20 * time.Millisecond):
	}
	if !owner.active.Load() || owner.released.Load() != 0 {
		t.Fatal("original measurement exclusion ended before worker join")
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("original SOCKS measurement worker did not join")
	}
	var status hopmeasure.Status
	if err := json.Unmarshal([]byte(service.StatusJSON()), &status); err != nil ||
		!status.Complete || !status.Drained || owner.active.Load() || owner.released.Load() != 1 || closes.Load() != 1 {
		t.Fatal("measurement cancellation lost its actual drain receipt", err, status, closes.Load())
	}
	foreign, err := NewNodeChainSOCKSRuntime(runtime.source)
	if err != nil {
		t.Fatal(err)
	}
	owner.runtime = foreign
	if _, err := runtime.NewHopMeasurementContext(context.Background(), owner); err == nil {
		t.Fatal("unproved replacement acquired the original measurement owner")
	}
}

func TestNodeChainSOCKSRuntimeKeepsGenericAdmissionClosed(t *testing.T) {
	runtime, _ := newNodeChainSOCKSRuntimeFixture(t, "wg")
	for _, name := range []string{"LaunchInput", "RunServer", "NewCandidatePlan", "PhysicalReadValidated", "NativeClosed", "BindNative"} {
		if _, exists := reflect.TypeOf(runtime).MethodByName(name); exists {
			t.Fatal("typed proof runtime lent unrelated admission", name)
		}
	}
	if _, ok := any(runtime).(DesktopPhysicalPolicy); ok {
		t.Fatal("typed proof runtime acquired physical authority")
	}
	raw, err := runtime.source.Source()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNodeChain(raw); err == nil {
		t.Fatal("generic source parser admitted typed SOCKS runtime")
	}
	if launch, err := runtime.chain.LaunchInput(); err == nil || launch != "" {
		t.Fatal("private runtime chain lent generic launch authority")
	}
	for _, execution := range []string{"local", "server", "auto"} {
		if _, err := NewNodeChainExecutionPreparation(raw, execution); err == nil {
			t.Fatal("typed source acquired generic execution authority", execution)
		}
	}
	original := nodeChainImportedFixture(t, "wg", "")
	if _, err := NewNodeChain(startJSON(t, original)); err != nil {
		t.Fatal("original schema2 changed", err)
	}
}
