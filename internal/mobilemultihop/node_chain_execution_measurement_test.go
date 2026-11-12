package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

type nodeChainExecutionMeasurementTestOwner struct {
	mu          sync.Mutex
	runtime     *NodeChainExecutionRuntime
	active      atomic.Bool
	releases    atomic.Int32
	releaseHook func()
	beginErr    error
}

func (o *nodeChainExecutionMeasurementTestOwner) MeasurementExecutionContext(ctx context.Context) (*NodeChainExecutionRuntime, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.runtime, ctx.Err()
}
func (o *nodeChainExecutionMeasurementTestOwner) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if ctx.Err() != nil || !o.active.CompareAndSwap(false, true) {
		return nil, errors.New("original native activity busy")
	}
	return func() {
		if o.releaseHook != nil {
			o.releaseHook()
		}
		o.releases.Add(1)
		o.active.Store(false)
	}, o.beginErr
}

func nodeChainExecutionMeasurementHTTP(t *testing.T, f *nodeChainExecutionRuntimeFixture) {
	t.Helper()
	for position, node := range f.runtime.projection.policy.local.nodes {
		api, _ := privateAPI(predecessorText(node.profile, "router_api"))
		token := predecessorText(node.profile, "api_token")
		proof := f.runtime.projection.policy.local.proofs[position]
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != api.Host || r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "foreign identity", 403)
				return
			}
			if position == 0 && r.URL.Path == nodeChainExecutionLeasePath {
				f.serveControl(w, r)
				return
			}
			switch r.URL.Path {
			case "/health":
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": proof.NodeID, "proof": "router-vpn-private-agent-v1"})
			case "/api/benchmark/download":
				w.Header().Set("Content-Length", "65536")
				w.Header().Set("X-Routervpn-Benchmark", "download-v1")
				w.Header().Set("X-Routervpn-Benchmark-Bytes", "65536")
				_, _ = w.Write(make([]byte, 65536))
			case "/api/benchmark/upload":
				n, _ := io.Copy(io.Discard, r.Body)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "direction": "upload", "bytes": n, "server_receive_ms": 1, "peer": "captured", "proof": "authenticated tunnel-peer private throughput sink"})
			default:
				http.Error(w, "unknown", 404)
			}
		}))
		t.Cleanup(server.Close)
		for _, execution := range []string{"local", "server"} {
			proofs, _ := f.runtime.projection.ProofInventory(execution)
			f.engine.mu.Lock()
			f.engine.peers[proofs[position].Tag+"/"+api.Host] = server.Listener.Addr().String()
			f.engine.mu.Unlock()
		}
	}
	// These replacement private peers must outlive the original fixed DELETE.
	// The fixture's earlier cleanup is idempotent after this real joined stop.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.runtime.CloseContext(ctx); err != nil {
			t.Error("measurement peer cleanup preceded original runtime stop", err)
		}
	})
}

func waitNodeChainExecutionMeasurement(t *testing.T, service *NodeChainExecutionMeasurement) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.RequestTimeout)
	defer cancel()
	for {
		var state hopmeasure.Status
		if json.Unmarshal([]byte(service.StatusContextJSON(ctx)), &state) != nil {
			t.Fatal("measurement status")
		}
		if state.Complete || state.Failure != "" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func nodeChainExecutionMeasurementFixture(t *testing.T, execution string, configure ...func(*nodeChainExecutionRuntimeFixture)) (*nodeChainExecutionRuntimeFixture, *nodeChainExecutionMeasurementTestOwner, *NodeChainExecutionMeasurement) {
	t.Helper()
	f := newNodeChainExecutionRuntimeFixture(t, execution)
	if execution == "auto" {
		f.engine.localDelay = time.Millisecond
		f.engine.serverDelay = 30 * time.Millisecond
	}
	for _, apply := range configure {
		apply(f)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	nodeChainExecutionMeasurementHTTP(t, f)
	owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
	service, err := f.runtime.NewHopMeasurementContext(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return f, owner, service
}

func TestNodeChainExecutionMeasurementUsesSelectedPrivatePrefixes(t *testing.T) {
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			f, owner, service := nodeChainExecutionMeasurementFixture(t, execution)
			selected := f.runtime.Progress().Execution
			if execution == "auto" && selected != "local" {
				t.Fatal("fixture did not select Local")
			}
			id := strings.Repeat("a", 32)
			if err := service.Start(id, 65536); err != nil {
				t.Fatal(err)
			}
			waitNodeChainExecutionMeasurement(t, service)
			if err := service.Drain(id); err != nil {
				t.Fatal(err)
			}
			var state hopmeasure.Status
			if err := json.Unmarshal([]byte(service.StatusJSON()), &state); err != nil {
				t.Fatal(err)
			}
			proofs, _ := f.runtime.projection.ProofInventory(selected)
			if !state.Complete || !state.Drained || state.Failure != "" || len(state.Results) != len(proofs) || owner.active.Load() || owner.releases.Load() != 1 {
				t.Fatal("selected measurement did not join original activity", state)
			}
			for i, result := range state.Results {
				if !result.Ready || result.ID != proofs[i].ProfileID || result.Download == nil || result.Download.Bytes != 65536 || result.Upload == nil || result.Upload.Bytes != 65536 || !strings.Contains(result.Label, "Cumulative "+selected+" path") {
					t.Fatal("selected prefix lost exact private byte/identity receipt", i, result)
				}
			}
			if err := service.StartResponse(strings.Repeat("b", 32), proofs[len(proofs)-1].ProfileID); err == nil {
				t.Fatal("private path gained external-origin receipt")
			}
		})
	}
}

func TestNodeChainExecutionMeasurementRejectsAnotherRuntimeAndRoute(t *testing.T) {
	var dials atomic.Int32
	var measuring atomic.Bool
	f, owner, service := nodeChainExecutionMeasurementFixture(t, "server", func(f *nodeChainExecutionRuntimeFixture) {
		f.engine.beforeDial = func(context.Context, string, string) (net.Conn, error, bool) {
			if measuring.Load() {
				dials.Add(1)
			}
			return nil, nil, false
		}
	})
	measuring.Store(true)
	service.engine.nextID = strings.Repeat("a", 32)
	release, err := service.engine.BeginMeasurementContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	local, _ := f.runtime.projection.ProofInventory("local")
	server, _ := f.runtime.projection.ProofInventory("server")
	for _, input := range [][2]string{{local[1].Tag, "10.81.0.1:8787"}, {server[1].Tag, "1.1.1.1:443"}, {"proxy", "10.80.0.1:8787"}} {
		if conn, err := service.engine.Dial(context.Background(), input[0], input[1]); err == nil || conn != nil {
			t.Fatal("measurement escaped exact selected prefix", input)
		}
	}
	release()
	if dials.Load() != 0 {
		t.Fatal("unowned route reached native dial")
	}
	other, err := NewNodeChainExecutionRuntime(f.runtime.projection, f.engine)
	if err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	owner.runtime = other
	owner.mu.Unlock()
	if err := service.Start(strings.Repeat("b", 32), 65536); err == nil {
		t.Fatal("same-identity replacement runtime inherited measurement")
	}
	if owner.active.Load() {
		t.Fatal("rejected replacement acquired original activity")
	}
}

func TestNodeChainExecutionMeasurementRequiresFreshServerReceipt(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	var reject atomic.Bool
	f.mutateStatus = func(status *multihoprelay.NodeChainLeaseStatus) {
		if reject.Load() {
			status.Receipt.Nonce = strings.Repeat("b", 64)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	nodeChainExecutionMeasurementHTTP(t, f)
	owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
	service, err := f.runtime.NewHopMeasurementContext(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	reject.Store(true)
	if err := service.engine.VerifyMeasurement(ctx); err == nil {
		t.Fatal("cached health accepted an unproved fresh server receipt")
	}
	id := strings.Repeat("a", 32)
	if err := service.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	if err := service.Drain(id); err != nil {
		t.Fatal(err)
	}
	var state hopmeasure.Status
	_ = json.Unmarshal([]byte(service.StatusJSON()), &state)
	if state.Failure == "" || len(state.Results) != 0 || !state.Drained {
		t.Fatal("cached health published measurement without original fresh server receipt", state)
	}
}

func TestNodeChainExecutionMeasurementRetainsFailedErrorConnection(t *testing.T) {
	var injected, allow, measuring atomic.Bool
	counts := &nodeChainExecutionDiscoveryTestEngine{}
	counts.closeBefore = func(int32) error {
		if !allow.Load() {
			return errors.New("original measurement close failed")
		}
		return nil
	}
	client, peer := net.Pipe()
	t.Cleanup(func() { allow.Store(true); _ = peer.Close(); _ = client.Close() })
	owned := &nodeChainExecutionDiscoveryTestConn{Conn: client, engine: counts}
	f, owner, service := nodeChainExecutionMeasurementFixture(t, "server", func(f *nodeChainExecutionRuntimeFixture) {
		proofs, _ := f.runtime.projection.ProofInventory("server")
		f.engine.beforeDial = func(_ context.Context, tag, address string) (net.Conn, error, bool) {
			if measuring.Load() && tag == proofs[1].Tag && injected.CompareAndSwap(false, true) {
				counts.dials.Add(1)
				return owned, errors.New("late native validation error"), true
			}
			return nil, nil, false
		}
	})
	measuring.Store(true)
	t.Cleanup(func() { allow.Store(true) })
	id := strings.Repeat("a", 32)
	if err := service.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	if err := service.Drain(id); err == nil {
		t.Fatal("failed original native close was reported drained")
	}
	var state hopmeasure.Status
	_ = json.Unmarshal([]byte(service.StatusJSON()), &state)
	if !injected.Load() || state.Drained || !owner.active.Load() || owner.releases.Load() != 0 || counts.closes.Load() != 0 {
		t.Fatal("failed original socket lost its native activity", state, owner.releases.Load())
	}
	if err := service.Start(strings.Repeat("b", 32), 65536); err == nil {
		t.Fatal("replacement overlapped retained original close")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := f.runtime.CloseContext(closeCtx); err == nil {
		t.Fatal("runtime acknowledged closed while measurement still owned native I/O")
	}
	cancel()
	allow.Store(true)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if owner.active.Load() || owner.releases.Load() != 1 || counts.dials.Load() != 1 || counts.closes.Load() != 1 {
		t.Fatal("retry lost/replaced original measurement resources")
	}
	closeCtx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.runtime.CloseContext(closeCtx); err != nil {
		t.Fatal("exact runtime did not acknowledge joined measurement retry", err)
	}
}

type nodeChainExecutionMeasurementHeldConn struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *nodeChainExecutionMeasurementHeldConn) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Conn.Close()
}

func TestNodeChainExecutionMeasurementJoinsLateDialAndClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	closing, finish := make(chan struct{}), make(chan struct{})
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	var measuring, injected atomic.Bool
	_, owner, service := nodeChainExecutionMeasurementFixture(t, "server", func(f *nodeChainExecutionRuntimeFixture) {
		proofs, _ := f.runtime.projection.ProofInventory("server")
		f.engine.beforeDial = func(_ context.Context, tag, address string) (net.Conn, error, bool) {
			if !measuring.Load() || tag != proofs[1].Tag || !injected.CompareAndSwap(false, true) {
				return nil, nil, false
			}
			close(entered)
			<-release
			return &nodeChainExecutionMeasurementHeldConn{Conn: client, entered: closing, release: finish}, nil, true
		}
	})
	var onceDial, onceClose sync.Once
	unblockDial := func() { onceDial.Do(func() { close(release) }) }
	unblockClose := func() { onceClose.Do(func() { close(finish) }) }
	t.Cleanup(func() { unblockClose(); unblockDial() })
	measuring.Store(true)
	id := strings.Repeat("a", 32)
	if err := service.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("native measurement dial not entered")
	}
	service.Cancel(id)
	short, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := service.CloseContext(short)
	cancel()
	if err == nil || !owner.active.Load() || owner.releases.Load() != 0 {
		t.Fatal("late dial abandoned native measurement hold", err)
	}
	unblockDial()
	select {
	case <-closing:
	case <-time.After(3 * time.Second):
		t.Fatal("original late socket close not entered")
	}
	var state hopmeasure.Status
	_ = json.Unmarshal([]byte(service.StatusJSON()), &state)
	if state.Drained || owner.releases.Load() != 0 {
		t.Fatal("socket close acknowledged before join")
	}
	unblockClose()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if owner.active.Load() || owner.releases.Load() != 1 {
		t.Fatal("late original join did not release exactly once")
	}
}

func TestNodeChainExecutionMeasurementJoinsActivityRelease(t *testing.T) {
	_, owner, service := nodeChainExecutionMeasurementFixture(t, "server")
	entered, release := make(chan struct{}), make(chan struct{})
	owner.releaseHook = func() { close(entered); <-release }
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	id := strings.Repeat("a", 32)
	if err := service.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	// This case owns the activity-release join, not the duration of a complete
	// fifty-sample throughput run (covered by UsesSelectedPrivatePrefixes).
	// Cancel the actual admitted worker so its release reaches our held owner
	// within the original handoff deadline, including race-instrumented CI.
	service.Cancel(id)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("original activity release not entered")
	}
	short, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := service.CloseContext(short)
	cancel()
	if err == nil || !owner.active.Load() || owner.releases.Load() != 0 {
		t.Fatal("unfinished native activity release was acknowledged")
	}
	unblock()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if owner.active.Load() || owner.releases.Load() != 1 {
		t.Fatal("original release lost or repeated")
	}
}

func TestNodeChainExecutionMeasurementRetainsPartialActivityAcquisition(t *testing.T) {
	f, owner, service := nodeChainExecutionMeasurementFixture(t, "server")
	entered, release := make(chan struct{}), make(chan struct{})
	owner.releaseHook = func() { close(entered); <-release }
	owner.beginErr = errors.New("source retired after native activity acquisition")
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	finished := make(chan error, 1)
	go func() { finished <- service.Start(strings.Repeat("a", 32), 65536) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("partial native activity did not enter original release")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := f.runtime.CloseContext(ctx); err == nil {
		t.Fatal("runtime dropped a partially acquired measurement activity")
	}
	cancel()
	if !owner.active.Load() || owner.releases.Load() != 0 {
		t.Fatal("partial activity released before real callback joined")
	}
	unblock()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("partial acquisition granted measurement")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original partial acquisition did not finish")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("joined partial activity blocked original cleanup", err)
	}
	if owner.active.Load() || owner.releases.Load() != 1 {
		t.Fatal("partial release repeated or lost")
	}
}

type rejectingExecutionMeasurementOwner struct{ t *testing.T }

func (o rejectingExecutionMeasurementOwner) MeasurementExecutionContext(context.Context) (*NodeChainExecutionRuntime, error) {
	o.t.Fatal("invalid caller reached native owner")
	return nil, nil
}
func (o rejectingExecutionMeasurementOwner) BeginMeasurementContext(context.Context) (func(), error) {
	o.t.Fatal("invalid caller acquired native activity")
	return nil, nil
}

func TestNodeChainExecutionMeasurementRejectsInvalidCaller(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	owner := rejectingExecutionMeasurementOwner{t}
	if _, err := f.runtime.NewHopMeasurementContext(nil, owner); err == nil {
		t.Fatal("nil caller accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.runtime.NewHopMeasurementContext(ctx, owner); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller entered native owner", err)
	}
}
