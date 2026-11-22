package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

// HTTP/TLS, the shared controller, lease protocol and fifty-sample worker are
// real. Native routing and remote worker receipts use the existing explicit
// fixture doubles; this does not claim encrypted or device acceptance.
type executionEntryOwner struct {
	*nodeChainExecutionMeasurementTestOwner
	capture    string
	catalogErr atomic.Bool
	calls      atomic.Int32
}

func (o *executionEntryOwner) CandidateInventoryCurrentContext(ctx context.Context, capture string) error {
	o.calls.Add(1)
	if o.catalogErr.Load() || capture != o.capture {
		return hopmeasure.ErrStale
	}
	return ctx.Err()
}
func entryInventory(t *testing.T) (string, string) {
	input, address := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	return candidateInventoryFixture(t, "entry-catalog-1", input), address
}
func entryRun(t *testing.T, f *nodeChainExecutionRuntimeFixture, outcome string) {
	t.Helper()
	var refused atomic.Int32
	var trialsMu sync.Mutex
	var trials []*nodeChainExecutionTrial
	if strings.HasPrefix(outcome, "compare-") {
		winner := strings.TrimPrefix(outcome, "compare-")
		loser := "local"
		if winner == "local" {
			loser = "server"
		}
		proofs, _ := f.runtime.projection.ProofInventory(loser)
		last := len(proofs) - 1
		api, err := privateAPI(predecessorText(f.runtime.projection.policy.local.nodes[last].profile, "router_api"))
		if err != nil {
			t.Fatal(err)
		}
		f.engine.beforeDial = func(_ context.Context, tag, address string) (net.Conn, error, bool) {
			if tag == proofs[last].Tag && address == api.Host {
				refused.Add(1)
				return nil, errors.New("fixture refuses only losing final proof"), true
			}
			return nil, nil, false
		}
		f.engine.beforeDNS = func(context.Context) {
			f.runtime.mu.Lock()
			trial := f.runtime.active
			f.runtime.mu.Unlock()
			if trial != nil && trial.execution == winner {
				trialsMu.Lock()
				if len(trials) == 0 || trials[len(trials)-1] != trial {
					trials = append(trials, trial)
				}
				trialsMu.Unlock()
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	progress := f.runtime.Progress()
	want := strings.TrimPrefix(outcome, "compare-")
	if !progress.Ready || progress.Execution != want {
		t.Fatal("fixture did not select requested actual winner", progress.Execution)
	}
	if strings.HasPrefix(outcome, "compare-") {
		if refused.Load() == 0 || len(progress.Comparison.Measurements) != 2 || progress.Comparison.Final == nil || progress.Comparison.Winner == nil {
			t.Fatal("missing deterministic comparison proof")
		}
		for i, m := range progress.Comparison.Measurements {
			expected := "local"
			if i == 1 {
				expected = "server"
			}
			if m.Candidate != f.runtime.candidate(expected) {
				t.Fatal("comparison replaced original candidate")
			}
			if expected == want {
				if !m.Eligible || m.ScoreMS == nil || m.LastNodeMS <= 0 || m.ExternalMS <= 0 || *m.ScoreMS != (m.LastNodeMS+m.ExternalMS)/2 {
					t.Fatal("winning two-probe formula lost")
				}
			} else if m.Eligible || m.ScoreMS != nil {
				t.Fatal("refused losing proof obtained a score")
			}
		}
		final := progress.Comparison.Final
		if !final.Eligible || final.ScoreMS == nil || final.LastNodeMS <= 0 || final.ExternalMS <= 0 || *final.ScoreMS != (final.LastNodeMS+final.ExternalMS)/2 || final.Candidate != f.runtime.candidate(want) {
			t.Fatal("fresh winner lost actual formula")
		}
		trialsMu.Lock()
		captured := append([]*nodeChainExecutionTrial(nil), trials...)
		trialsMu.Unlock()
		if len(captured) != 2 || captured[0].id == captured[1].id || captured[1] != f.runtime.active {
			t.Fatal("winner reused a retired trial")
		}
	}
}
func entryFixture(t *testing.T, outcome string) (*nodeChainExecutionRuntimeFixture, *NodeChainExecutionCandidatePlan, *executionEntryOwner, string) {
	t.Helper()
	execution := "server"
	if strings.HasPrefix(outcome, "compare-") {
		execution = "auto"
	}
	f := newNodeChainExecutionRuntimeFixture(t, execution)
	entryRun(t, f, outcome)
	inventory, address := entryInventory(t)
	p, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	o := &executionEntryOwner{nodeChainExecutionMeasurementTestOwner: &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}, capture: p.CaptureSHA256()}
	return f, p, o, address
}
func entryMeasurement(t *testing.T, p *NodeChainExecutionCandidatePlan, o *executionEntryOwner) *NodeChainExecutionCandidateMeasurement {
	t.Helper()
	s, err := p.NewMeasurementContext(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}
func entryStatus(t *testing.T, s *NodeChainExecutionCandidateMeasurement) hopmeasure.CandidateStatus {
	t.Helper()
	var status hopmeasure.CandidateStatus
	if json.Unmarshal([]byte(s.StatusJSON()), &status) != nil {
		t.Fatal("invalid candidate status")
	}
	return status
}
func entryWait(t *testing.T, s *NodeChainExecutionCandidateMeasurement) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), hopmeasure.RequestTimeout+hopmeasure.ObservationTimeout)
	defer cancel()
	for {
		state := entryStatus(t, s)
		if state.Complete {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func entryTarget(t *testing.T, f *nodeChainExecutionRuntimeFixture, p *NodeChainExecutionCandidatePlan, address string) *atomic.Int32 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	f.engine.mu.Lock()
	f.engine.peers[p.plan.prefix.Tag+"/"+address] = listener.Addr().String()
	f.engine.mu.Unlock()
	return count
}

// Like executionFiftyMeasurementFixture, this is an explicit event from the
// retained native-worker model. A lease heartbeat must not fabricate ProofAt.
// The actual fifty TCP samples and every original freshness check remain live.
func entryMaintainServerProof(t *testing.T, f *nodeChainExecutionRuntimeFixture) *atomic.Int32 {
	t.Helper()
	completed := new(atomic.Int32)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	refresh := func() error {
		f.runner.mu.Lock()
		workers := append([]*nodeChainExecutionRuntimeWorker(nil), f.runner.workers...)
		f.runner.mu.Unlock()
		for _, worker := range workers {
			if worker.alive.Load() && worker.ready.Load() {
				if err := worker.Bootstrap(ctx); err != nil {
					return err
				}
				completed.Add(1)
			}
		}
		return nil
	}
	// A successful fifty can finish before the first periodic refresh. Deliver
	// the same actual worker event before returning; elapsed time is not proof.
	if err := refresh(); err != nil {
		cancel()
		t.Fatal("initial original worker proof event", err)
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if refresh() != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return completed
}

func TestNodeChainExecutionEntryCandidateImmediateWorkerProof(t *testing.T) {
	f, _, _, _ := entryFixture(t, "server")
	if completed := entryMaintainServerProof(t, f); completed.Load() == 0 {
		t.Fatal("original worker completion depended on a later timer tick")
	}
}

func TestNodeChainExecutionEntryCandidateOrdinaryFifty(t *testing.T) {
	for _, outcome := range []string{"server", "compare-local", "compare-server"} {
		t.Run(outcome, func(t *testing.T) {
			f, p, o, address := entryFixture(t, outcome)
			proofEvents := entryMaintainServerProof(t, f)
			count := entryTarget(t, f, p, address)
			s := entryMeasurement(t, p, o)
			id := strings.Repeat("a", 32)
			if err := s.Start(id, p.plan.targets[0].ID); err != nil {
				t.Fatal(err)
			}
			entryWait(t, s)
			if err := s.Drain(id); err != nil {
				t.Fatal(err)
			}
			state := entryStatus(t, s)
			if !state.Complete || !state.Drained || state.Failure != "" || len(state.Results) != 1 || !state.Results[0].Ready || state.Results[0].Benchmark == nil {
				t.Fatal("missing completed original candidate result", state)
			}
			b := state.Results[0].Benchmark
			if b.Attempts != 50 || b.Failed != 0 || b.Distribution == nil || b.Distribution.Samples != 50 || count.Load() != 50 || o.active.Load() || o.releases.Load() != 1 {
				t.Fatal("entry candidate lost exact fifty samples or original lease", b, count.Load())
			}
			if p.trial.execution == "server" && proofEvents.Load() == 0 {
				t.Fatal("fifty candidate fixture omitted original worker proof completion events")
			}
			if f.runtime.active != p.trial || f.runtime.engine != p.native || f.runtime.Progress().Execution != p.trial.execution {
				t.Fatal("candidate reopened or replaced selected execution")
			}
		})
	}
}
func TestNodeChainExecutionEntryCandidateSourceAndScope(t *testing.T) {
	f, p, _, _ := entryFixture(t, "server")
	inventory, _ := entryInventory(t)
	for _, fault := range []string{"nil-context", "cancelled-context", "negative-position", "later-position", "final-position", "empty", "malformed", "schema", "revision", "empty-targets", "duplicate-target", "foreign-input", "copied-plan", "copied-runtime"} {
		t.Run(fault, func(t *testing.T) {
			ctx := t.Context()
			position := 0
			raw := inventory
			r := f.runtime
			switch fault {
			case "nil-context":
				ctx = nil
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "negative-position":
				position = -1
			case "later-position":
				position = 1
			case "final-position":
				position = 2
			case "empty":
				raw = ""
			case "malformed":
				raw = "{"
			case "schema", "revision", "empty-targets", "duplicate-target", "foreign-input":
				var record NodeChainCandidateInventory
				_ = json.Unmarshal([]byte(raw), &record)
				switch fault {
				case "schema":
					record.Schema = 2
				case "revision":
					record.Revision = ""
				case "empty-targets":
					record.Inputs = nil
				case "duplicate-target":
					record.Inputs = append(record.Inputs, record.Inputs[0])
				case "foreign-input":
					record.Inputs = []string{`{"kind":"foreign"}`}
				}
				raw = startJSON(t, record)
			case "copied-plan":
				copy := *p
				if copy.validate() == nil || copy.Metadata() != "" {
					t.Fatal("copied plan retained entry authority")
				}
				return
			case "copied-runtime":
				r = &NodeChainExecutionRuntime{projection: f.runtime.projection, engine: f.runtime.engine, identity: p.identity, active: p.trial, lifetime: f.runtime.lifetime}
			}
			if got, err := r.NewEntryCandidatePlanContext(ctx, position, raw); err == nil || got != nil {
				t.Fatal("entry-only sealed source refusal missing", fault)
			}
		})
	}
}
func TestNodeChainExecutionEntryCandidateOriginalAuthority(t *testing.T) {
	for _, fault := range []string{"owner", "native", "trial", "epoch", "projection", "preparation", "catalog", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			f, p, o, _ := entryFixture(t, "server")
			ctx := t.Context()
			restore := func() {}
			switch fault {
			case "owner":
				o.runtime = &NodeChainExecutionRuntime{}
				restore = func() { o.runtime = f.runtime }
			case "native":
				old := p.native
				p.native = &nodeChainExecutionRuntimeEngine{}
				restore = func() { p.native = old }
			case "trial":
				old := p.trial
				p.trial = &nodeChainExecutionTrial{runtime: f.runtime}
				restore = func() { p.trial = old }
			case "epoch":
				f.engine.mu.Lock()
				f.engine.epoch++
				f.engine.mu.Unlock()
				restore = func() { f.engine.mu.Lock(); f.engine.epoch--; f.engine.mu.Unlock() }
			case "projection":
				old := p.projection
				copy := *old
				p.projection = &copy
				restore = func() { p.projection = old }
			case "preparation":
				old := p.preparation
				copy := *old
				p.preparation = &copy
				restore = func() { p.preparation = old }
			case "catalog":
				o.catalogErr.Store(true)
				restore = func() { o.catalogErr.Store(false) }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer restore()
			if got, err := p.NewMeasurementContext(ctx, o); err == nil || got != nil || o.active.Load() {
				t.Fatal("foreign original execution acquired candidate", fault)
			}
		})
	}
}
func TestNodeChainExecutionEntryCandidateMetadata(t *testing.T) {
	_, p, _, _ := entryFixture(t, "server")
	var m map[string]any
	if json.Unmarshal([]byte(p.Metadata()), &m) != nil {
		t.Fatal("metadata")
	}
	for _, field := range []string{"source_sha256", "config_sha256", "preparation_source_sha256", "preparation_config_sha256"} {
		t.Run(field, func(t *testing.T) {
			expected := map[string]string{"source_sha256": p.projection.SourceSHA256(), "config_sha256": p.projection.ConfigSHA256(), "preparation_source_sha256": p.preparation.SourceSHA256(), "preparation_config_sha256": p.preparation.ConfigSHA256()}
			if m[field] != expected[field] {
				t.Fatal("preparation/projection identity relabeled", field)
			}
			copy := *p
			copy.self = &copy
			if strings.HasPrefix(field, "preparation_") {
				prep := *p.preparation
				copy.preparation = &prep
			} else {
				projection := *p.projection
				copy.projection = &projection
			}
			if copy.Metadata() != "" {
				t.Fatal("substituted identity acquired metadata")
			}
		})
	}
	if m["execution"] != "server" || m["requested_execution"] != "server" || m["selection_epoch"] != float64(p.trial.selectionEpoch) || m["prefix_position"] != float64(0) || m["capture_sha256"] != p.capture {
		t.Fatal("selected execution metadata lost scope")
	}
}
func TestNodeChainExecutionEntryCandidateTypedSource(t *testing.T) {
	for _, family := range []string{"socks", "connect", "openvpn"} {
		t.Run(family, func(t *testing.T) {
			var f *nodeChainExecutionRuntimeFixture
			switch family {
			case "socks":
				f = socksExecutionRuntimeFixture(t, "server")
			case "connect":
				f = newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionFixtureSource(t, "server"))
			case "openvpn":
				f = openVPNExecutionRuntimeFixture(t, "server")
			}
			entryRun(t, f, "server")
			inventory, _ := entryInventory(t)
			p, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 0, inventory)
			if err != nil {
				t.Fatal(err)
			}
			if p.preparation != f.runtime.projection.preparation || p.projection != f.runtime.projection || p.native != f.engine || p.plan.chain != f.runtime.projection.policy.local {
				t.Fatal("typed entry substituted detached local authority")
			}
			o := &executionEntryOwner{nodeChainExecutionMeasurementTestOwner: &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}, capture: p.CaptureSHA256()}
			measurement := entryMeasurement(t, p, o)
			if o.calls.Load() == 0 || measurement.engine.plan != p {
				t.Fatal("typed entry bypassed actual catalog/owner")
			}

		})
	}
}
func TestNodeChainExecutionEntryCandidateDormant(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	inventory, _ := entryInventory(t)
	if p, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 0, inventory); err == nil || p != nil {
		t.Fatal("dormant execution obtained entry candidate")
	}
}
func TestNodeChainExecutionEntryCandidateCopiedMeasurement(t *testing.T) {
	// A failed terminal row can be drained by the worker while the original
	// host callback is still retained. No result may escape that pending scope.
	failed := hopmeasure.CandidateStatus{Status: hopmeasure.Status{Complete: true, Drained: true, Stage: "failed", Failure: "original close failed", Results: []hopmeasure.Result{{ID: "captured-candidate"}}}}
	nodeChainExecutionCandidateMaskPending(&failed, true)
	if failed.Drained || len(failed.Results) != 0 || failed.Failure != "original close failed" {
		t.Fatal("failed pending cleanup exposed candidate rows")
	}
	_, p, o, _ := entryFixture(t, "server")
	s := entryMeasurement(t, p, o)
	copy := *s
	if copy.Start(strings.Repeat("b", 32), p.plan.targets[0].ID) == nil || copy.Close() == nil || copy.StatusJSON() != "{}" {
		t.Fatal("copied measurement acquired cleanup authority")
	}
	copy.Invalidate()
	if s.engine.base.closed.Load() {
		t.Fatal("copied measurement retired original")
	}
}
func TestNodeChainExecutionEntryCandidateRuntimeActivity(t *testing.T) {
	_, p, o, _ := entryFixture(t, "server")
	s := entryMeasurement(t, p, o)
	release, err := o.BeginMeasurementContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(strings.Repeat("c", 32), p.plan.targets[0].ID); err == nil {
		release()
		t.Fatal("candidate bypassed original MTU activity")
	}
	release()
	if o.active.Load() || p.runtime.measurementHolds != 0 {
		t.Fatal("failed admission lost original hold")
	}
}
func TestNodeChainExecutionEntryCandidateCancelDrain(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	inventory, address := entryInventory(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	f.engine.beforeDial = func(ctx context.Context, tag, addr string) (net.Conn, error, bool) {
		if addr == address {
			close(entered)
			<-release
			return nil, ctx.Err(), true
		}
		return nil, nil, false
	}
	entryRun(t, f, "server")
	p, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	o := &executionEntryOwner{nodeChainExecutionMeasurementTestOwner: &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}, capture: p.CaptureSHA256()}
	s := entryMeasurement(t, p, o)
	id := strings.Repeat("d", 32)
	if err := s.Start(id, p.plan.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(hopmeasure.ObservationTimeout):
		t.Fatal("candidate did not reach exact route")
	}
	s.Cancel(id)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Millisecond)
	err = s.CloseContext(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || !o.active.Load() {
		t.Fatal("unjoined original dial released native activity", err)
	}
	held := entryStatus(t, s)
	if held.Drained || len(held.Results) != 0 {
		t.Fatal("pending owned cleanup exposed candidate rows")
	}
	unblock()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if o.active.Load() || o.releases.Load() != 1 {
		t.Fatal("original canceled dial did not join")
	}
}
