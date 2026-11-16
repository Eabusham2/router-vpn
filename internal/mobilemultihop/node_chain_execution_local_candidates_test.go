package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

// The original shared execution/Compare and fifty-dial service run here.
// entryTarget retains the existing explicit native-route double and real TCP
// listener. These fixtures do not establish encrypted/native/device acceptance.
func localCandidateFixture(t *testing.T, count, position int) (*nodeChainExecutionRuntimeFixture, *NodeChainExecutionCandidatePlan, *executionEntryOwner, string) {
	t.Helper()
	f := newNodeChainExecutionRuntimeFixtureFromSource(t, nodeChainExecutionFixtureSource(t, count, "", "auto"))
	entryRun(t, f, "compare-local")
	inventory, address := entryInventory(t)
	p, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), position, inventory)
	if err != nil {
		t.Fatal(err)
	}
	o := &executionEntryOwner{nodeChainExecutionMeasurementTestOwner: &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}, capture: p.CaptureSHA256()}
	return f, p, o, address
}

func TestNodeChainExecutionLocalCandidateFifty(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, position := range []int{1, count - 2} {
			t.Run(fmt.Sprintf("%d/%d", count, position), func(t *testing.T) {
				f, p, o, address := localCandidateFixture(t, count, position)
				f.engine.mu.Lock()
				opens, selections, epoch := f.engine.opens, len(f.engine.selections), f.engine.epoch
				f.engine.mu.Unlock()
				trial := f.runtime.active
				count := entryTarget(t, f, p, address)
				s := entryMeasurement(t, p, o)
				id := strings.Repeat("e", 32)
				if err := s.Start(id, p.plan.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				entryWait(t, s)
				if err := s.Drain(id); err != nil {
					t.Fatal(err)
				}
				result := entryStatus(t, s)
				if !result.Complete || !result.Drained || result.Failure != "" || len(result.Results) != 1 || !result.Results[0].Ready || result.Results[0].Benchmark == nil {
					t.Fatal("missing original Local interior result", result)
				}
				benchmark := result.Results[0].Benchmark
				if benchmark.Attempts != 50 || benchmark.Failed != 0 || benchmark.Distribution == nil || benchmark.Distribution.Samples != 50 || count.Load() != 50 {
					t.Fatal("Local interior did not dial fifty original targets", benchmark, count.Load())
				}
				f.engine.mu.Lock()
				unchanged := f.engine.opens == opens && len(f.engine.selections) == selections && f.engine.epoch == epoch
				f.engine.mu.Unlock()
				if !unchanged || f.runtime.active != trial || trial != p.trial || trial.execution != "local" || p.native != f.engine || o.active.Load() || o.releases.Load() != 1 {
					t.Fatal("Local candidate reran execution or lost original activity")
				}
				var m map[string]any
				if json.Unmarshal([]byte(p.Metadata()), &m) != nil || m["prefix_position"] != float64(position) || m["requested_execution"] != "auto" || m["execution"] != "local" || m["selection_epoch"] != float64(epoch) || m["preparation_source_sha256"] != p.preparation.SourceSHA256() || m["preparation_config_sha256"] != p.preparation.ConfigSHA256() || m["source_sha256"] != p.projection.SourceSHA256() || m["config_sha256"] != p.projection.ConfigSHA256() {
					t.Fatal("Local candidate relabeled preparation/projection or selected choice")
				}
			})
		}
	}
}

func TestNodeChainExecutionLocalCandidateScope(t *testing.T) {
	for _, selected := range []string{"server", "compare-server"} {
		t.Run(selected, func(t *testing.T) {
			f, _, _, _ := entryFixture(t, selected)
			inventory, _ := entryInventory(t)
			if p, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), 1, inventory); err == nil || p != nil {
				t.Fatal("Server winner acquired Local interior authority")
			}
		})
	}
	f, p, _, _ := localCandidateFixture(t, 4, 1)
	inventory, _ := entryInventory(t)
	for _, position := range []int{-1, 0, 3, 4, 8} {
		t.Run(fmt.Sprintf("position-%d", position), func(t *testing.T) {
			if got, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), position, inventory); err == nil || got != nil {
				t.Fatal("Local interior admitted entry/final/foreign position")
			}
		})
	}
	if got, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 1, inventory); err == nil || got != nil {
		t.Fatal("entry constructor widened")
	}
	entry, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	copy := *p
	copy.self = &copy
	copy.localInterior = false
	if copy.Metadata() != "" || copy.validate() == nil || entry.CaptureSHA256() == p.CaptureSHA256() {
		t.Fatal("Local and entry sealed admission collapsed")
	}
	for _, fault := range []string{"nil-context", "cancelled", "copied-plan", "copied-runtime", "inventory", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			ctx := t.Context()
			r := f.runtime
			raw := inventory
			switch fault {
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "copied-plan":
				clone := *p
				if clone.Metadata() != "" || clone.validate() == nil {
					t.Fatal("copied Local plan gained authority")
				}
				return
			case "copied-runtime":
				r = &NodeChainExecutionRuntime{projection: f.runtime.projection, engine: f.runtime.engine, identity: p.identity, active: p.trial, lifetime: f.runtime.lifetime}
			case "inventory":
				raw = `{"schema":1,"revision":"changed","inputs":["foreign"]}`
			case "duplicate":
				var record NodeChainCandidateInventory
				_ = json.Unmarshal([]byte(raw), &record)
				record.Inputs = append(record.Inputs, record.Inputs[0])
				raw = startJSON(t, record)
			}
			if got, err := r.NewLocalCandidatePlanContext(ctx, 1, raw); err == nil || got != nil {
				t.Fatal("Local interior source refusal missing", fault)
			}
		})
	}
}

func TestNodeChainExecutionLocalCandidateTypedBoundary(t *testing.T) {
	for _, family := range []string{"imported", "socks", "connect", "openvpn"} {
		for _, count := range []int{4, 8} {
			t.Run(fmt.Sprintf("%s/%d", family, count), func(t *testing.T) {
				var f *nodeChainExecutionRuntimeFixture
				switch family {
				case "imported":
					f = newNodeChainExecutionRuntimeFixtureFromSource(t, nodeChainImportedPrefixExecutionSource(t, count-2, "wg", "auto"))
				case "socks":
					f = newNodeChainExecutionRuntimeFixtureFromSource(t, socksExecutionPrefixFixtureSource(t, count, "auto"))
				case "connect":
					f = newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionPrefixFixtureSource(t, count, "auto"))
				case "openvpn":
					_, prep, source := openVPNExecutionFixture(t, count-2, "wg", "tcp", "", "auto", "")
					f = newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, prep)
				}
				entryRun(t, f, "compare-local")
				inventory, _ := entryInventory(t)
				p, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), count-3, inventory)
				if err != nil {
					t.Fatal("original typed packet interior refused", err)
				}
				if p.plan.chain != f.runtime.projection.policy.local || p.preparation != f.runtime.projection.preparation || p.projection != f.runtime.projection || p.native != f.engine {
					t.Fatal("typed Local candidate substituted ordinary source")
				}
				o := &executionEntryOwner{nodeChainExecutionMeasurementTestOwner: &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}, capture: p.CaptureSHA256()}
				_ = entryMeasurement(t, p, o)
				if o.calls.Load() == 0 {
					t.Fatal("typed Local candidate skipped original catalog")
				}
				for _, position := range []int{count - 2, count - 1} {
					if got, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), position, inventory); err == nil || got != nil {
						t.Fatal("typed Local candidate crossed imported or final boundary", position)
					}
				}
			})
		}
	}
}

func TestNodeChainExecutionLocalCandidateOriginalAuthority(t *testing.T) {
	for _, fault := range []string{"owner", "native", "trial", "epoch", "projection", "preparation", "catalog", "retired", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			f, p, o, _ := localCandidateFixture(t, 4, 1)
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
			case "retired":
				f.runtime.retired.Store(true)
				restore = func() { f.runtime.retired.Store(false) }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer restore()
			if s, err := p.NewMeasurementContext(ctx, o); err == nil || s != nil || o.active.Load() {
				t.Fatal("foreign original Local owner acquired candidate", fault)
			}
		})
	}
}

func TestNodeChainExecutionLocalCandidateDialScope(t *testing.T) {
	f, p, o, address := localCandidateFixture(t, 4, 1)
	_ = entryTarget(t, f, p, address)
	s := entryMeasurement(t, p, o)
	// Exercise the real scope/dial guards, not a refusal caused by missing work.
	s.engine.base.mu.Lock()
	s.engine.base.nextID = strings.Repeat("1", 32)
	s.engine.base.mu.Unlock()
	finish, err := s.engine.BeginMeasurementContext(t.Context())
	if err != nil || finish == nil {
		t.Fatal("original Local scope", err)
	}
	defer finish()
	connection, err := s.engine.Dial(t.Context(), p.plan.prefix.Tag, address)
	if err != nil || connection == nil {
		t.Fatal("original Local dial", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	var escaped atomic.Int32
	f.engine.beforeDial = func(_ context.Context, tag, addr string) (net.Conn, error, bool) {
		if addr == address || addr == "192.0.2.244:443" {
			escaped.Add(1)
			return nil, errors.New("unexpected native candidate dial"), true
		}
		return nil, nil, false
	}
	for _, fault := range []string{"entry-tag", "other-prefix", "foreign-target"} {
		t.Run(fault, func(t *testing.T) {
			tag, addr := p.plan.prefix.Tag, address
			switch fault {
			case "entry-tag":
				tag = p.plan.chain.proofs[0].Tag
			case "other-prefix":
				tag = p.plan.chain.proofs[2].Tag
			case "foreign-target":
				addr = "192.0.2.244:443"
			}
			if conn, err := s.engine.Dial(t.Context(), tag, addr); err == nil || conn != nil || escaped.Load() != 0 {
				t.Fatal("Local candidate dial escaped captured tag/target")
			}
		})
	}
}

func TestNodeChainExecutionLocalCandidateHeldClose(t *testing.T) {
	f, p, o, address := localCandidateFixture(t, 4, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	// Register after entryMeasurement so its cleanup cannot precede unblock.
	s := entryMeasurement(t, p, o)
	t.Cleanup(unblock)
	f.engine.beforeDial = func(ctx context.Context, tag, addr string) (net.Conn, error, bool) {
		if addr == address {
			if tag != p.plan.prefix.Tag {
				return nil, errors.New("wrong original interior"), true
			}
			close(entered)
			<-release
			return nil, ctx.Err(), true
		}
		return nil, nil, false
	}
	id := strings.Repeat("f", 32)
	if err := s.Start(id, p.plan.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(hopmeasure.ObservationTimeout):
		t.Fatal("Local candidate did not reach original interior")
	}
	s.Cancel(id)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Millisecond)
	err := s.CloseContext(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || !o.active.Load() {
		t.Fatal("held Local dial released original activity", err)
	}
	held := entryStatus(t, s)
	if held.Drained || len(held.Results) != 0 {
		t.Fatal("held Local cleanup published rows")
	}
	releaseOther, otherErr := o.BeginMeasurementContext(t.Context())
	if otherErr == nil {
		if releaseOther != nil {
			releaseOther()
		}
		t.Fatal("held Local cleanup allowed replacement activity")
	}
	unblock()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if o.active.Load() || o.releases.Load() != 1 {
		t.Fatal("Local original callback did not join")
	}
}
