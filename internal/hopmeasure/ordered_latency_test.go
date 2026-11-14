package hopmeasure

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
)

type orderedLatencyFixtureEngine struct {
	*orderedImportedMeasurementFixture
	held        atomic.Bool
	releases    atomic.Int32
	before      func(context.Context) error
	releaseHook func()
}

func (e *orderedLatencyFixtureEngine) IdentityContext(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return e.Identity(), nil
}
func (e *orderedLatencyFixtureEngine) VerifyMeasurement(ctx context.Context) error {
	if e.before != nil {
		return e.before(ctx)
	}
	return ctx.Err()
}
func (e *orderedLatencyFixtureEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.held.CompareAndSwap(false, true) {
		return nil, errors.New("original activity occupied")
	}
	hook := e.releaseHook
	return func() {
		if hook != nil {
			hook()
		}
		e.releases.Add(1)
		e.held.Store(false)
	}, nil
}
func orderedLatencyFixture(t *testing.T) (*OrderedLatencyService, *orderedLatencyFixtureEngine) {
	t.Helper()
	legacy, private := fixture(t)
	public := newPublicFixture(t)
	hops := orderedImportedHops()
	for _, position := range []int{0, 2} {
		old := legacy.hops[position/2]
		hops[position].API, hops[position].Token, hops[position].Proof = old.API, old.Token, old.Proof
	}
	engine := &orderedLatencyFixtureEngine{orderedImportedMeasurementFixture: &orderedImportedMeasurementFixture{private: private, public: public, hops: hops}}
	base, err := NewOrderedImportedMiddleContext(t.Context(), engine, hops)
	if err != nil {
		t.Fatal(err)
	}
	base.publicTLS = public.tls
	t.Cleanup(func() {
		if err := base.Close(); err != nil {
			t.Error(err)
		}
	})
	service, err := NewOrderedLatencyContext(t.Context(), base, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return service, engine
}
func orderedLatencyResult(t *testing.T, s *OrderedLatencyService, request string) Status {
	t.Helper()
	if err := s.Drain(request); err != nil {
		t.Fatal(err)
	}
	var result Status
	if err := json.Unmarshal([]byte(s.StatusJSON()), &result); err != nil {
		t.Fatal(err)
	}
	if result.Request != request || !result.Complete || !result.Drained {
		t.Fatal("original benchmark did not join", result)
	}
	return result
}
func TestOrderedLatencyFiftyOriginalResponsesOnEveryCapturedHop(t *testing.T) {
	service, engine := orderedLatencyFixture(t)
	for position, hop := range service.service.hops {
		request := fmt.Sprintf("%032x", position+1)
		if service.service.StartLatency(request, hop.ID) == nil {
			t.Fatal("ordered hop borrowed external-final latency authority")
		}
		if err := service.Start(request, hop.ID); err != nil {
			t.Fatal(err)
		}
		status := orderedLatencyResult(t, service, request)
		if status.Failure != "" || len(status.Results) != 1 {
			t.Fatal(status)
		}
		result := status.Results[0]
		benchmark := result.Benchmark
		if !result.Ready || result.ID != hop.ID || result.Role != hop.Role || result.Kind != hop.Kind || result.Idle != nil || result.Download != nil || result.Upload != nil || benchmark == nil || benchmark.Attempts != 50 || benchmark.Failed != 0 || benchmark.Distribution == nil || benchmark.Distribution.Samples != 50 {
			t.Fatal("ordered benchmark did not retain all fifty exact responses", result)
		}
		distribution := benchmark.Distribution
		if distribution.Min <= 0 || distribution.Min > distribution.Median || distribution.Median > distribution.P90 || distribution.P90 > distribution.Max || benchmark.TrimmedMean < distribution.Min || benchmark.TrimmedMean > distribution.Max {
			t.Fatal("invalid measured distribution", benchmark)
		}
		metric := "routed-private-response-including-connection"
		if position == 1 {
			metric = "routed-https-response-after-tls"
		}
		if benchmark.Measurement != metric || position != 1 && benchmark.Endpoint != "" {
			t.Fatal("private/public interval semantics changed", benchmark)
		}
		raw := service.SavedJSON(hop.ID)
		var receipt OrderedLatencyReceipt
		if json.Unmarshal([]byte(raw), &receipt) != nil || receipt.Schema != 1 || receipt.Position != position || receipt.NodeID != hop.ID || receipt.Request != request || receipt.SourceSHA256 != strings.Repeat("a", 64) || receipt.ConfigSHA256 != strings.Repeat("b", 64) || !nodeID.MatchString(receipt.GenerationSHA256) || receipt.MeasuredAt <= 0 {
			t.Fatal("complete receipt lost original capture", raw)
		}
		for _, secret := range []string{hop.Token, hop.API, engine.Identity()} {
			if secret != "" && strings.Contains(raw, secret) {
				t.Fatal("receipt exposed original private input")
			}
		}
		if service.Start(request, hop.ID) == nil {
			t.Fatal("completed request replayed")
		}
	}
	engine.private.mu.Lock()
	first, last := engine.private.requests["entry-wg"], engine.private.requests["proxy"]
	engine.private.mu.Unlock()
	engine.public.mu.Lock()
	publicCalls := len(engine.public.tags)
	engine.public.mu.Unlock()
	if first != 50 || last != 50 || publicCalls != 50 || engine.public.downloaded.Load() != 50 || engine.held.Load() || engine.releases.Load() != 3 {
		t.Fatal("fifty-sample work bypassed original routes or drain", first, last, publicCalls)
	}
}
func TestOrderedLatencyRetainsPreviousReceiptOnIncompleteStaleAndCancel(t *testing.T) {
	for _, fault := range []string{"last-sample", "tls", "source-generation", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			service, engine := orderedLatencyFixture(t)
			hop := service.service.hops[1]
			first := strings.Repeat("c", 32)
			if err := service.Start(first, hop.ID); err != nil {
				t.Fatal(err)
			}
			if status := orderedLatencyResult(t, service, first); len(status.Results) != 1 || !status.Results[0].Ready {
				t.Fatal(status)
			}
			saved := service.SavedJSON(hop.ID)
			before := engine.public.downloaded.Load()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch fault {
			case "last-sample":
				var attempts atomic.Int32
				engine.public.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					if attempts.Add(1) == 50 {
						return nil, errors.New("original fiftieth dial failed")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", engine.public.server.Listener.Addr().String())
				}
			case "tls":
				service.service.publicTLS = nil
			case "source-generation", "cancel":
				var observations atomic.Int32
				engine.before = func(ctx context.Context) error {
					if observations.Add(1) == 12 {
						if fault == "cancel" {
							cancel()
						} else {
							engine.private.mu.Lock()
							engine.private.generation = "changed-original-generation"
							engine.private.mu.Unlock()
						}
					}
					return ctx.Err()
				}
			}
			request := strings.Repeat("d", 32)
			if err := service.StartContext(ctx, request, hop.ID); err != nil {
				t.Fatal("control never entered original worker", err)
			}
			status := orderedLatencyResult(t, service, request)
			for _, result := range status.Results {
				if result.Ready || result.Benchmark != nil {
					t.Fatal("partial or stale benchmark published", result)
				}
			}
			if service.SavedJSON(hop.ID) != saved || engine.held.Load() {
				t.Fatal("failed worker replaced saved result or escaped drain")
			}
			if fault == "last-sample" && engine.public.downloaded.Load()-before != 49 {
				t.Fatal("last-sample control did not prove original first forty-nine responses")
			}
		})
	}
}
func TestOrderedLatencyRefusesForeignOwnerAndInventory(t *testing.T) {
	service, _ := orderedLatencyFixture(t)
	for _, id := range []string{"", "foreign", "custom-exit"} {
		if service.Start(strings.Repeat("e", 32), id) == nil {
			t.Fatal("foreign hop admitted")
		}
	}
	if service.Start("bad", service.service.hops[0].ID) == nil {
		t.Fatal("unbounded request identifier admitted")
	}
	if _, err := NewOrderedLatencyContext(t.Context(), service.service, strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("duplicate wrapper stole original owner")
	}
	copied := *service
	if copied.Start(strings.Repeat("e", 32), service.service.hops[0].ID) == nil || copied.Close() == nil || copied.SavedJSON(service.service.hops[0].ID) != "" {
		t.Fatal("copied owner borrowed original authority")
	}
	legacy, _ := fixture(t)
	if _, err := NewOrderedLatencyContext(t.Context(), legacy, strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("ordinary pair borrowed ordered benchmark")
	}
}

func TestOrderedLatencyCancelBeforeOriginalDrainPreservesSavedReceipt(t *testing.T) {
	service, engine := orderedLatencyFixture(t)
	hop := service.service.hops[1]
	first := strings.Repeat("1", 32)
	if err := service.Start(first, hop.ID); err != nil {
		t.Fatal(err)
	}
	orderedLatencyResult(t, service, first)
	saved := service.SavedJSON(hop.ID)
	if saved == "" {
		t.Fatal("initial complete receipt missing")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	engine.releaseHook = func() { close(entered); <-release }
	request := strings.Repeat("2", 32)
	if err := service.Start(request, hop.ID); err != nil {
		close(release)
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("original release boundary never entered")
	}
	var pending Status
	if json.Unmarshal([]byte(service.StatusJSON()), &pending) != nil || !pending.Complete || pending.Drained || !engine.held.Load() || service.SavedJSON(hop.ID) != saved {
		close(release)
		t.Fatal("undrained worker replaced previous receipt")
	}
	if service.Start(strings.Repeat("3", 32), hop.ID) == nil {
		close(release)
		t.Fatal("still-owned release allowed another benchmark")
	}
	service.Cancel(request)
	close(release)
	status := orderedLatencyResult(t, service, request)
	if status.Stage != "cancelled" || len(status.Results) != 0 || engine.held.Load() || service.SavedJSON(hop.ID) != saved {
		t.Fatal("cancelled original join replaced saved receipt", status)
	}
}

func TestOrderedLatencyCloseNeverCancelsReusedThroughputToken(t *testing.T) {
	facade, engine := orderedLatencyFixture(t)
	base := facade.service
	t.Cleanup(func() {
		if err := base.Close(); err != nil {
			t.Error(err)
		}
	})
	original := strings.Repeat("5", 32)
	hop := base.hops[0].ID
	if err := facade.Start(original, hop); err != nil {
		t.Fatal(err)
	}
	orderedLatencyResult(t, facade, original)
	previous := facade.SavedJSON(hop)
	// Advance the original service once, then deliberately reuse the facade's
	// old string ID. The original admission pointer/channel must distinguish it.
	other := strings.Repeat("6", 32)
	if err := base.startContext(t.Context(), other, func(context.Context) {}); err != nil {
		t.Fatal(err)
	}
	if err := base.Drain(other); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var revoked atomic.Bool
	if err := base.startContext(t.Context(), original, func(ctx context.Context) { close(entered); <-release; revoked.Store(ctx.Err() != nil) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("replacement throughput never entered")
	}
	facade.Cancel(original)
	if err := facade.Close(); err != nil {
		t.Fatal("facade tried to join unrelated throughput", err)
	}
	base.mu.Lock()
	closed, current, token := base.closed, base.state.Request, base.done
	base.mu.Unlock()
	if closed || current != original || !engine.held.Load() {
		t.Fatal("latency facade retired host throughput")
	}
	select {
	case <-token:
		t.Fatal("latency facade joined another throughput worker")
	default:
	}
	if facade.SavedJSON(hop) != previous {
		t.Fatal("facade close erased historical receipt")
	}
	var status Status
	if json.Unmarshal([]byte(facade.StatusJSON()), &status) != nil || len(status.Results) != 0 || status.Stage != "retired" {
		t.Fatal("retired facade exposed another worker's result")
	}
	unblock()
	if err := base.Drain(original); err != nil {
		t.Fatal(err)
	}
	if revoked.Load() || engine.held.Load() {
		t.Fatal("stale latency token cancelled replacement throughput")
	}
	// A new facade may borrow only after the previous facade's exact join.
	next, err := NewOrderedLatencyContext(t.Context(), base, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := next.Close(); err != nil {
			t.Error(err)
		}
	})
	request := strings.Repeat("7", 32)
	if err = next.Start(request, hop); err != nil {
		t.Fatal(err)
	}
	if result := orderedLatencyResult(t, next, request); len(result.Results) != 1 || !result.Results[0].Ready {
		t.Fatal("new borrowed facade lost original service", result)
	}
}

func TestOrderedLatencyFailedCloseRetainsOnlyOriginalBorrow(t *testing.T) {
	facade, engine := orderedLatencyFixture(t)
	base := facade.service
	t.Cleanup(func() {
		if err := base.Close(); err != nil {
			t.Error(err)
		}
	})
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	engine.releaseHook = func() { close(entered); <-release }
	request := strings.Repeat("8", 32)
	if err := facade.Start(request, base.hops[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original fifty release never entered")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Millisecond)
	err := facade.CloseContext(ctx)
	cancel()
	base.mu.Lock()
	retained, closed := base.orderedLatency == facade, base.closed
	base.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) || !retained || closed || !engine.held.Load() {
		t.Fatal("failed latency close released borrow or retired host", err)
	}
	if _, err := NewOrderedLatencyContext(t.Context(), base, strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("pending facade close admitted replacement")
	}
	unblock()
	if err := facade.Close(); err != nil {
		t.Fatal("original latency close could not retry", err)
	}
	engine.releaseHook = nil
	next := strings.Repeat("9", 32)
	if err := base.Start(next, 65536); err != nil {
		t.Fatal("retired latency facade closed host throughput", err)
	}
	base.Cancel(next)
	if err := base.Drain(next); err != nil {
		t.Fatal(err)
	}
	if engine.held.Load() {
		t.Fatal("host throughput lost original drain")
	}
}

func TestOrderedLatencyFailedHostValidationLeavesNoBorrow(t *testing.T) {
	previous, _ := orderedLatencyFixture(t)
	base := previous.service
	if err := previous.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := base.Close(); err != nil {
			t.Error(err)
		}
	})
	failure := errors.New("captured typed host changed")
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		called := false
		candidate, err := NewOrderedLatencyValidatedContext(ctx, base, strings.Repeat("a", 64), strings.Repeat("b", 64), func(call context.Context) error {
			called = true
			// Validation must not execute under the worker mutex.
			if !base.mu.TryLock() {
				t.Fatal("host validation held original service lock")
			}
			base.mu.Unlock()
			if expired {
				cancel()
				return nil
			}
			return failure
		})
		cancel()
		if !called || candidate != nil || err == nil {
			t.Fatal("failed host validation exposed facade")
		}
		base.mu.Lock()
		attached, closed := base.orderedLatency, base.closed
		base.mu.Unlock()
		if attached != nil || closed {
			t.Fatal("failed host validation stranded borrow or closed throughput")
		}
	}
	request := strings.Repeat("9", 32)
	if err := base.Start(request, 65536); err != nil {
		t.Fatal("failed host factory retired throughput", err)
	}
	base.Cancel(request)
	if err := base.Drain(request); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewOrderedLatencyValidatedContext(t.Context(), base, strings.Repeat("a", 64), strings.Repeat("b", 64), func(context.Context) error { return nil })
	if err != nil || fresh == nil {
		t.Fatal("failed host validation blocked fresh retry", err)
	}
	defer fresh.Close()
	request = strings.Repeat("8", 32)
	if err = fresh.Start(request, base.hops[0].ID); err != nil {
		t.Fatal(err)
	}
	result := orderedLatencyResult(t, fresh, request)
	if len(result.Results) != 1 || !result.Results[0].Ready || fresh.SavedJSON(base.hops[0].ID) == "" {
		t.Fatal("fresh host retry lost original fifty worker")
	}
}
