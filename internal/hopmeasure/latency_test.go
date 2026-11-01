package hopmeasure

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func latencyStatus(t *testing.T, service *Service, id string) Status {
	t.Helper()
	if err := service.Drain(id); err != nil {
		t.Fatal(err)
	}
	var status Status
	if err := json.Unmarshal([]byte(service.StatusJSON()), &status); err != nil {
		t.Fatal(err)
	}
	if status.Request != id || !status.Complete || !status.Drained {
		t.Fatal("latency result did not belong to the fully joined request", status)
	}
	return status
}

func TestLatencyBenchmarkMakesFiftyRealHTTPSResponsesOnOnlyCapturedExit(t *testing.T) {
	fixture := newPublicFixture(t)
	service := fixture.service(t, publicHop("entry"), publicHop("exit"))
	id := strings.Repeat("a", 32)
	if err := service.StartLatency(id, "exit-node"); err != nil {
		t.Fatal(err)
	}
	status := latencyStatus(t, service, id)
	if status.Failure != "" || len(status.Results) != 1 {
		t.Fatal("captured exit did not return its single complete result", status)
	}
	result := status.Results[0]
	benchmark := result.Benchmark
	if !result.Ready || result.ID != "exit-node" || result.Kind != "public-path" || result.Role != "exit" || result.Idle != nil || result.Download != nil || result.Upload != nil ||
		benchmark == nil || benchmark.Schema != 1 || benchmark.Attempts != 50 || benchmark.Failed != 0 ||
		benchmark.Measurement != "routed-https-response-after-tls" || benchmark.Endpoint != "https://speed.cloudflare.com/__down?bytes=1" {
		t.Fatal("latency benchmark mixed direct/node/transfer semantics", result)
	}
	distribution := benchmark.Distribution
	if distribution == nil || distribution.Samples != 50 || distribution.Min <= 0 || distribution.Min > distribution.Median || distribution.Median > distribution.P90 || distribution.P90 > distribution.Max ||
		distribution.Average < distribution.Min || distribution.Average > distribution.Max || benchmark.TrimmedMean < distribution.Min || benchmark.TrimmedMean > distribution.Max || distribution.Jitter < 0 {
		t.Fatal("invalid measured 50-sample distribution", benchmark)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.tags) != 50 || fixture.downloaded.Load() != 50 || fixture.uploaded.Load() != 0 {
		t.Fatal("latency benchmark did not perform exactly fifty one-byte responses", fixture.tags, fixture.downloaded.Load(), fixture.uploaded.Load())
	}
	for _, tag := range fixture.tags {
		if tag != "custom-exit" {
			t.Fatal("latency benchmark borrowed another route", tag)
		}
	}
	if service.StartLatency(id, "exit-node") == nil {
		t.Fatal("latency request replay was accepted")
	}
}

func TestLatencyBenchmarkRejectsUnownedIDsAndPreservesTransferBounds(t *testing.T) {
	fixture := newPublicFixture(t)
	service := fixture.service(t, publicHop("entry"), publicHop("exit"))
	id := strings.Repeat("b", 32)
	for _, node := range []string{"", "entry-node", "different-node"} {
		if service.StartLatency(id, node) == nil {
			t.Fatal("unowned latency identity was admitted", node)
		}
	}
	if service.StartLatency("bad-id", "exit-node") == nil || service.Start(id, 0) == nil || service.Start(id, MaxBytes+1) == nil {
		t.Fatal("latency API relaxed the request/transfer bounds")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.tags) != 0 {
		t.Fatal("rejected latency request opened a native socket")
	}
}

func TestLatencyBenchmarkDiscardsPartialFailedAndStaleSamples(t *testing.T) {
	for _, mode := range []string{"redirect", "short", "untrusted-tls", "retired", "failed-fiftieth"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newPublicFixture(t)
			service := fixture.service(t, publicHop("exit"))
			if mode == "untrusted-tls" {
				service.publicTLS = nil
			} else if mode == "failed-fiftieth" {
				var attempts atomic.Int32
				fixture.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					if attempts.Add(1) == 50 {
						return nil, errors.New("last captured native dial failed")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", fixture.server.Listener.Addr().String())
				}
			} else {
				fixture.mode.Store(mode)
			}
			id := strings.Repeat("c", 32)
			if err := service.StartLatency(id, "exit-node"); err != nil {
				t.Fatal(err)
			}
			status := latencyStatus(t, service, id)
			if status.Failure == "" && (len(status.Results) != 1 || status.Results[0].Failure == "") {
				t.Fatal("failed or stale latency request pretended success", status)
			}
			for _, result := range status.Results {
				if result.Ready || result.Benchmark != nil || result.Idle != nil || result.Download != nil || result.Upload != nil {
					t.Fatal("incomplete latency request published usable statistics", result)
				}
			}
			if mode == "failed-fiftieth" && fixture.downloaded.Load() != 49 {
				t.Fatal("last-sample negative did not exchange the first forty-nine actual responses", fixture.downloaded.Load())
			}
		})
	}
}

type latencyBoundaryEngine struct {
	*publicFixture
	checks atomic.Int32
	failAt int32
}

func (engine *latencyBoundaryEngine) VerifyMeasurement(ctx context.Context) error {
	if ctx.Err() != nil || engine.checks.Add(1) == engine.failAt {
		return errors.New("native proof generation changed")
	}
	return nil
}

func TestLatencyBenchmarkRechecksNativeProofBeforeFinalPublication(t *testing.T) {
	for _, failedAt := range []int32{1, 2} {
		fixture := newPublicFixture(t)
		service := fixture.service(t, publicHop("exit"))
		engine := &latencyBoundaryEngine{publicFixture: fixture, failAt: failedAt}
		service.engine = engine
		id := strings.Repeat("d", 32)
		if err := service.StartLatency(id, "exit-node"); err != nil {
			t.Fatal(err)
		}
		status := latencyStatus(t, service, id)
		if status.Failure == "" || len(status.Results) != 0 || engine.checks.Load() != failedAt ||
			fixture.downloaded.Load() != int64((failedAt-1)*50) {
			t.Fatal("latency ignored fresh native proof boundary", failedAt, status, engine.checks.Load(), fixture.downloaded.Load())
		}
	}
}

type latencyScopeEngine struct {
	*publicFixture
	entered, release chan struct{}
	held             atomic.Bool
}

func (engine *latencyScopeEngine) BeginMeasurement() (func(), error) {
	if !engine.held.CompareAndSwap(false, true) {
		return nil, errors.New("measurement resources still held")
	}
	return func() { close(engine.entered); <-engine.release; engine.held.Store(false) }, nil
}

func TestLatencyBenchmarkCancellationKeepsScopeUntilActualDrain(t *testing.T) {
	fixture := newPublicFixture(t)
	service := fixture.service(t, publicHop("exit"))
	engine := &latencyScopeEngine{publicFixture: fixture, entered: make(chan struct{}), release: make(chan struct{})}
	service.engine = engine
	id := strings.Repeat("e", 32)
	if err := service.StartLatency(id, "exit-node"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-engine.entered:
	case <-time.After(3 * time.Second):
		close(engine.release)
		t.Fatal("latency worker never reached its real scope release")
	}
	if !engine.held.Load() || service.StartLatency(strings.Repeat("f", 32), "exit-node") == nil {
		close(engine.release)
		t.Fatal("completed status released native resources before worker drain")
	}
	service.Cancel(id)
	var pending Status
	if json.Unmarshal([]byte(service.StatusJSON()), &pending) != nil || pending.Drained || pending.Stage != "cancelled" || len(pending.Results) != 0 {
		close(engine.release)
		t.Fatal("cancel did not revoke the still-undrained result", pending)
	}
	close(engine.release)
	status := latencyStatus(t, service, id)
	if engine.held.Load() || status.Stage != "cancelled" || len(status.Results) != 0 {
		t.Fatal("latency cancellation did not preserve and join original resources", status)
	}
}
