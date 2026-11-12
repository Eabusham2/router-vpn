package hopmeasure

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
)

type candidateEngineFixture struct {
	t        *testing.T
	prefix   CandidatePrefix
	target   CandidateTarget
	current  atomic.Bool
	held     atomic.Bool
	dials    atomic.Int32
	closed   atomic.Int32
	released atomic.Int32
	failAt   int32
	broken   func(context.Context) (net.Conn, error)
}

func (e *candidateEngineFixture) Identity() string { panic("detached identity observation") }
func (e *candidateEngineFixture) IdentityContext(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if !e.current.Load() {
		return "", ErrStale
	}
	return "original-native-owner-and-catalog", nil
}
func (e *candidateEngineFixture) VerifyMeasurement(ctx context.Context) error {
	_, err := e.IdentityContext(ctx)
	return err
}
func (e *candidateEngineFixture) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := e.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	if !e.held.CompareAndSwap(false, true) {
		return nil, errors.New("original MTU hold occupied")
	}
	return func() { e.released.Add(1); e.held.Store(false) }, nil
}
func (e *candidateEngineFixture) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if tag != e.prefix.Tag || address != e.target.Address || !e.held.Load() {
		e.t.Error("candidate substituted its original prefix, target or MTU ownership")
		return nil, ErrStale
	}
	count := e.dials.Add(1)
	if e.broken != nil {
		return e.broken(ctx)
	}
	if count == e.failAt {
		return nil, errors.New("private candidate credential must not appear in status")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return connection, err
	}
	return &candidateCloseFixture{Conn: connection, count: &e.closed}, nil
}

type candidateCloseFixture struct {
	net.Conn
	count            *atomic.Int32
	once             sync.Once
	entered, release chan struct{}
}

func (c *candidateCloseFixture) Close() error {
	c.once.Do(func() {
		if c.entered != nil {
			close(c.entered)
			<-c.release
		}
		c.count.Add(1)
	})
	return c.Conn.Close()
}

func newCandidateFixture(t *testing.T) (*CandidateService, *candidateEngineFixture) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	engine := &candidateEngineFixture{t: t,
		prefix: CandidatePrefix{Position: 0, ID: "original-first", Tag: "routervpn-chain-0-aaaaaaaaaaaa-node-bbbbbbbbbbbb", CaptureSHA256: strings.Repeat("c", 64)},
		target: CandidateTarget{ID: "candidate", SourceSHA256: strings.Repeat("d", 64), Address: listener.Addr().String()},
	}
	engine.current.Store(true)
	targets := []CandidateTarget{engine.target}
	service, err := NewPrefixCandidatesContext(context.Background(), engine, engine.prefix, targets)
	if err != nil {
		t.Fatal(err)
	}
	targets[0].Address = "127.0.0.1:1" // The constructor must own an independent inventory.
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return service, engine
}

func candidateStatus(t *testing.T, service *CandidateService) CandidateStatus {
	t.Helper()
	var status CandidateStatus
	if err := json.Unmarshal([]byte(service.StatusJSON()), &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestPrefixCandidateMeasuresFiftyOriginalTCPConnections(t *testing.T) {
	service, engine := newCandidateFixture(t)
	request := strings.Repeat("a", 32)
	if err := service.Start(request, engine.target.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Drain(request); err != nil {
		t.Fatal(err)
	}
	status := candidateStatus(t, service)
	if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 ||
		engine.dials.Load() != 50 || engine.closed.Load() != 50 || engine.released.Load() != 1 || engine.held.Load() {
		t.Fatal("original connections did not complete and drain", status, engine.dials.Load(), engine.closed.Load())
	}
	result := status.Results[0]
	if !result.Ready || result.ID != engine.target.ID || result.Kind != "tcp-connect" || result.Benchmark == nil ||
		result.Benchmark.Measurement != "routed-tcp-connect" || result.Benchmark.Attempts != 50 ||
		result.Benchmark.Distribution.Samples != 50 || result.Benchmark.TrimmedMean <= 0 || result.Benchmark.Endpoint != "" ||
		status.CaptureSHA256 != engine.prefix.CaptureSHA256 || status.CandidateSourceSHA256 != engine.target.SourceSHA256 ||
		status.ExpiresAt-status.MeasuredAt != CandidateReceiptLifetime.Milliseconds() {
		t.Fatal("wrong candidate receipt", status)
	}
	if strings.Contains(service.StatusJSON(), engine.target.Address) || strings.Contains(service.StatusJSON(), "icmp") {
		t.Fatal("candidate exposed private address or claimed ICMP")
	}
	if next := candidateStatus(t, service); next.MeasuredAt != status.MeasuredAt || next.ExpiresAt != status.ExpiresAt {
		t.Fatal("status read extended candidate lifetime")
	}
	service.service.mu.Lock()
	service.completion.measured = time.Now().Add(-CandidateReceiptLifetime - time.Second)
	service.service.mu.Unlock()
	if expired := candidateStatus(t, service); expired.Stage != "expired" || len(expired.Results) != 0 {
		t.Fatal("expired candidate retained a score", expired)
	}
}

func TestPrefixCandidateFailureNeverScoresSuccessfulSubset(t *testing.T) {
	service, engine := newCandidateFixture(t)
	engine.failAt = 10
	request := strings.Repeat("b", 32)
	if err := service.Start(request, engine.target.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Drain(request); err != nil {
		t.Fatal(err)
	}
	status := candidateStatus(t, service)
	if !status.Complete || !status.Drained || len(status.Results) != 1 || status.Results[0].Ready ||
		status.Results[0].Benchmark != nil || engine.dials.Load() != 10 || engine.closed.Load() != 9 || engine.held.Load() {
		t.Fatal("failed candidate acquired a partial or zero score", status)
	}
	if strings.Contains(service.StatusJSON(), "private candidate credential") {
		t.Fatal("native error leaked")
	}
	if err := service.Start(strings.Repeat("c", 32), "uncaptured"); err == nil {
		t.Fatal("foreign candidate admitted")
	}
}

func TestPrefixCandidateCancelRetainsLateDialAndMTUOwner(t *testing.T) {
	service, engine := newCandidateFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	engine.broken = func(ctx context.Context) (net.Conn, error) {
		close(entered)
		<-release
		one, two := net.Pipe()
		_ = two.Close()
		return &candidateCloseFixture{Conn: one, count: &engine.closed}, ctx.Err()
	}
	request := strings.Repeat("d", 32)
	if err := service.Start(request, engine.target.ID); err != nil {
		t.Fatal(err)
	}
	<-entered
	service.Cancel(request)
	status := candidateStatus(t, service)
	if status.Drained || len(status.Results) != 0 || !engine.held.Load() {
		t.Fatal("cancel certified an undrained candidate", status)
	}
	if err := service.Start(strings.Repeat("e", 32), engine.target.ID); err == nil {
		t.Fatal("replacement borrowed late worker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := service.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) || !engine.held.Load() {
		t.Fatal("late dial released original activity", err)
	}
	close(release)
	if err := service.Drain(request); err != nil {
		t.Fatal(err)
	}
	if engine.held.Load() || engine.closed.Load() != 1 || engine.released.Load() != 1 {
		t.Fatal("late original connection was not joined")
	}
}

func TestPrefixCandidateCatalogChangeInvalidatesBlockedClose(t *testing.T) {
	service, engine := newCandidateFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	engine.broken = func(context.Context) (net.Conn, error) {
		one, two := net.Pipe()
		_ = two.Close()
		return &candidateCloseFixture{Conn: one, count: &engine.closed, entered: entered, release: release}, nil
	}
	request := strings.Repeat("f", 32)
	if err := service.Start(request, engine.target.ID); err != nil {
		t.Fatal(err)
	}
	<-entered
	engine.current.Store(false)
	status := candidateStatus(t, service)
	if status.Drained || len(status.Results) != 0 || !engine.held.Load() {
		t.Fatal("stale catalog escaped pending native close", status)
	}
	close(release)
	if err := service.Drain(request); err != nil {
		t.Fatal(err)
	}
	if status := candidateStatus(t, service); !status.Drained || len(status.Results) != 0 || status.Stage != "invalidated" {
		t.Fatal(status)
	}
	if engine.closed.Load() != 1 || engine.released.Load() != 1 {
		t.Fatal("original cleanup lost")
	}
}

func TestPrefixCandidateConstructorRejectsForgedScope(t *testing.T) {
	_, engine := newCandidateFixture(t)
	for _, mutate := range []func(*CandidatePrefix, *[]CandidateTarget){
		func(p *CandidatePrefix, _ *[]CandidateTarget) { p.Position = 1 },
		func(p *CandidatePrefix, _ *[]CandidateTarget) { p.Tag = "proxy" },
		func(p *CandidatePrefix, _ *[]CandidateTarget) { p.CaptureSHA256 = "foreign" },
		func(_ *CandidatePrefix, v *[]CandidateTarget) { (*v)[0].Address = "example.org:443" },
		func(_ *CandidatePrefix, v *[]CandidateTarget) { (*v)[0].Address = "127.0.0.1:0" },
		func(_ *CandidatePrefix, v *[]CandidateTarget) { (*v)[0].Address = "127.0.0.1:0443" },
		func(_ *CandidatePrefix, v *[]CandidateTarget) { (*v)[0].SourceSHA256 = "uncaptured" },
		func(_ *CandidatePrefix, v *[]CandidateTarget) { *v = append(*v, (*v)[0]) },
		func(_ *CandidatePrefix, v *[]CandidateTarget) { *v = nil },
	} {
		prefix, targets := engine.prefix, []CandidateTarget{engine.target}
		mutate(&prefix, &targets)
		if _, err := NewPrefixCandidatesContext(context.Background(), engine, prefix, targets); err == nil {
			t.Fatal("forged prefix/candidate inventory admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewPrefixCandidatesContext(ctx, engine, engine.prefix, []CandidateTarget{engine.target}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
