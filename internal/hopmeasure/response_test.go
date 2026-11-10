package hopmeasure

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLiveResponseUsesThreeActualHTTPSResponsesAndSeparateResult(t *testing.T) {
	fixture := newPublicFixture(t)
	service := fixture.service(t, publicHop("entry"), publicHop("exit"))
	id := strings.Repeat("1", 32)
	if err := service.StartResponse(id, "exit-node"); err != nil {
		t.Fatal(err)
	}
	status := latencyStatus(t, service, id)
	if status.Failure != "" || len(status.Results) != 1 {
		t.Fatal("live response lost its original result", status)
	}
	r := status.Results[0]
	if !r.Ready || r.ID != "exit-node" || r.Role != "exit" || r.Kind != "public-path" || r.Failure != "" ||
		r.Idle != nil || r.Benchmark != nil || r.Download != nil || r.Upload != nil || r.Response == nil {
		t.Fatal("live response borrowed another measurement type", r)
	}
	v := r.Response
	if v.Schema != 1 || v.Measurement != "routed-https-response-after-tls" || v.Endpoint != "https://speed.cloudflare.com/__down?bytes=1" ||
		v.Attempts != 3 || v.Distribution == nil || v.Distribution.Samples != 3 || v.Distribution.Min <= 0 ||
		v.Distribution.Median < v.Distribution.Min || v.Distribution.Median > v.Distribution.Max {
		t.Fatal("live response did not retain its measured distribution", v)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.tags) != 3 || fixture.downloaded.Load() != 3 || fixture.uploaded.Load() != 0 {
		t.Fatal("live response did not perform exactly three one-byte HTTPS exchanges", fixture.tags)
	}
	for _, tag := range fixture.tags {
		if tag != "custom-exit" {
			t.Fatal("live response used another native route", tag)
		}
	}
	if service.StartResponse(id, "exit-node") == nil {
		t.Fatal("live response replay was admitted")
	}
}

func TestLiveResponseRejectsUnownedRoutesAndRequest(t *testing.T) {
	f := newPublicFixture(t)
	s := f.service(t, publicHop("entry"), publicHop("exit"))
	for _, node := range []string{"", "entry-node", "another-exit"} {
		if s.StartResponse(strings.Repeat("2", 32), node) == nil {
			t.Fatal("live response borrowed an unowned exit", node)
		}
	}
	if s.StartResponse("invalid", "exit-node") == nil || s.StartResponseContext(nil, strings.Repeat("2", 32), "exit-node") == nil {
		t.Fatal("live response accepted an invalid request or missing caller")
	}
	if len(f.tags) != 0 {
		t.Fatal("refused response opened a native socket")
	}
}

func TestLiveResponseDiscardsPartialFailureAndChangedProof(t *testing.T) {
	for _, mode := range []string{"redirect", "short", "untrusted-tls", "retired", "failed-third", "proof-before", "proof-after"} {
		t.Run(mode, func(t *testing.T) {
			f := newPublicFixture(t)
			s := f.service(t, publicHop("exit"))
			var boundary *latencyBoundaryEngine
			switch mode {
			case "untrusted-tls":
				s.publicTLS = nil
			case "failed-third":
				var calls atomic.Int32
				f.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					if calls.Add(1) == 3 {
						return nil, errors.New("private failure must never become a result")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", f.server.Listener.Addr().String())
				}
			case "proof-before", "proof-after":
				failure := int32(1)
				if mode == "proof-after" {
					failure = 2
				}
				boundary = &latencyBoundaryEngine{publicFixture: f, failAt: failure}
				s.engine = boundary
			default:
				f.mode.Store(mode)
			}
			id := strings.Repeat("3", 32)
			if err := s.StartResponse(id, "exit-node"); err != nil {
				t.Fatal(err)
			}
			status := latencyStatus(t, s, id)
			if status.Failure == "" && (len(status.Results) != 1 || status.Results[0].Failure == "") {
				t.Fatal("incomplete live response pretended success", status)
			}
			for _, r := range status.Results {
				if r.Ready || r.Response != nil || r.Benchmark != nil || r.Idle != nil || r.Download != nil || r.Upload != nil {
					t.Fatal("incomplete live response published usable statistics", r)
				}
			}
			if mode == "failed-third" && f.downloaded.Load() != 2 {
				t.Fatal("last-response failure did not exchange the first two actual responses")
			}
			if boundary != nil && (boundary.checks.Load() != boundary.failAt || f.downloaded.Load() != int64((boundary.failAt-1)*3)) {
				t.Fatal("live response skipped one of its native proof boundaries")
			}
		})
	}
}

func TestLiveResponseRetainsOriginalCallerAndBoundedWorker(t *testing.T) {
	f := newPublicFixture(t)
	s := f.service(t, publicHop("exit"))
	type key struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "original"))
	defer cancel()
	entered := make(chan struct{})
	f.dial = func(worker context.Context, _, _ string) (net.Conn, error) {
		deadline, ok := worker.Deadline()
		if worker.Value(key{}) != "original" || !ok || time.Until(deadline) > PathResponseTimeout {
			t.Error("live response lost its original caller or ten-second bound")
		}
		close(entered)
		<-worker.Done()
		return nil, worker.Err()
	}
	id := strings.Repeat("4", 32)
	if err := s.StartResponseContext(ctx, id, "exit-node"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("live response did not reach the original native dial")
	}
	cancel()
	status := latencyStatus(t, s, id)
	if status.Stage != "invalidated" || status.Failure == "" || len(status.Results) != 0 {
		t.Fatal("cancelled live response retained a result", status)
	}
}

func TestLiveResponseCancellationRetainsScopeThroughActualDrain(t *testing.T) {
	f := newPublicFixture(t)
	s := f.service(t, publicHop("exit"))
	engine := &latencyScopeEngine{publicFixture: f, entered: make(chan struct{}), release: make(chan struct{})}
	s.engine = engine
	id := strings.Repeat("5", 32)
	if err := s.StartResponse(id, "exit-node"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-engine.entered:
	case <-time.After(3 * time.Second):
		close(engine.release)
		t.Fatal("live response did not reach its original scope release")
	}
	if !engine.held.Load() || s.StartResponse(strings.Repeat("6", 32), "exit-node") == nil || s.StartLatency(strings.Repeat("7", 32), "exit-node") == nil {
		close(engine.release)
		t.Fatal("undrained live response admitted a competing measurement")
	}
	s.Cancel(id)
	close(engine.release)
	status := latencyStatus(t, s, id)
	if engine.held.Load() || status.Stage != "cancelled" || len(status.Results) != 0 {
		t.Fatal("live response cancellation lost its original cleanup owner", status)
	}
}
