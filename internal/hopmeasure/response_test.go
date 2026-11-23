package hopmeasure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestOrderedPrivateResponseSamplesFreshAuthenticatedEndpoints(t *testing.T) {
	for _, count := range []int{9, 16} {
		for _, fault := range []string{"", "wrong-final-proof", "replaced-owner"} {
			t.Run(fmt.Sprintf("%d/%s", count, fault), func(t *testing.T) {
				positions := make([]int, count-2)
				for i := range positions {
					positions[i] = i + 1
				}
				hops := importedNodesHops(count, positions...)
				engine := &testEngine{generation: "original-generation", servers: map[string]*httptest.Server{}, destinations: map[string]string{}, requests: map[string]int{}}
				for _, position := range []int{0, count - 1} {
					hop := &hops[position]
					hop.Token = fmt.Sprintf("original-node-%d-token", position)
					hop.Label = fmt.Sprintf("Cumulative path through node %d of %d", position+1, count)
					served := new(atomic.Int32)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodGet || r.URL.RequestURI() != "/health" || r.Header.Get("Authorization") != "Bearer "+hop.Token {
							t.Error("original native route did not send the authenticated private health request")
							http.Error(w, "denied", http.StatusForbidden)
							return
						}
						proof := hop.Proof
						if position == count-1 && served.Add(1) == 2 {
							switch fault {
							case "wrong-final-proof":
								proof = strings.Repeat("f", 64)
							case "replaced-owner":
								engine.mu.Lock()
								engine.generation = "different-generation"
								engine.mu.Unlock()
							}
						}
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":"router-vpn-private-agent-v1"}`, proof)
					}))
					t.Cleanup(server.Close)
					engine.servers[hop.Tag] = server
					engine.destinations[hop.Tag] = "10.77.0.1:8787"
				}
				service, err := NewOrderedImportedNodesContext(t.Context(), engine, hops)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := service.Close(); err != nil {
						t.Error(err)
					}
				})
				request := strings.Repeat("a", 32)
				samples := 2
				if count == 16 {
					samples = 3
				}
				if err := service.StartOrderedResponseContext(t.Context(), request, samples); err != nil {
					t.Fatal(err)
				}
				if err := service.Drain(request); err != nil {
					t.Fatal(err)
				}
				status, err := service.CompletedOrderedResponseContext(t.Context(), request, samples)
				if fault != "" {
					if err == nil || len(status.Results) != 0 {
						t.Fatal("wrong original owner or failed proof survived", status)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				ends := [2]Hop{hops[0], hops[count-1]}
				d, err := OrderedResponseLatencies(status, request, samples, ends)
				if err != nil || d[0].Samples != samples || d[1].Samples != samples {
					t.Fatal("lost fresh original response", d, err)
				}
				engine.mu.Lock()
				if len(engine.requests) != 2 || engine.requests[ends[0].Tag] != samples || engine.requests[ends[1].Tag] != samples {
					t.Error("wrong original requests", engine.requests)
				}
				engine.mu.Unlock()
				if _, err := OrderedResponseLatencies(status, request, samples+1, ends); err == nil {
					t.Fatal("borrowed sample count")
				}
				ends[1].ID = hops[count-2].ID
				if _, err := OrderedResponseLatencies(status, request, samples, ends); err == nil {
					t.Fatal("borrowed final position")
				}
				status.Results[1].Response.Endpoint = "https://public.invalid/"
				if _, err := OrderedResponseLatencies(status, request, samples, [2]Hop{hops[0], hops[count-1]}); err == nil {
					t.Fatal("borrowed public endpoint")
				}
			})
		}
	}
}
