package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestDNSBenchmarkRanksOnlyResponsiveSamplesAndComputesEvenMedian(t *testing.T) {
	candidates := []dnsCandidate{{"partial", "1.1.1.1"}, {"fast", "2606:4700:4700::1111"}, {"dead", "9.9.9.9"}, {"zero", "8.8.8.8"}}
	var mu sync.Mutex
	calls := make(map[string][]uint16)
	probe := func(ctx context.Context, address string, qtype uint16) (time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		calls[address] = append(calls[address], qtype)
		switch address {
		case "1.1.1.1":
			values := []time.Duration{100, 10, 30, 20, 0}
			value := values[len(calls[address])-1]
			if value == 0 {
				return time.Second, errors.New("failed response")
			}
			return value * time.Millisecond, nil
		case "2606:4700:4700::1111":
			return 2 * time.Millisecond, nil
		case "8.8.8.8":
			return 0, nil
		default:
			return 0, errors.New("no DNS response")
		}
	}
	results, err := measureDNSCandidates(context.Background(), candidates, probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(candidates) || results[0].LatencyMs != 25 || !results[0].Working || results[1].Family != "ipv6" || results[2].Working || results[3].Working {
		t.Fatalf("incorrect DNS result attribution: %+v", results)
	}
	if winner := measuredDNSWinner(results); winner.Address != candidates[1].Address || !winner.Working || winner.LatencyMs != 2 {
		t.Fatalf("wrong measured winner: %+v", winner)
	}
	for _, candidate := range candidates {
		got := calls[candidate.Address]
		if len(got) != 5 || got[0] != 1 || got[1] != 28 || got[2] != 1 || got[3] != 28 || got[4] != 1 {
			t.Fatalf("lost five A/AAAA samples for %s: %v", candidate.Address, got)
		}
	}
}

func TestDNSBenchmarkCancellationBoundsAndJoinsAllWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, dnsBenchmarkWorkers)
	var active, total atomic.Int32
	probe := func(ctx context.Context, _ string, _ uint16) (time.Duration, error) {
		if n := active.Add(1); n > dnsBenchmarkWorkers {
			t.Errorf("unbounded simultaneous probes: %d", n)
		}
		defer active.Add(-1)
		total.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		results, err := measureDNSCandidates(ctx, dnsCandidates, probe)
		if results != nil {
			t.Error("cancelled benchmark returned partial rankings")
		}
		done <- err
	}()
	for i := 0; i < dnsBenchmarkWorkers; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("bounded workers did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled benchmark did not return")
	}
	if active.Load() != 0 || total.Load() != dnsBenchmarkWorkers {
		t.Fatalf("workers not joined or new queries started: active=%d total=%d", active.Load(), total.Load())
	}
	if results, err := measureDNSCandidates(ctx, dnsCandidates, probe); results != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled benchmark: results=%v err=%v", results, err)
	}
	if total.Load() != dnsBenchmarkWorkers {
		t.Fatal("pre-cancelled request issued more DNS queries")
	}
}

func dnsBenchmarkTestServer() *server {
	_, network, _ := net.ParseCIDR("10.77.0.0/24")
	return &server{cfg: cfg{Token: "test-token"}, nets: []*net.IPNet{network}}
}

func dnsBenchmarkRequest(ctx context.Context) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/dns/benchmark", nil).WithContext(ctx)
	r.RemoteAddr = "10.77.0.2:40000"
	r.Header.Set("Authorization", "Bearer test-token")
	return r
}

func TestDNSBenchmarkHandlerPreservesAuthCancellationAndExclusiveOwnership(t *testing.T) {
	for _, scenario := range []string{"method", "token", "source", "cancelled", "busy", "working"} {
		t.Run(scenario, func(t *testing.T) {
			s := dnsBenchmarkTestServer()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := dnsBenchmarkRequest(ctx)
			want := http.StatusOK
			switch scenario {
			case "method":
				r.Method = http.MethodGet
				want = http.StatusMethodNotAllowed
			case "token":
				r.Header.Set("Authorization", "Bearer wrong")
				want = http.StatusForbidden
			case "source":
				r.RemoteAddr = "192.168.50.2:40000"
				want = http.StatusForbidden
			case "cancelled":
				cancel()
				want = http.StatusRequestTimeout
			case "busy":
				s.dnsMu.Lock()
				defer s.dnsMu.Unlock()
				want = http.StatusConflict
			}
			var calls atomic.Int32
			w := httptest.NewRecorder()
			s.serveDNSBenchmark(w, r, []dnsCandidate{{"test", "1.1.1.1"}}, func(context.Context, string, uint16) (time.Duration, error) {
				calls.Add(1)
				return time.Millisecond, nil
			})
			if w.Code != want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
			}
			if scenario == "working" {
				if calls.Load() != 5 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("working benchmark did not run five samples with no-store")
				}
			} else if calls.Load() != 0 {
				t.Fatal("rejected request started DNS probes")
			}
		})
	}
}

func TestDNSBenchmarkNoResponsesDoesNotInventFallbackWinner(t *testing.T) {
	s := dnsBenchmarkTestServer()
	w := httptest.NewRecorder()
	s.serveDNSBenchmark(w, dnsBenchmarkRequest(context.Background()), dnsCandidates, func(context.Context, string, uint16) (time.Duration, error) { return 0, errors.New("no response") })
	var payload struct {
		Winner  common.DNSBenchmarkResult   `json:"winner"`
		Results []common.DNSBenchmarkResult `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || w.Code != 200 {
		t.Fatalf("status=%d body=%s err=%v", w.Code, w.Body.String(), err)
	}
	if payload.Winner.Address != "" || payload.Winner.Working || len(payload.Results) != len(dnsCandidates) {
		t.Fatalf("unmeasured winner or missing failures: %+v", payload)
	}
	for _, result := range payload.Results {
		if result.Working || result.LatencyMs != 0 {
			t.Fatalf("invented successful sample: %+v", result)
		}
	}
}

func TestDNSBenchmarkCallerDeadlineReleasesSlotAndDiscardsPartialResults(t *testing.T) {
	s := dnsBenchmarkTestServer()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var active atomic.Int32
	w := httptest.NewRecorder()
	s.serveDNSBenchmark(w, dnsBenchmarkRequest(ctx), dnsCandidates, func(ctx context.Context, _ string, _ uint16) (time.Duration, error) {
		active.Add(1)
		defer active.Add(-1)
		<-ctx.Done()
		return time.Millisecond, nil
	})
	if w.Code != http.StatusRequestTimeout || active.Load() != 0 {
		t.Fatalf("status=%d active=%d", w.Code, active.Load())
	}
	if !s.dnsMu.TryLock() {
		t.Fatal("cancelled benchmark retained its slot")
	}
	s.dnsMu.Unlock()
	if dnsBenchmarkTimeout >= 45*time.Second || dnsBenchmarkWorkers != 4 {
		t.Fatal("request budget no longer fits native HTTP timeout")
	}
}
