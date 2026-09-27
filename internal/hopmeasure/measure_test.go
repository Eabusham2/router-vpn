package hopmeasure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type testEngine struct {
	mu           sync.Mutex
	generation   string
	bad          map[string]string
	servers      map[string]*httptest.Server
	destinations map[string]string
	requests     map[string]int
	errors       []string
}

func (e *testEngine) Identity() string { e.mu.Lock(); defer e.mu.Unlock(); return e.generation }
func (e *testEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	e.mu.Lock()
	server := e.servers[tag]
	wanted := e.destinations[tag]
	e.requests[tag]++
	e.mu.Unlock()
	if server == nil || address != wanted {
		return nil, fmt.Errorf("unexpected native dial tag/destination")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
}
func fixture(t *testing.T) (*Service, *testEngine) {
	t.Helper()
	e := &testEngine{generation: "generation-one:local", bad: map[string]string{}, servers: map[string]*httptest.Server{}, requests: map[string]int{}, destinations: map[string]string{"entry-wg": "10.77.0.1:8787", "proxy": "10.88.0.1:8787"}}
	hops := []Hop{{"one", "entry", "entry-wg", "http://10.77.0.1:8787", "token-one", strings.Repeat("a", 64)}, {"two", "exit", "proxy", "http://10.88.0.1:8787", "token-two", strings.Repeat("b", 64)}}
	for _, hop := range hops {
		h := hop
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.mu.Lock()
			bad := e.bad[h.Tag]
			if r.Header.Get("Authorization") != "Bearer "+h.Token {
				e.errors = append(e.errors, "wrong node token")
			}
			e.mu.Unlock()
			if bad == "hang" {
				<-r.Context().Done()
				return
			}
			if bad == "redirect" {
				http.Redirect(w, r, "http://public.invalid/", 302)
				return
			}
			if bad == "compress" {
				w.Header().Set("Content-Encoding", "gzip")
			}
			switch r.URL.Path {
			case "/health":
				time.Sleep(2 * time.Millisecond)
				proof := h.Proof
				if bad == "identity" {
					proof = strings.Repeat("c", 64)
				}
				if bad == "duplicate" {
					fmt.Fprintf(w, `{"ok":true,"node_id":"%s","node_id":"%s","proof":"router-vpn-private-agent-v1"}`, h.Proof, h.Proof)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": proof, "proof": "router-vpn-private-agent-v1"})
			case "/api/benchmark/download":
				n := 65536
				fmt.Sscanf(r.URL.Query().Get("bytes"), "%d", &n)
				w.Header().Set("Content-Length", fmt.Sprint(n))
				w.Header().Set("X-Routervpn-Benchmark", "download-v1")
				w.Header().Set("X-Routervpn-Benchmark-Bytes", fmt.Sprint(n))
				if bad == "truncate" {
					io.WriteString(w, "short")
					return
				}
				if bad == "framing" {
					w.Header().Set("X-Routervpn-Benchmark-Bytes", "0")
				}
				chunk := make([]byte, 16384)
				for sent := 0; sent < n; sent += len(chunk) {
					_, _ = w.Write(chunk)
					w.(http.Flusher).Flush()
					time.Sleep(25 * time.Millisecond)
				}
			case "/api/benchmark/upload":
				n, _ := io.Copy(io.Discard, r.Body)
				time.Sleep(90 * time.Millisecond)
				if bad == "ack" {
					n--
				}
				json.NewEncoder(w).Encode(map[string]any{"ok": true, "bytes": n, "direction": "upload", "server_receive_ms": 1, "peer": "10.77.0.2", "proof": "authenticated tunnel-peer private throughput sink"})
			default:
				t.Errorf("unexpected private API %s", r.URL.Path)
				w.WriteHeader(404)
			}
		}))
		e.servers[h.Tag] = server
		t.Cleanup(server.Close)
	}
	s, err := New(e, hops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, e
}
func status(t *testing.T, s *Service) Status {
	t.Helper()
	var v Status
	if err := json.Unmarshal([]byte(s.StatusJSON()), &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func wait(t *testing.T, s *Service) Status {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		v := status(t, s)
		if v.Complete {
			return v
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("test did not terminate")
	return Status{}
}
func TestMeasuresActualSeparateHopBytesAndLatency(t *testing.T) {
	s, e := fixture(t)
	id := strings.Repeat("1", 32)
	if err := s.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	v := wait(t, s)
	if v.Request != id || len(v.Results) != 2 || v.Failure != "" {
		t.Fatal(v)
	}
	for i, r := range v.Results {
		if !r.Ready || r.ID != s.hops[i].ID || r.Idle.Samples != 6 || r.Download.Bytes != 65536 || r.Upload.Bytes != 65536 {
			t.Fatal(r)
		}
		for _, transfer := range []*Transfer{r.Download, r.Upload} {
			if transfer.Mbps != float64(transfer.Bytes)*8/transfer.Seconds/1e6 {
				t.Fatal("fabricated transfer rate")
			}
			if transfer.Loaded == nil || transfer.Loaded.Samples < 1 || transfer.Bufferbloat == nil {
				t.Fatal("missing actual loaded sample")
			}
		}
	}
	e.mu.Lock()
	bad := e.requests["entry-wg"] == 0 || e.requests["proxy"] == 0 || len(e.errors) > 0
	e.mu.Unlock()
	if bad {
		t.Fatal("misrouted hop or credentials")
	}
	for _, secret := range []string{"token-one", "token-two", "10.77.0.1", "generation-one"} {
		if strings.Contains(s.StatusJSON(), secret) {
			t.Fatal("private control details leaked")
		}
	}
}
func TestFailedTransfersNeverBecomeZeroSpeed(t *testing.T) {
	for _, bad := range []string{"identity", "duplicate", "redirect", "compress", "truncate", "framing", "ack"} {
		t.Run(bad, func(t *testing.T) {
			s, e := fixture(t)
			e.mu.Lock()
			e.bad["proxy"] = bad
			e.mu.Unlock()
			s.Start(strings.Repeat("2", 32), 65536)
			v := wait(t, s)
			if len(v.Results) != 2 || !v.Results[0].Ready || v.Results[1].Ready || v.Results[1].Failure == "" || v.Results[1].Download != nil || v.Results[1].Upload != nil {
				t.Fatal(v)
			}
		})
	}
}
func TestCancellationOwnershipAndStaleSelector(t *testing.T) {
	s, e := fixture(t)
	id := strings.Repeat("3", 32)
	e.mu.Lock()
	e.bad["entry-wg"] = "hang"
	e.mu.Unlock()
	if err := s.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	if s.Start(strings.Repeat("4", 32), 65536) == nil {
		t.Fatal("overlapping transfer accepted")
	}
	s.Cancel(strings.Repeat("9", 32))
	if status(t, s).Complete {
		t.Fatal("foreign request cancelled measurement")
	}
	s.Cancel(id)
	v := wait(t, s)
	if v.Stage != "cancelled" || len(v.Results) != 0 {
		t.Fatal(v)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Start(strings.Repeat("4", 32), 65536) == nil {
		t.Fatal("closed owner reused")
	}
	s2, e2 := fixture(t)
	s2.Start(strings.Repeat("4", 32), 65536)
	wait(t, s2)
	e2.mu.Lock()
	e2.generation = "generation-one:server"
	e2.mu.Unlock()
	v = status(t, s2)
	if len(v.Results) != 0 || v.Stage != "invalidated" {
		t.Fatal("results from old exit survived", v)
	}
}
func TestInputAndSizeBounds(t *testing.T) {
	s, e := fixture(t)
	for _, size := range []int{-1, 0, 65535, MaxBytes + 1} {
		if s.Start(strings.Repeat("5", 32), size) == nil {
			t.Fatal("unbounded size")
		}
	}
	for _, id := range []string{"", strings.Repeat("a", 31), strings.Repeat("x", 32)} {
		if s.Start(id, 65536) == nil {
			t.Fatal("bad request ID")
		}
	}
	for _, raw := range []string{"http://public.example:8787", "http://127.0.0.1:8787", "http://10.77.0.1:8787/?token=x", "http://u:p@10.77.0.1:8787", "http://10.77.0.1:8787/%68ealth", "http://[fe80::1%25en0]:8787", "ftp://10.77.0.1:8787", "http://10.77.0.1:65536"} {
		h := s.hops[0]
		h.API = raw
		if _, err := New(e, []Hop{h}); err == nil {
			t.Fatal("unsafe API", raw)
		}
	}
	h := s.hops[0]
	h.Tag = "direct"
	if _, err := New(e, []Hop{h}); err == nil {
		t.Fatal("direct outbound permitted")
	}
}
func TestLatencyDistributionUsesSamplesNotSpeed(t *testing.T) {
	v := distribution([]float64{1, 2, 3, 4})
	if v.Samples != 4 || v.Median != 2.5 || v.Average != 2.5 || v.Jitter != 1 || v.P90 != 4 {
		t.Fatal(v)
	}
	if distribution(nil) != nil {
		t.Fatal("missing samples manufactured")
	}
}
