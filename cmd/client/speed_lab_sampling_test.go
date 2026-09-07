package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpeedLabPatternReaderPreservesStreamAcrossReads(t *testing.T) {
	for _, pattern := range [][]byte{{0}, {1, 2, 3}, bytes.Repeat([]byte{7, 19, 41}, 30000)} {
		r := &speedLabPatternReader{pattern: pattern}
		offset := 0
		for _, size := range []int{0, 1, 2, 7, 65536, 3, 131073, 0, 37} {
			got := make([]byte, size)
			n, err := r.Read(got)
			if err != nil || n != size {
				t.Fatalf("Read(%d): n=%d err=%v", size, n, err)
			}
			for i, value := range got {
				if want := pattern[(offset+i)%len(pattern)]; value != want {
					t.Fatalf("stream byte %d: got %d want %d", offset+i, value, want)
				}
			}
			offset += size
		}
	}
}

func TestSpeedLabPatternReaderEmptyPattern(t *testing.T) {
	r := &speedLabPatternReader{}
	if n, err := r.Read(make([]byte, 16)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty pattern: n=%d err=%v", n, err)
	}
}

func BenchmarkSpeedLabPatternReader(b *testing.B) {
	pattern := bytes.Repeat([]byte{3, 17, 251, 29}, 16384)
	r := &speedLabPatternReader{pattern: pattern}
	buffer := make([]byte, 32768)
	b.SetBytes(int64(len(buffer)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := r.Read(buffer); err != nil || n != len(buffer) {
			b.Fatalf("Read: n=%d err=%v", n, err)
		}
	}
}

// Exercise the production HTTP clients without any public Internet traffic.
// Requests keep HTTPS and certificate validation; only their test dial target
// and expected test certificate name are changed. These tests are not parallel
// because the production factory clones http.DefaultTransport.
func installSpeedLabSamplingServer(t *testing.T, handler http.Handler) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = previous
		transport.CloseIdleConnections()
		server.Close()
	})
}

func TestSpeedLabLoadedSamplerDoesNotCountIntentionalStopAsFailure(t *testing.T) {
	for _, scenario := range []struct {
		name string
		good int
		bad  int
	}{
		{"healthy", 3, 0},
		{"real_failures_preserved", 3, 2},
		{"all_probes_failed", 0, 3},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pending := make(chan struct{})
			var calls atomic.Int32
			installSpeedLabSamplingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(calls.Add(1))
				if n <= scenario.bad {
					http.Error(w, "probe failure", http.StatusServiceUnavailable)
					return
				}
				if n <= scenario.bad+scenario.good {
					_, _ = w.Write([]byte{0})
					return
				}
				close(pending)
				<-r.Context().Done()
			}))
			result := speedLabLoadedLatencySampler(ctx)
			select {
			case <-pending:
			case <-time.After(5 * time.Second):
				t.Fatal("latency sampler did not reach the in-flight request")
			}
			cancel()
			select {
			case got := <-result:
				if got.Samples != scenario.good || got.Failed != scenario.bad {
					t.Fatalf("intentional stop changed probe counts: got samples=%d failed=%d; want samples=%d failed=%d", got.Samples, got.Failed, scenario.good, scenario.bad)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("latency sampler did not finish cancellation")
			}
		})
	}
}

func TestSpeedLabIdleRejectsCancellationDuringLastProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	installSpeedLabSamplingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 10 {
			cancel()
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte{0})
	}))
	if _, err := measureSpeedLabIdleLatency(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled idle measurement returned %v; expected context cancellation", err)
	}
}

func TestSpeedLabRejectsInvalidPathBeforeFirstProbe(t *testing.T) {
	var requests atomic.Int32
	installSpeedLabSamplingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte{0})
	}))
	pathErr := errors.New("test path identity changed")
	_, err := measureSpeedLab(context.Background(), speedLabDuration{}, time.Second, time.Second, func() error { return pathErr })
	if !errors.Is(err, pathErr) {
		t.Fatalf("invalid path: got %v want %v", err, pathErr)
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid path emitted %d requests before validation", requests.Load())
	}
}

func TestSpeedLabRejectsCancellationDuringFinalValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var uploads atomic.Int32
	installSpeedLabSamplingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			uploads.Add(1)
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
			time.Sleep(85 * time.Millisecond)
			_, _ = io.WriteString(w, "{}")
			return
		}
		n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil || n < 1 || n > 64<<20 {
			http.Error(w, "invalid test payload", http.StatusBadRequest)
			return
		}
		if n != 1 {
			time.Sleep(85 * time.Millisecond)
		}
		_, _ = io.CopyN(w, &speedLabPatternReader{pattern: make([]byte, 64<<10)}, n)
	}))
	result, err := measureSpeedLab(ctx, speedLabDuration{}, 250*time.Millisecond, 400*time.Millisecond, func() error {
		if uploads.Load() != 0 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled final validation returned measurement=%+v error=%v", result, err)
	}
	if !result.Finished.IsZero() {
		t.Fatal("cancelled result was marked finished")
	}
}
