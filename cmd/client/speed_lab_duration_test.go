package main

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Redirect only the fixed Speed Lab provider's TLS dial to an isolated HTTP
// server. Nothing reaches a public network and production TLS remains unchanged.
func installSpeedLabDurationEdge(t *testing.T, load http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Get("bytes") == "1" {
			_, _ = w.Write([]byte{1})
			return
		}
		load(w, r)
	}))
	old := http.DefaultTransport
	transport := old.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "speed.cloudflare.com:443" {
			return nil, errors.New("unexpected speed provider address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = old
		transport.CloseIdleConnections()
		server.Close()
	})
}

func TestSpeedLabDirectionDeadlineStopsUnfinishedDownload(t *testing.T) {
	installSpeedLabDurationEdge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", r.URL.Query().Get("bytes"))
		_, _ = w.Write(make([]byte, 256))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	result, err := measureSpeedLabDirection(parent, "download", time.Second, time.Second, 0)
	elapsed := time.Since(started)
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("one-second maximum was exceeded: %s, err=%v", elapsed, err)
	}
	if err != nil {
		t.Fatalf("deadline discarded bytes actually received: %v", err)
	}
	if result.Bytes != 256 || result.Rounds != 1 || result.LoadedLatency.Samples < 2 || result.StoppedStable {
		t.Fatalf("invalid bounded partial download: %+v", result)
	}
	if result.Seconds < .95 || result.Seconds > 1.5 {
		t.Fatalf("reported transfer window is not the real deadline: %+v", result)
	}
	if parent.Err() != nil {
		t.Fatal("direction deadline cancelled its parent request")
	}
}

func TestSpeedLabDirectionDeadlineCountsOnlyAcknowledgedUploads(t *testing.T) {
	var requests atomic.Int32
	var acknowledged atomic.Int64
	installSpeedLabDurationEdge(t, func(w http.ResponseWriter, r *http.Request) {
		first := requests.Add(1) == 1
		read, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			return
		}
		if first {
			acknowledged.Store(read)
			_, _ = w.Write([]byte("ok"))
			return
		}
		// The payload may be consumed locally/in transit, but the test server
		// never acknowledges this round before the selected deadline.
		<-r.Context().Done()
	})
	parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	result, err := measureSpeedLabDirection(parent, "upload", time.Second, time.Second, 0)
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Fatalf("upload outlived its maximum: %s, err=%v", elapsed, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() < 2 || acknowledged.Load() == 0 || result.Bytes != acknowledged.Load() {
		t.Fatalf("unacknowledged upload was credited: requests=%d acknowledged=%d result=%+v", requests.Load(), acknowledged.Load(), result)
	}
	// Include the final stalled round in the denominator, rather than showing
	// the initial fast burst as the full one-second measurement.
	expected := float64(result.Bytes) * 8 / 1_000_000 / result.Seconds
	if math.Abs(result.Mbps-expected) > .01 || result.Seconds < .95 || result.StoppedStable {
		t.Fatalf("stalled tail was hidden in throughput accounting: %+v", result)
	}
}

func TestSpeedLabDirectionDeadlineDoesNotInventUnacknowledgedUpload(t *testing.T) {
	installSpeedLabDurationEdge(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	})
	parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	result, err := measureSpeedLabDirection(parent, "upload", time.Second, time.Second, 0)
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Fatalf("unacknowledged upload outlived its maximum: %s", elapsed)
	}
	if err == nil || result.Bytes != 0 || result.Mbps != 0 {
		t.Fatalf("unacknowledged upload became a successful speed: %+v err=%v", result, err)
	}
}

func TestSpeedLabDirectionCallerCancellationRejectsPartialResult(t *testing.T) {
	started := make(chan struct{}, 1)
	installSpeedLabDurationEdge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", r.URL.Query().Get("bytes"))
		_, _ = w.Write(make([]byte, 256))
		w.(http.Flusher).Flush()
		started <- struct{}{}
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := measureSpeedLabDirection(ctx, "download", time.Second, time.Second, 0)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("load never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("caller cancellation became a duration-limited success: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("load did not stop after caller cancellation")
	}
}

func TestSpeedLabDirectionProviderFailureIsNotNormalDeadline(t *testing.T) {
	installSpeedLabDurationEdge(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not a benchmark", http.StatusForbidden)
	})
	_, err := measureSpeedLabDirection(context.Background(), "download", time.Second, time.Second, 0)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("provider failure was hidden: %v", err)
	}
}

func TestSpeedLabRoundCalibrationSupportsSlowLinks(t *testing.T) {
	for _, rate := range []float64{0, .05, 1} {
		if size := speedLabRoundBytes(rate); size <= 0 || size > 128<<10 {
			t.Fatalf("slow-link calibration %.2f Mbps starts with %d bytes", rate, size)
		}
	}
	if speedLabRoundBytes(1000) < 8<<20 || speedLabRoundBytes(10000) != 64<<20 {
		t.Fatal("slow-link calibration removed the high-throughput bounded ramp")
	}
}

func TestSpeedLabDirectionParallelDoesNotCreditRejectedUploads(t *testing.T) {
	client := &http.Client{Transport: speedLabTestTransport(func(r *http.Request) (*http.Response, error) {
		defer r.Body.Close()
		_, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("rejected")), Header: make(http.Header)}, nil
	})}
	bytes, _, err := speedLabParallelRound(context.Background(), "upload", client, 4096, 4, []byte("payload"))
	if err == nil || bytes != 0 || !strings.Contains(err.Error(), strconv.Itoa(http.StatusForbidden)) {
		t.Fatalf("rejected upload bytes counted as verified: %d, %v", bytes, err)
	}
}
