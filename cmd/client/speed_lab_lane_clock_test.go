package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Only this client maps the fixed provider to its trusted isolated TLS peer.
// Production resolver, trust and transport construction remain unchanged.
func speedLabClockClient(t *testing.T, badResponse bool) (*http.Client, *atomic.Int32) {
	t.Helper()
	requests := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/__down" || r.URL.Query().Get("bytes") != "1" ||
			r.Host != "speed.cloudflare.com" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("latency probe changed its fixed provider or byte contract")
		}
		if badResponse {
			_, _ = w.Write([]byte{1, 2})
			return
		}
		_, _ = w.Write([]byte{1})
	}))
	client := server.Client()
	client.Timeout = time.Second
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "speed.cloudflare.com:443" {
			return nil, fmt.Errorf("unexpected provider destination %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(func() { transport.CloseIdleConnections(); server.Close() })
	return client, requests
}

func TestSpeedLabAndHopLaneUseCheckedIntervals(t *testing.T) {
	original := errors.New("original checked sample clock error")
	for _, path := range []string{"speed-lab", "paired-hop"} {
		for _, fault := range []string{"tiny", "ordinary", "start", "read", "zero", "negative", "nan", "infinite", "cancel", "wrong-response"} {
			t.Run(path+"/"+fault, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var sample func(clientMeasurementClock) clientClockOutcome
				var requests *atomic.Int32
				if path == "speed-lab" {
					client, calls := speedLabClockClient(t, fault == "wrong-response")
					requests = calls
					sample = func(clock clientMeasurementClock) clientClockOutcome {
						value, err := speedLabProbeOnceWithClock(ctx, client, clock)
						n := 0
						if err == nil {
							n = 1
						}
						return clientClockOutcome{score: value, samples: n, err: err}
					}
				} else {
					_, profile, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
					requests = &atomic.Int32{}
					asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						index := requests.Add(1)
						if r.URL.String() != "http://10.77.0.1:8787/health" || r.Header.Get("Authorization") != "Bearer "+profile.APIToken {
							t.Error("hop measurement changed original private lane or authority")
						}
						node := profile.NodeProofID
						if fault == "wrong-response" && index == 2 {
							node = strings.Repeat("0", 64)
						}
						fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, node, desktopNodeProofKind)
					}))
					sample = func(clock clientMeasurementClock) clientClockOutcome {
						value, err := measureRoutedProfileLatencyViaProxyWithClock(ctx, profile, 2, multihopProofProxy, clock)
						if err == nil && (!value.Connected || value.RouterID != profile.ID || !strings.Contains(value.Proof, "node-identity HTTP RTT")) {
							t.Error("hop latency changed original identity or HTTP measurement label")
						}
						return clientClockOutcome{score: value.MedianMs, samples: value.Samples, err: err}
					}
				}
				starts, reads := 0, 0
				want := 0.000001
				if fault == "ordinary" {
					want = 1.23456
				}
				clock := func() (clientMeasurementInterval, error) {
					starts++
					if fault == "start" {
						return nil, original
					}
					return clientClockRead(func() (float64, error) {
						reads++
						// A late failure cannot salvage an earlier good hop sample.
						if path == "paired-hop" && reads == 1 && fault != "ordinary" {
							return want, nil
						}
						switch fault {
						case "read":
							return 3, original
						case "zero":
							return 0, nil
						case "negative":
							return -1, nil
						case "nan":
							return math.NaN(), nil
						case "infinite":
							return math.Inf(1), nil
						case "cancel":
							cancel()
						}
						return want, nil
					}), nil
				}
				got := sample(clock)
				if fault == "tiny" || fault == "ordinary" {
					n := 1
					if path == "paired-hop" {
						n = 2
						if fault == "ordinary" {
							want = 1.235
						}
					}
					if got.err != nil || got.score != want || got.samples != n || starts != n || reads != n || requests.Load() != int32(n) {
						t.Fatalf("measured sample changed: got %+v want %g, clocks %d/%d requests %d", got, want, starts, reads, requests.Load())
					}
					return
				}
				if got.err == nil || got.score != 0 || got.samples != 0 {
					t.Fatalf("invalid or cancelled sample earned a result: %+v", got)
				}
				if (fault == "start" || fault == "read") && !errors.Is(got.err, original) {
					t.Fatalf("clock cause lost: %v", got.err)
				}
				if fault == "cancel" && !errors.Is(got.err, context.Canceled) {
					t.Fatalf("sample retained cancelled clock readback: %v", got.err)
				}
				if fault == "start" && (requests.Load() != 0 || reads != 0) {
					t.Fatal("failed clock initialization started network work")
				}
			})
		}
	}
}

func TestSpeedLabLatencyStatisticsRetainMeasuredTinyValues(t *testing.T) {
	values := []float64{0.000001, 0.000001, 0.000001, 0.000001}
	stats, err := computeSpeedLabLatencyStats(values, 2)
	if err != nil || stats.Samples != 4 || stats.Failed != 2 || stats.JitterMs != 0 {
		t.Fatalf("actual constant samples changed: %+v %v", stats, err)
	}
	for _, actual := range []float64{stats.MinMs, stats.MedianMs, stats.AverageMs, stats.P90Ms, stats.MaxMs} {
		if actual != values[0] {
			t.Fatalf("real tiny positive interval was rounded away: %+v", stats)
		}
	}
	for _, invalid := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		if result, err := computeSpeedLabLatencyStats([]float64{1, invalid, 2}, 0); err == nil || result.Samples != 0 {
			t.Fatalf("invalid input became statistics: %+v %v", result, err)
		}
	}
}

func TestSpeedLabProbeProductionClockAndCancelledCaller(t *testing.T) {
	client, requests := speedLabClockClient(t, false)
	actual, err := speedLabProbeOnce(context.Background(), client)
	if err != nil || actual <= 0 || math.IsNaN(actual) || math.IsInf(actual, 0) || requests.Load() != 1 {
		t.Fatalf("production clock failed actual TLS exchange: %g %v", actual, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	starts := 0
	_, err = speedLabProbeOnceWithClock(ctx, client, func() (clientMeasurementInterval, error) {
		starts++
		return clientClockRead(func() (float64, error) { return 1, nil }), nil
	})
	if !errors.Is(err, context.Canceled) || starts != 0 || requests.Load() != 1 {
		t.Fatal("cancelled probe created another interval or HTTP request", err)
	}
}
