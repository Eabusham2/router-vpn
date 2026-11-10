package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
)

type clientClockRead func() (float64, error)

func (r clientClockRead) Milliseconds() (float64, error) { return r() }

type clientClockOutcome struct {
	score   float64
	samples int
	err     error
	label   string
}

func clientClockSampleFixture(t *testing.T, path string) func(context.Context, clientMeasurementClock) clientClockOutcome {
	t.Helper()
	switch path {
	case "tcp":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				_ = c.Close()
			}
		}()
		t.Cleanup(func() { _ = listener.Close(); <-done })
		p := common.RouterProfile{ID: "clock-node", Endpoint: "127.0.0.1"}
		return func(ctx context.Context, clock clientMeasurementClock) clientClockOutcome {
			v, e := profileLatencyAtPortWithClock(ctx, p, listener.Addr().(*net.TCPAddr).Port, 1, clock)
			return clientClockOutcome{v.MedianMs, v.Samples, e, v.Description}
		}
	case "http":
		root := t.TempDir()
		t.Setenv("HOMEVPN_ROOT", root)
		p := common.RouterProfile{ID: "clock-node", NodeKind: "router-vpn", NodeProofID: strings.Repeat("a", 64), APIToken: "original-paired-token"}
		p.NodeProofID = writeTestWGIdentity(t, root, p.ID)
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+p.APIToken || r.URL.Path != "/health" {
				t.Error("HTTP clock sample changed captured proof authority")
			}
			fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
		}))
		t.Cleanup(server.Close)
		p.RouterAPI = server.URL
		return func(ctx context.Context, clock clientMeasurementClock) clientClockOutcome {
			refused := false
			v, e := privatePathLatencyWithClock(ctx, p, state{Connected: true, RouterID: p.ID}, 1, func() (clientMeasurementInterval, error) {
				interval, err := clock()
				refused = err != nil
				return interval, err
			})
			if refused && requests.Load() != 0 {
				t.Fatal("failed clock initialization sent authenticated HTTP work")
			}
			return clientClockOutcome{v.MedianMs, v.Samples, e, v.Proof}
		}
	default:
		a, _, observation := registeredDNSRuntimeSnapshotFixture(t)
		return func(ctx context.Context, clock clientMeasurementClock) clientClockOutcome {
			v := proveSelectedDNSWithClock(ctx, a, observation, "external-socks5", func(call context.Context, question string) ([]string, error) {
				if question != "example.com" {
					t.Error("DNS question changed")
				}
				if _, ok := call.Deadline(); !ok {
					t.Error("DNS lost original bounded caller")
				}
				return []string{"192.0.2.1"}, nil
			}, clock)
			if v.Status != "passed" {
				return clientClockOutcome{err: errors.New(v.Reason)}
			}
			if v.Host != "9.9.9.9" || v.Mode != "custom" {
				t.Error("DNS selected policy changed")
			}
			return clientClockOutcome{v.LatencyMs, 1, nil, v.Reason}
		}
	}
}

func TestClientRTTUsesCheckedClockWithoutFallback(t *testing.T) {
	actual := errors.New("original native clock failure")
	for _, path := range []string{"tcp", "http", "dns"} {
		for _, fault := range []string{"tiny", "fraction", "ordinary", "start", "read", "zero", "negative", "nan", "infinity", "cancel"} {
			t.Run(path+"/"+fault, func(t *testing.T) {
				sample := clientClockSampleFixture(t, path)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				starts, reads := 0, 0
				want := 0.017
				clock := func() (clientMeasurementInterval, error) {
					starts++
					if fault == "start" {
						return nil, actual
					}
					return clientClockRead(func() (float64, error) {
						reads++
						switch fault {
						case "tiny":
							return 0.000001, nil
						case "ordinary":
							return 1.23456, nil
						case "read":
							return 7, actual
						case "zero":
							return 0, nil
						case "negative":
							return -1, nil
						case "nan":
							return math.NaN(), nil
						case "infinity":
							return math.Inf(1), nil
						case "cancel":
							cancel()
						}
						return want, nil
					}), nil
				}
				got := sample(ctx, clock)
				success := fault == "tiny" || fault == "fraction" || fault == "ordinary"
				if success {
					if fault == "tiny" {
						want = 0.000001
					}
					if fault == "ordinary" {
						want = 1.235
						if path == "dns" {
							want = 1.23456
						}
					}
					if got.err != nil || got.samples != 1 || got.score != want {
						t.Fatalf("measured interval changed: %+v want %v", got, want)
					}
					expected := "TCP-handshake RTT"
					if path == "http" {
						expected = "HTTP RTT"
					}
					if path == "dns" {
						expected = "OS resolver query succeeded"
					}
					if !strings.Contains(got.label, expected) {
						t.Fatalf("measurement meaning changed: %q", got.label)
					}
				} else {
					if got.err == nil || got.samples != 0 || got.score != 0 {
						t.Fatalf("invalid clock earned score: %+v", got)
					}
					if fault == "start" || fault == "read" {
						if path != "dns" && !errors.Is(got.err, actual) {
							t.Fatal("original clock cause lost", got.err)
						}
						if !strings.Contains(got.err.Error(), actual.Error()) {
							t.Fatal("clock failure hidden", got.err)
						}
					}
					if fault == "cancel" && path != "dns" && !errors.Is(got.err, context.Canceled) {
						t.Fatal("clock read lost caller cancellation", got.err)
					}
				}
				expectedReads := 1
				if fault == "start" {
					expectedReads = 0
				}
				if starts != 1 || reads != expectedReads {
					t.Fatalf("sample restarted clock: starts=%d reads=%d", starts, reads)
				}
			})
		}
	}
}

func TestClientDNSClockReadCannotAdoptReplacementRuntime(t *testing.T) {
	a, path, observation := registeredDNSRuntimeSnapshotFixture(t)
	proof := proveSelectedDNSWithClock(context.Background(), a, observation, "external-socks5", func(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil }, func() (clientMeasurementInterval, error) {
		return clientClockRead(func() (float64, error) { replaceDNSRuntimeWithSamePolicy(t, path); return .017, nil }), nil
	})
	if proof.Status == "passed" || proof.LatencyMs != 0 {
		t.Fatal("clock read adopted replacement DNS owner", proof)
	}
}

func TestClientDurableLatencyClockFailureCannotOverwriteStatistics(t *testing.T) {
	for _, fault := range []string{"tiny", "ordinary", "outliers", "start", "late-read", "late-zero", "late-negative", "late-nan", "cancel", "replacement"} {
		t.Run(fault, func(t *testing.T) {
			a, tracker := fastestAdoptionFixture(t)
			a.profiles.Profiles = a.profiles.Profiles[:1]
			a.profiles.Profiles[0].Endpoint = "127.0.0.1"
			if e := a.persistProfilesLocked(); e != nil {
				t.Fatal(e)
			}
			before, e := os.ReadFile(a.cfg.ProfilesFile)
			if e != nil {
				t.Fatal(e)
			}
			listener, e := net.Listen("tcp", "127.0.0.1:8388")
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan struct{})
			var accepted atomic.Int32
			go func() {
				defer close(done)
				for {
					c, e := listener.Accept()
					if e != nil {
						return
					}
					accepted.Add(1)
					_ = c.Close()
				}
			}()
			defer func() { _ = listener.Close(); <-done }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads, starts := 0, 0
			clock := func() (clientMeasurementInterval, error) {
				starts++
				if fault == "start" {
					return nil, errors.New("original initialization failure")
				}
				return clientClockRead(func() (float64, error) {
					reads++
					if reads == 25 {
						switch fault {
						case "late-read":
							return 7, errors.New("original read failure")
						case "late-zero":
							return 0, nil
						case "late-negative":
							return -1, nil
						case "late-nan":
							return math.NaN(), nil
						case "cancel":
							cancel()
						case "replacement":
							sessionTrackers.Store(a, &sessionTracker{a: a, session: tracker.session})
						}
					}
					if fault == "ordinary" {
						return 1.23456, nil
					}
					if fault == "outliers" {
						if reads <= 5 {
							return .1, nil
						}
						if reads > 45 {
							return 10000, nil
						}
						return 10, nil
					}
					return .000001, nil
				}), nil
			}
			w := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/profile/latency", strings.NewReader(`{"id":"a","samples":1}`)).WithContext(ctx)
			a.profileLatencyWithClock(w, request, func(context.Context) (string, error) { return "original-physical-network", nil }, clock)
			after, e := os.ReadFile(a.cfg.ProfilesFile)
			if e != nil {
				t.Fatal(e)
			}
			if fault == "tiny" || fault == "ordinary" || fault == "outliers" {
				var result latencyResponse
				if e = json.Unmarshal(w.Body.Bytes(), &result); e != nil {
					t.Fatalf("durable score missing: %d %s", w.Code, w.Body.String())
				}
				want := .000001
				if fault == "ordinary" {
					want = 1.235
				}
				if fault == "outliers" {
					want = 10
					if result.MinMs != .1 || result.MaxMs != 10000 || result.AverageMs != 1008.01 || a.profiles.Profiles[0].LatencyTrimmedMeanMs != want {
						t.Fatalf("outliers were erased or included in the persisted trimmed mean: %+v", result)
					}
				}
				if w.Code != 200 || !result.Complete || !result.Saved || result.Samples != 50 || result.Failed != 0 || result.MedianMs != want || result.TrimmedMs != want || a.profiles.Profiles[0].LatencyMedianMs != want || starts != 50 || reads != 50 {
					t.Fatalf("actual fifty-sample statistics changed: %+v starts=%d reads=%d", result, starts, reads)
				}
				deadline := time.NewTimer(time.Second)
				defer deadline.Stop()
				for accepted.Load() < 51 {
					select {
					case <-deadline.C:
						t.Fatal("fifty original TCP dials plus discovery missing")
					case <-time.After(time.Millisecond):
					}
				}
				if accepted.Load() != 51 {
					t.Fatal("sample/discovery count changed", accepted.Load())
				}
			} else {
				wantStatus := http.StatusBadGateway
				if fault == "cancel" {
					wantStatus = http.StatusRequestTimeout
				}
				if fault == "replacement" {
					wantStatus = http.StatusConflict
				}
				if w.Code != wantStatus || !bytes.Equal(before, after) || a.profiles.Profiles[0].LatencyMedianMs != 40 {
					t.Fatalf("failed/retired timing changed durable statistics: status=%d body=%s", w.Code, w.Body.String())
				}
				if fault == "start" && reads != 0 {
					t.Fatal("failed initialization read the clock")
				}
				if fault != "start" && fault != "replacement" && reads != 25 {
					t.Fatal("clock failure silently salvaged/retried", reads)
				}
				deadline := time.NewTimer(time.Second)
				defer deadline.Stop()
				for accepted.Load() < int32(reads+1) {
					select {
					case <-deadline.C:
						t.Fatal("original discovery/sample dials missing")
					case <-time.After(time.Millisecond):
					}
				}
				if accepted.Load() != int32(reads+1) {
					t.Fatal("clock failure admitted extra sample dials", accepted.Load(), reads)
				}
			}
		})
	}
}

func TestClientClockUsesProductionIntervalAndTinyFastestScoresRemainValid(t *testing.T) {
	interval, err := startClientMeasurementInterval()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := interval.(hopmeasure.Interval); !ok {
		t.Fatalf("production clock substituted %T", interval)
	}
	p := common.RouterProfile{ID: "tiny", Endpoint: "127.0.0.1"}
	values := make([]float64, 50)
	for i := range values {
		values[i] = .000001
	}
	started := time.Now()
	result := profileLatencySummary(p, 8388, values, 0)
	if !validFastestProfileResult(p, result, started) || result.TrimmedMs != .000001 {
		t.Fatal("real tiny interval erased by display rounding", result)
	}
	result.Failed = 1
	if validFastestProfileResult(p, result, started) {
		t.Fatal("failed sample gained a Fastest score")
	}
}
