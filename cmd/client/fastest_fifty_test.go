package main

import (
	"context"
	"encoding/json"
	"errors"
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
)

func fastestFiftyValues(p common.RouterProfile, values []float64) liveLatencyResult {
	return profileLatencySummary(p, 443, values, 0)
}

func fastestFiftyConstant(p common.RouterProfile, ms float64) liveLatencyResult {
	values := make([]float64, 50)
	for i := range values {
		values[i] = ms
	}
	return fastestFiftyValues(p, values)
}

func TestFastestFiftyResultRequiresCompleteFiniteCurrentStatistics(t *testing.T) {
	p := common.RouterProfile{ID: "node", Endpoint: "node.invalid"}
	started := time.Now().Add(-time.Second)
	valid := fastestFiftyConstant(p, 5)
	if !validFastestProfileResult(p, valid, started) {
		t.Fatal("complete current fifty-sample statistics rejected")
	}
	mutations := map[string]func(*liveLatencyResult){
		"49 samples":            func(v *liveLatencyResult) { v.Samples = 49 },
		"51 samples":            func(v *liveLatencyResult) { v.Samples = 51 },
		"failed sample":         func(v *liveLatencyResult) { v.Failed = 1 },
		"negative failed count": func(v *liveLatencyResult) { v.Failed = -1 },
		"foreign node":          func(v *liveLatencyResult) { v.ID = "another" },
		"foreign endpoint":      func(v *liveLatencyResult) { v.Endpoint = "another.invalid" },
		"invalid port":          func(v *liveLatencyResult) { v.Port = 0 },
		"stale":                 func(v *liveLatencyResult) { v.MeasuredAt = started.Add(-time.Nanosecond) },
		"future":                func(v *liveLatencyResult) { v.MeasuredAt = time.Now().Add(time.Hour) },
		"zero minimum":          func(v *liveLatencyResult) { v.MinMs = 0 },
		"negative median":       func(v *liveLatencyResult) { v.MedianMs = -1 },
		"NaN mean":              func(v *liveLatencyResult) { v.AverageMs = math.NaN() },
		"infinite trimmed mean": func(v *liveLatencyResult) { v.TrimmedMs = math.Inf(1) },
		"zero trimmed mean":     func(v *liveLatencyResult) { v.TrimmedMs = 0 },
		"trimmed outside range": func(v *liveLatencyResult) { v.TrimmedMs = 6 },
		"reversed quantiles":    func(v *liveLatencyResult) { v.MinMs = 1; v.P90Ms = 4 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if validFastestProfileResult(p, value, started) {
				t.Fatal("invalid statistics earned a Fastest score")
			}
		})
	}
}

func TestFastestFiftyRequestCountAndMetricIsolation(t *testing.T) {
	for _, body := range []string{`{"samples":1}`, `{"samples":4}`, `{"samples":49}`, `{"samples":51}`, `{"samples":-1}`, `{"include_external":true}`} {
		t.Run(body, func(t *testing.T) {
			a, _ := fastestAdoptionFixture(t)
			calls := 0
			w := httptest.NewRecorder()
			a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(body)), func(_ context.Context, p common.RouterProfile, n int) (liveLatencyResult, error) {
				calls++
				return fastestFiftyConstant(p, 1), nil
			}, func() string { return "physical-A" })
			if w.Code != http.StatusBadRequest || calls != 0 || a.profiles.SelectedID != "a" {
				t.Fatalf("invalid sample/metric request reached measurement: status=%d calls=%d", w.Code, calls)
			}
		})
	}
	for _, body := range []string{`{"select":false}`, `{"samples":50,"select":false}`} {
		a, _ := fastestAdoptionFixture(t)
		a.profiles.Profiles = append(a.profiles.Profiles, common.RouterProfile{ID: "external", NodeKind: "external", Endpoint: "external.invalid"}, common.RouterProfile{ID: "unknown", NodeKind: "unknown", Endpoint: "unknown.invalid"})
		calls := 0
		w := httptest.NewRecorder()
		a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(body)), func(_ context.Context, p common.RouterProfile, n int) (liveLatencyResult, error) {
			calls++
			if n != 50 || p.ID == "external" || p.ID == "unknown" {
				t.Fatalf("mixed metric or incorrect count: node=%s count=%d", p.ID, n)
			}
			return fastestFiftyConstant(p, 5), nil
		}, func() string { return "physical-A" })
		if w.Code != http.StatusOK || calls != 2 || a.profiles.SelectedID != "a" {
			t.Fatalf("complete read-only Router comparison failed: %d %s calls=%d", w.Code, w.Body.String(), calls)
		}
	}
}

func TestFastestFiftyRanksTrimmedMeanWithStableTiesAndNoPartialScore(t *testing.T) {
	a, _ := fastestAdoptionFixture(t)
	a.profiles.Profiles = append(a.profiles.Profiles, common.RouterProfile{ID: "c", Endpoint: "three.invalid"}, common.RouterProfile{ID: "partial", Endpoint: "partial.invalid"})
	w := httptest.NewRecorder()
	a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{"select":false}`)), func(_ context.Context, p common.RouterProfile, _ int) (liveLatencyResult, error) {
		if p.ID == "a" {
			values := make([]float64, 50)
			for i := range values {
				values[i] = 1
				if i >= 26 {
					values[i] = 100
				}
			}
			return fastestFiftyValues(p, values), nil
		}
		v := fastestFiftyConstant(p, 20)
		if p.ID == "partial" {
			v.Samples = 49
			v.Failed = 1
			v.TrimmedMs = 1
		}
		return v, nil
	}, func() string { return "physical-A" })
	var response struct {
		Winner       liveLatencyResult   `json:"winner"`
		Results      []liveLatencyResult `json:"results"`
		Disqualified []map[string]any    `json:"disqualified"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK {
		t.Fatalf("comparison failed: %d %s: %v", w.Code, w.Body.String(), err)
	}
	if response.Winner.ID != "b" || len(response.Results) != 3 || response.Results[1].ID != "c" || response.Results[2].ID != "a" || response.Results[2].MedianMs >= response.Winner.MedianMs {
		t.Fatalf("trimmed ranking/tie order failed: %+v", response)
	}
	if len(response.Disqualified) != 1 || response.Disqualified[0]["id"] != "partial" {
		t.Fatalf("partial candidate disappeared or gained a score: %+v", response.Disqualified)
	}
	if _, ok := response.Disqualified[0]["trimmed_mean_ms"]; ok {
		t.Fatal("disqualified candidate published a fabricated score")
	}
	for _, failure := range []string{"partial", "transport"} {
		t.Run("no winner "+failure, func(t *testing.T) {
			a, _ := fastestAdoptionFixture(t)
			w := httptest.NewRecorder()
			a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{}`)), func(_ context.Context, p common.RouterProfile, _ int) (liveLatencyResult, error) {
				v := fastestFiftyConstant(p, 1)
				v.Samples, v.Failed = 49, 1
				if failure == "transport" {
					return liveLatencyResult{}, errors.New("controlled refused node")
				}
				return v, nil
			}, func() string { return "physical-A" })
			if w.Code != http.StatusBadGateway || a.profiles.SelectedID != "a" {
				t.Fatalf("invalid-only round selected a winner: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestFastestFiftyDeepCaptureAndReadOnlyStaleness(t *testing.T) {
	for _, change := range []string{"credentials", "slice", "selection", "session", "path", "network", "transient network", "cancel"} {
		t.Run(change, func(t *testing.T) {
			a, tracker := fastestAdoptionFixture(t)
			a.profiles.Profiles[1].APIToken = "original-private-token"
			a.profiles.Profiles[1].CustomLayers = []string{"original-layer"}
			originalDisk, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			network := "physical-A"
			w := httptest.NewRecorder()
			a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{"select":false}`)).WithContext(ctx), func(ctx context.Context, p common.RouterProfile, n int) (liveLatencyResult, error) {
				if n != 50 {
					t.Fatalf("not an exact fifty round: %d", n)
				}
				if p.ID == "a" {
					switch change {
					case "credentials":
						a.profiles.Profiles[1].APIToken = "new-private-token"
					case "slice":
						a.profiles.Profiles[1].CustomLayers[0] = "new-layer"
					case "selection":
						a.profiles.SelectedID = "manual-selection"
					case "session":
						tracker.mu.Lock()
						tracker.session.ID = "replacement-session"
						tracker.mu.Unlock()
					case "path":
						a.state.Mode = "replacement-path"
					case "network":
						network = "physical-B"
					case "transient network":
						network = "physical-B"
						current, ok := ctx.Value(fastestNetworkKey{}).(func() bool)
						if !ok || current() {
							t.Fatal("sample failed to observe network replacement")
						}
						network = "physical-A"
						return liveLatencyResult{}, errors.New("observed physical metadata drift")
					case "cancel":
						cancel()
					}
				} else if p.APIToken != "original-private-token" || p.CustomLayers[0] != "original-layer" {
					t.Fatal("probe received live mutable credentials or a shallow policy slice")
				}
				return fastestFiftyConstant(p, 5), nil
			}, func() string { return network })
			if w.Code == http.StatusOK {
				t.Fatalf("stale/cancelled read-only round returned a winner: %s", w.Body.String())
			}
			if change != "selection" && a.profiles.SelectedID != "a" {
				t.Fatal("rejected round changed selection")
			}
			currentDisk, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil || string(currentDisk) != string(originalDisk) {
				t.Fatal("read-only refusal changed saved statistics or selection")
			}
		})
	}
}

func TestFastestFiftyReadOnlyRejectsActiveVPN(t *testing.T) {
	for _, phase := range []string{"connected", "connecting"} {
		t.Run(phase, func(t *testing.T) {
			a, _ := fastestAdoptionFixture(t)
			a.state.Phase, a.state.Connected = phase, phase == "connected"
			calls := 0
			w := httptest.NewRecorder()
			a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{"select":false}`)), func(_ context.Context, p common.RouterProfile, _ int) (liveLatencyResult, error) {
				calls++
				return fastestFiftyConstant(p, 1), nil
			}, func() string { return "physical-A" })
			if w.Code != http.StatusConflict || calls != 0 {
				t.Fatalf("ambient VPN was admitted as direct TCP: status=%d probes=%d", w.Code, calls)
			}
		})
	}
}

func TestFastestFiftyReadOnlyOwnsTrackerBeforeAppWithoutMutationLease(t *testing.T) {
	a, tracker := fastestAdoptionFixture(t)
	measured, finish := make(chan struct{}), make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 1)
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	go func() {
		w := httptest.NewRecorder()
		a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{"select":false}`)), func(_ context.Context, p common.RouterProfile, _ int) (liveLatencyResult, error) {
			if p.ID == "b" {
				close(measured)
				<-finish
			}
			return fastestFiftyConstant(p, 5), nil
		}, func() string { return "physical-A" })
		done <- w
	}()
	select {
	case <-measured:
	case <-time.After(time.Second):
		close(finish)
		t.Fatal("read-only measurement waited for the mutation lease")
	}
	// Hold the final app snapshot. A coherent read-only response must retain
	// tracker.mu while waiting here, despite not owning operationMu.
	a.mu.Lock()
	close(finish)
	trackerOwned := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if tracker.mu.TryLock() {
			tracker.mu.Unlock()
		} else {
			trackerOwned = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	a.mu.Unlock()
	select {
	case w := <-done:
		if w.Code != http.StatusOK || !trackerOwned || a.profiles.SelectedID != "a" {
			t.Fatalf("read-only terminal snapshot lost tracker ownership: status=%d tracker=%t selected=%s", w.Code, trackerOwned, a.profiles.SelectedID)
		}
	case <-time.After(time.Second):
		t.Fatal("read-only response did not release the joined tracker/app snapshot")
	}
}

func TestFastestFiftyActualTCPAndObservedNetworkDrift(t *testing.T) {
	for _, scenario := range []string{"complete", "network", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var accepted atomic.Int32
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					n := accepted.Add(1)
					_ = conn.Close()
					if scenario == "cancel" && n == 3 {
						cancel()
					}
				}
			}()
			defer func() { _ = listener.Close(); <-joined }()
			var networkReads atomic.Int32
			ctx = context.WithValue(ctx, fastestNetworkKey{}, func() bool { return scenario != "network" || networkReads.Add(1) != 3 })
			p := common.RouterProfile{ID: "loopback-node", Endpoint: "127.0.0.1"}
			started := time.Now()
			result, err := profileLatencyAtPort(ctx, p, listener.Addr().(*net.TCPAddr).Port, 50)
			if scenario != "complete" {
				if err == nil || result.Samples != 0 {
					t.Fatalf("interrupted actual dial round earned a score: %+v %v", result, err)
				}
				if scenario == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("request cancellation lost: %v", err)
				}
				return
			}
			if err != nil || !validFastestProfileResult(p, result, started) {
				t.Fatalf("actual fifty TCP dials failed: %+v %v", result, err)
			}
			deadline := time.Now().Add(time.Second)
			for accepted.Load() < 50 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if accepted.Load() != 50 {
				t.Fatalf("actual accept count=%d, want exactly 50 (discovery excluded)", accepted.Load())
			}
		})
	}
}
