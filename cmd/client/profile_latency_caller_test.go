package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func profileLatencyCallerFixture(t *testing.T) (*app, *sessionTracker, []byte, *atomic.Int32) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := savedLatencyFixture()
	p.Endpoint = "127.0.0.1"
	p.LatencyReceipt.SourceToken = liveMeasurementProfileToken(p)
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "nodes.json")},
		profiles: common.RouterProfileStore{SelectedID: p.ID, Profiles: []common.RouterProfile{p}}}
	a.state.RouterID = p.ID
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "original-latency-session"}}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	listener, err := net.Listen("tcp4", "127.0.0.1:8388")
	if err != nil {
		t.Fatal(err)
	}
	count := new(atomic.Int32)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			_ = connection.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("original durable-latency TCP listener did not join")
		}
	})
	return a, tracker, before, count
}

func profileLatencyCallerUnchanged(t *testing.T, a *app, before []byte, store common.RouterProfileStore, out *httptest.ResponseRecorder, want int) {
	t.Helper()
	current, err := os.ReadFile(a.cfg.ProfilesFile)
	if out.Code != want || strings.Contains(out.Body.String(), `"saved"`) || strings.Contains(out.Body.String(), `"samples"`) {
		t.Fatalf("expired/replaced durable latency published a result: HTTP%d want%d %s", out.Code, want, out.Body.String())
	}
	if err != nil || !bytes.Equal(before, current) || !reflect.DeepEqual(a.profiles, store) || a.state.RouterID != store.SelectedID {
		t.Fatal("expired/replaced durable latency changed saved history or selection", err)
	}
}

func TestProfileLatencyCallerNetworkObservation(t *testing.T) {
	for _, stage := range []int{1, 2, 52, 53} {
		t.Run(map[int]string{1: "initial", 2: "sample", 52: "before-transaction", 53: "before-persistence"}[stage], func(t *testing.T) {
			a, _, before, _ := profileLatencyCallerFixture(t)
			store := cloneRouterProfileStore(a.profiles)
			type originalCaller struct{}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), originalCaller{}, a))
			entered, observed, abort := make(chan struct{}), make(chan struct{}), make(chan struct{})
			done := make(chan *httptest.ResponseRecorder, 1)
			joined := make(chan struct{})
			defer func() {
				cancel()
				close(abort)
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("original durable-latency observer did not join")
				}
			}()
			go func() {
				defer close(joined)
				out := httptest.NewRecorder()
				calls := 0
				a.profileLatencyWithNetwork(out, httptest.NewRequest(http.MethodPost, "/api/profile/latency", strings.NewReader(`{"id":"saved-node","samples":50}`)).WithContext(ctx),
					func(actual context.Context) (string, error) {
						calls++
						if actual.Value(originalCaller{}) != a {
							t.Error("physical read lost original durable-latency caller")
						}
						if _, ok := actual.Deadline(); !ok {
							t.Error("physical read lost bounded measurement deadline")
						}
						if calls == stage {
							close(entered)
							select {
							case <-actual.Done():
							case <-abort:
								return "", errors.New("observer fixture aborted")
							}
							close(observed)
						}
						return "explicit physical fixture", actual.Err()
					})
				done <- out
			}()
			select {
			case <-entered:
			case out := <-done:
				t.Fatalf("latency missed original observation: HTTP%d %s", out.Code, out.Body.String())
			case <-time.After(3 * time.Second):
				t.Fatal("durable latency did not reach original physical observation")
			}
			cancel()
			select {
			case out := <-done:
				select {
				case <-observed:
				default:
					t.Fatal("durable latency returned before original observation joined")
				}
				profileLatencyCallerUnchanged(t, a, before, store, out, http.StatusRequestTimeout)
			case <-time.After(time.Second):
				t.Fatal("durable latency ignored physical observer cancellation")
			}
		})
	}
}

func TestProfileLatencyCallerHeldLocks(t *testing.T) {
	for _, stage := range []string{"capture-app", "capture-tracker", "transaction-app", "persist-app", "persist-tracker"} {
		t.Run(stage, func(t *testing.T) {
			a, tracker, before, _ := profileLatencyCallerFixture(t)
			store := cloneRouterProfileStore(a.profiles)
			held := &a.mu
			if strings.HasSuffix(stage, "tracker") {
				held = &tracker.mu
			}
			ctx, cancel := context.WithCancel(context.Background())
			entered := make(chan struct{})
			done := make(chan *httptest.ResponseRecorder, 1)
			joined := make(chan struct{})
			release := sync.OnceFunc(held.Unlock)
			trigger := 1
			if stage == "transaction-app" {
				trigger = 52
			}
			if strings.HasPrefix(stage, "persist-") {
				trigger = 53
			}
			var locked atomic.Bool
			defer func() {
				cancel()
				if locked.Load() {
					release()
				}
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("original durable-latency lock admission did not join")
				}
			}()
			go func() {
				defer close(joined)
				out := httptest.NewRecorder()
				calls := 0
				a.profileLatencyWithNetwork(out, httptest.NewRequest(http.MethodPost, "/api/profile/latency", strings.NewReader(`{"id":"saved-node","samples":50}`)).WithContext(ctx),
					func(actual context.Context) (string, error) {
						calls++
						if calls == trigger {
							held.Lock()
							locked.Store(true)
							close(entered)
						}
						return "explicit physical fixture", actual.Err()
					})
				done <- out
			}()
			select {
			case <-entered:
			case out := <-done:
				t.Fatalf("latency missed original held lock: HTTP%d %s", out.Code, out.Body.String())
			case <-time.After(3 * time.Second):
				t.Fatal("durable latency did not reach original held lock")
			}
			cancel()
			select {
			case out := <-done:
				if held.TryLock() {
					held.Unlock()
					t.Fatal("fixture lost its original held lock")
				}
				profileLatencyCallerUnchanged(t, a, before, store, out, http.StatusRequestTimeout)
			case <-time.After(time.Second):
				t.Fatal("durable latency waited for a held lock after cancellation")
			}
		})
	}
}

func TestProfileLatencyCallerRetainsTrackerAndActualSamples(t *testing.T) {
	for _, fault := range []string{"original", "same-id-tracker", "network-change"} {
		t.Run(fault, func(t *testing.T) {
			a, tracker, before, accepted := profileLatencyCallerFixture(t)
			store := cloneRouterProfileStore(a.profiles)
			out := httptest.NewRecorder()
			calls := 0
			a.profileLatencyWithNetwork(out, httptest.NewRequest(http.MethodPost, "/api/profile/latency", strings.NewReader(`{"id":"saved-node","samples":50}`)),
				func(ctx context.Context) (string, error) {
					calls++
					if calls == 53 {
						if fault == "same-id-tracker" {
							session := *tracker.session
							sessionTrackers.Store(a, &sessionTracker{a: a, session: &session})
						}
						if fault == "network-change" {
							return "replacement physical fixture", nil
						}
					}
					return "explicit physical fixture", ctx.Err()
				})
			if calls != 53 || accepted.Load() != 51 {
				t.Fatalf("durable latency changed actual sample contract: network=%d TCP=%d", calls, accepted.Load())
			}
			if fault != "original" {
				profileLatencyCallerUnchanged(t, a, before, store, out, http.StatusConflict)
				return
			}
			var result latencyResponse
			if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &result) != nil || !result.Complete || !result.Saved || result.Samples != 50 || result.Failed != 0 ||
				a.profiles.SelectedID != store.SelectedID || a.state.RouterID != store.SelectedID || a.profiles.Profiles[0].LatencySamples != 50 {
				t.Fatalf("original durable latency did not save its actual50 samples: HTTP%d %s", out.Code, out.Body.String())
			}
		})
	}
}
