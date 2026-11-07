package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func fastestContextUnchanged(t *testing.T, a *app, original []byte, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code || strings.Contains(w.Body.String(), `"winner"`) || strings.Contains(w.Body.String(), `"results"`) {
		t.Fatalf("cancelled or replaced Fastest request published a result: status=%d body=%s", w.Code, w.Body.String())
	}
	if a.profiles.SelectedID != "a" || a.state.RouterID != "a" {
		t.Fatal("refused Fastest request changed selection")
	}
	current, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil || string(current) != string(original) {
		t.Fatal("refused Fastest request changed durable selection or benchmark", err)
	}
}

func TestFastestCallerNetworkObservationJoinsBeforeReturning(t *testing.T) {
	for _, stage := range []int{1, 2, 4, 5} {
		t.Run(map[int]string{1: "initial", 2: "before-candidate", 4: "before-ranking", 5: "before-adoption"}[stage], func(t *testing.T) {
			a, _ := fastestAdoptionFixture(t)
			original, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			type ownerKey struct{}
			caller, cancel := context.WithCancel(context.WithValue(context.Background(), ownerKey{}, a))
			defer cancel()
			entered, observed := make(chan struct{}), make(chan struct{})
			abort, joined := make(chan struct{}), make(chan struct{})
			done := make(chan *httptest.ResponseRecorder, 1)
			defer func() {
				cancel()
				close(abort)
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("original physical observation did not join fixture cleanup")
				}
			}()
			calls := 0
			go func() {
				defer close(joined)
				w := httptest.NewRecorder()
				a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{}`)).WithContext(caller),
					func(ctx context.Context, p common.RouterProfile, n int) (liveLatencyResult, error) {
						if n != 50 {
							t.Error("Fastest changed its sample contract")
						}
						return fastestMeasuredResult(p), nil
					},
					func(ctx context.Context) (string, error) {
						calls++
						if ctx.Value(ownerKey{}) != a {
							t.Error("physical observation lost its original caller")
						}
						if _, ok := ctx.Deadline(); !ok {
							t.Error("physical observation lost its bounded measurement deadline")
						}
						if calls == stage {
							close(entered)
							select {
							case <-ctx.Done():
							case <-abort:
								return "", errors.New("physical observer fixture aborted")
							}
							close(observed)
							return "captured-physical", ctx.Err()
						}
						return "captured-physical", ctx.Err()
					})
				done <- w
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("Fastest did not enter the original physical observer")
			}
			cancel()
			select {
			case w := <-done:
				select {
				case <-observed:
				default:
					t.Error("request returned before its original observation joined")
				}
				fastestContextUnchanged(t, a, original, w, http.StatusRequestTimeout)
			case <-time.After(time.Second):
				t.Fatal("original physical observation ignored caller cancellation")
			}
		})
	}
}

func TestFastestCallerHeldLocksReturnWhileOriginalLockRemainsHeld(t *testing.T) {
	for _, stage := range []string{"capture-app", "capture-tracker", "mutation-app", "candidate-guard", "adoption-tracker", "adoption-app"} {
		t.Run(stage, func(t *testing.T) {
			a, tracker := fastestAdoptionFixture(t)
			original, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			held := &a.mu
			if stage == "capture-tracker" || stage == "adoption-tracker" {
				held = &tracker.mu
			}
			if stage == "candidate-guard" {
				held = &viaEntryControlFor(a).mu
			}
			entered := make(chan struct{})
			done := make(chan *httptest.ResponseRecorder, 1)
			var release func()
			if strings.HasPrefix(stage, "capture-") || stage == "candidate-guard" {
				held.Lock()
				release = sync.OnceFunc(held.Unlock)
			}
			if release != nil {
				defer release()
			}
			calls := 0
			go func() {
				w := httptest.NewRecorder()
				a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{}`)).WithContext(caller),
					func(ctx context.Context, p common.RouterProfile, n int) (liveLatencyResult, error) {
						return fastestMeasuredResult(p), nil
					},
					func(ctx context.Context) (string, error) {
						calls++
						trigger := 1
						if stage == "mutation-app" || stage == "candidate-guard" {
							trigger = 4
						}
						if strings.HasPrefix(stage, "adoption-") {
							trigger = 5
						}
						if calls == trigger {
							if stage == "mutation-app" || strings.HasPrefix(stage, "adoption-") {
								held.Lock()
							}
							close(entered)
						}
						return "captured-physical", nil
					})
				done <- w
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				cancel()
				t.Fatal("Fastest did not reach held-lock boundary")
			}
			if release == nil {
				release = sync.OnceFunc(held.Unlock)
				defer release()
			}
			// Give the original request a scheduling turn with the selected mutex held.
			// The release remains controlled by this test, never by a background waiter.
			select {
			case w := <-done:
				t.Fatalf("Fastest escaped an unreleased original lock: %d %s", w.Code, w.Body.String())
			case <-time.After(20 * time.Millisecond):
			}
			cancel()
			select {
			case w := <-done:
				if held.TryLock() {
					held.Unlock()
					t.Fatal("test lost its original held lock")
				}
				release()
				fastestContextUnchanged(t, a, original, w, http.StatusRequestTimeout)
				if !a.operationMu.TryLock() {
					t.Fatal("cancelled Fastest retained mutation ownership")
				}
				a.operationMu.Unlock()
			case <-time.After(time.Second):
				release()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("original request did not join after fixture release")
				}
				t.Fatal("caller cancellation waited for release of an unrelated held lock")
			}
		})
	}
}

func TestFastestCallerReplacementTrackerCannotBorrowSameSessionID(t *testing.T) {
	a, tracker := fastestAdoptionFixture(t)
	original, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	copied := *tracker.session
	replacement := &sessionTracker{a: a, session: &copied}
	w := httptest.NewRecorder()
	a.fastestProfileWithSources(w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{}`)),
		func(ctx context.Context, p common.RouterProfile, n int) (liveLatencyResult, error) {
			sessionTrackers.Store(a, replacement)
			return fastestMeasuredResult(p), nil
		},
		func(context.Context) (string, error) { return "captured-physical", nil })
	fastestContextUnchanged(t, a, original, w, http.StatusConflict)
	if current, _ := sessionTrackers.Load(a); current != replacement {
		t.Fatal("old Fastest request replaced the current tracker")
	}
}

func TestFastestCallerActualSamplesCancelInsideNetworkObserver(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-serverDone }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, observed := make(chan struct{}), make(chan struct{})
	reads := 0
	sampleContext := context.WithValue(ctx, fastestNetworkKey{}, func(caller context.Context) error {
		reads++
		if reads == 3 {
			close(entered)
			<-caller.Done()
			close(observed)
			return caller.Err()
		}
		return caller.Err()
	})
	type result struct {
		value liveLatencyResult
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := profileLatencyAtPort(sampleContext, common.RouterProfile{ID: "captured-node", Endpoint: "127.0.0.1"}, listener.Addr().(*net.TCPAddr).Port, 50)
		done <- result{value, err}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual TCP sampling did not enter its third physical observation")
	}
	cancel()
	select {
	case got := <-done:
		select {
		case <-observed:
		default:
			t.Error("sample loop abandoned its original network observer")
		}
		if !errors.Is(got.err, context.Canceled) || got.value.Samples != 0 || got.value.TrimmedMs != 0 {
			t.Fatalf("cancelled actual samples earned a score: %+v %v", got.value, got.err)
		}
		if accepted.Load() != 2 {
			t.Fatalf("network refusal admitted a later TCP sample: accepted=%d", accepted.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("actual TCP sample observer ignored the original caller")
	}
}
