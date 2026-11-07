package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func viaEntryContextRefused(t *testing.T, a *app, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), `"results"`) || strings.Contains(w.Body.String(), `"fastest_id"`) {
		t.Fatalf("cancelled or replaced candidate observer published a score: %d %s", w.Code, w.Body.String())
	}
	c := viaEntryControlFor(a)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.owner != nil && (c.owner.running || c.owner.receipt != nil || !c.owner.drained) {
		t.Fatal("refused candidate request retained a score, worker or undrained lane")
	}
}

func waitViaEntryContextAdmission(t *testing.T, done <-chan struct{}) {
	t.Helper()
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	for {
		count, _ := runtime.GoroutineProfile(nil)
		if count > 4096 {
			t.Fatal("too many goroutines to inspect the original candidate observer")
		}
		records := make([]runtime.StackRecord, count+16)
		if count, ok := runtime.GoroutineProfile(records); ok {
			for _, record := range records[:count] {
				frames := runtime.CallersFrames(record.Stack())
				admission := false
				for {
					frame, more := frames.Next()
					if strings.HasSuffix(frame.Function, "/desktopnetwork.lockContext") || strings.Contains(frame.Function, "sync.(*Mutex).") {
						admission = true
					}
					if admission && strings.HasSuffix(frame.Function, ".viaEntrySnapshot.validate") {
						return
					}
					if !more {
						break
					}
				}
			}
		}
		select {
		case <-done:
			t.Fatal("candidate request completed before its original observer admission")
		case <-limit.C:
			t.Fatal("candidate observer did not reach its actual held app lock")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestViaEntryCallerPhysicalObserversJoinCancellation(t *testing.T) {
	for _, stage := range []string{"initial", "captured-source", "initial-observer", "inflight-observer", "after-drain"} {
		t.Run(stage, func(t *testing.T) {
			a, entry, candidates := viaEntryFixture(t)
			lane := &viaEntryTestLane{entry: entry}
			type callerKey struct{}
			caller, cancel := context.WithCancel(context.WithValue(context.Background(), callerKey{}, a))
			defer cancel()
			entered, observed, abort, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			done := make(chan *httptest.ResponseRecorder, 1)
			var calls atomic.Int32
			var once sync.Once
			defer func() {
				cancel()
				close(abort)
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("original candidate request did not join fixture cleanup")
				}
			}()
			go func() {
				defer close(joined)
				w := httptest.NewRecorder()
				a.viaEntryCandidatesWith(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates", strings.NewReader(viaEntryTestRequest(strings.Repeat("6", 32), candidates[:1]))).WithContext(caller), viaEntryDependencies{
					network: func(ctx context.Context) (string, error) {
						read := calls.Add(1)
						lane.mu.Lock()
						closed := lane.closed
						lane.mu.Unlock()
						target := stage == "initial" && read == 1 || stage == "captured-source" && read == 2 || stage == "initial-observer" && read == 3 || stage == "inflight-observer" && read == 4 || stage == "after-drain" && closed
						if target {
							once.Do(func() { close(entered) })
							if ctx.Value(callerKey{}) != a {
								t.Error("physical candidate observer lost its original caller")
							}
							if _, ok := ctx.Deadline(); !ok {
								t.Error("candidate observer lost its original deadline")
							}
							select {
							case <-ctx.Done():
								close(observed)
								return "", ctx.Err()
							case <-abort:
								return "", errors.New("candidate observer fixture aborted")
							}
						}
						return "captured-entry-network", ctx.Err()
					}, start: func(context.Context, string, string, common.RouterProfile, map[string][]byte, map[string][]byte, []common.RouterProfile) (viaEntryLane, error) {
						return lane, nil
					},
				})
				done <- w
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("candidate request did not enter the captured observer")
			}
			if stage == "after-drain" {
				// Cancel must acquire the control lock while final source observation is
				// blocked, then join that same request; no receipt can be published.
				cancelled := make(chan *httptest.ResponseRecorder, 1)
				go func() { cancelled <- cancelViaEntryTest(a, strings.Repeat("6", 32)) }()
				select {
				case w := <-cancelled:
					if w.Code != http.StatusOK {
						t.Errorf("exact owner cancellation failed: %d %s", w.Code, w.Body.String())
					}
				case <-time.After(time.Second):
					cancel()
					t.Fatal("terminal network callback held the control lock against Cancel")
				}
			} else {
				cancel()
			}
			select {
			case w := <-done:
				select {
				case <-observed:
				default:
					t.Error("candidate request returned before original observer joined")
				}
				viaEntryContextRefused(t, a, w)
			case <-time.After(time.Second):
				t.Fatal("candidate physical observer ignored its caller")
			}
		})
	}
}

func TestViaEntryCallerHeldAppObserverJoinsBeforeOwnerCleanup(t *testing.T) {
	a, entry, candidates := viaEntryFixture(t)
	lane := &viaEntryTestLane{entry: entry, entered: make(chan struct{}), block: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, joined := make(chan *httptest.ResponseRecorder, 1), make(chan struct{})
	go func() {
		defer close(joined)
		w := httptest.NewRecorder()
		a.viaEntryCandidatesWith(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates", strings.NewReader(viaEntryTestRequest(strings.Repeat("7", 32), candidates[:1]))).WithContext(ctx), viaEntryDependencies{network: func(ctx context.Context) (string, error) { return "captured-physical", ctx.Err() }, start: func(context.Context, string, string, common.RouterProfile, map[string][]byte, map[string][]byte, []common.RouterProfile) (viaEntryLane, error) {
			return lane, nil
		}})
		done <- w
	}()
	select {
	case <-lane.entered:
	case <-time.After(time.Second):
		t.Fatal("actual routed candidate did not enter its original lane")
	}
	a.mu.Lock()
	release := sync.OnceFunc(a.mu.Unlock)
	defer func() {
		cancel()
		release()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("candidate observer or routed worker did not join")
		}
	}()
	waitViaEntryContextAdmission(t, joined)
	cancel()
	select {
	case w := <-done:
		if a.mu.TryLock() {
			a.mu.Unlock()
			t.Fatal("test released original app lock before cancellation joined")
		}
		release()
		viaEntryContextRefused(t, a, w)
		lane.mu.Lock()
		closed, calls, proofs := lane.closed, lane.closeCalls, lane.proofs
		lane.mu.Unlock()
		if !closed || calls != 1 || proofs != 1 {
			t.Fatalf("cancelled observer lost its exact proved lane cleanup: closed=%t closes=%d proofs=%d", closed, calls, proofs)
		}
	case <-time.After(time.Second):
		t.Fatal("joined candidate observer waited for unrelated app lock release")
	}
}

func TestViaEntryCallerNativeAdmissionCannotWaitPastItsOwner(t *testing.T) {
	for _, stage := range []string{"alive", "dial", "close-serialization", "close-state"} {
		t.Run(stage, func(t *testing.T) {
			owner, cancelOwner := context.WithCancel(context.Background())
			defer cancelOwner()
			processDone := make(chan struct{})
			close(processDone)
			directory := t.TempDir()
			info, err := os.Stat(directory)
			if err != nil {
				t.Fatal(err)
			}
			lane := &viaEntryNativeLane{ctx: owner, cancel: cancelOwner, processDone: processDone, directory: directory, directoryInfo: info, allowed: map[string]bool{"198.51.100.2:443": true}, conns: map[*viaEntryNativeConn]bool{}}
			held := &lane.mu
			if stage == "close-serialization" {
				held = &lane.closeMu
			}
			held.Lock()
			release := sync.OnceFunc(held.Unlock)
			defer release()
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, done := make(chan struct{}), make(chan error, 1)
			go func() {
				close(entered)
				switch stage {
				case "alive":
					if lane.AliveContext(caller) {
						done <- errors.New("expired lane liveness was admitted")
					} else {
						done <- caller.Err()
					}
				case "dial":
					connection, err := lane.DialContext(caller, "tcp", "198.51.100.2:443")
					if connection != nil {
						_ = connection.Close()
						done <- errors.New("unadmitted candidate opened a socket")
					} else {
						done <- err
					}
				default:
					done <- lane.Close(caller)
				}
			}()
			<-entered
			select {
			case err := <-done:
				t.Fatal("native path escaped its original held mutex", err)
			case <-time.After(20 * time.Millisecond):
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("native candidate lost original cancellation", err)
				}
				if held.TryLock() {
					held.Unlock()
					t.Fatal("native test lost its held mutex")
				}
				release()
				if lane.closing || lane.removed || lane.operationsEnd != nil || len(lane.conns) != 0 {
					t.Fatal("failed native admission changed another owner's state")
				}
			case <-time.After(time.Second):
				release()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("native caller did not join after fixture release")
				}
				t.Fatal("native candidate waited for unrelated held lock after cancellation")
			}
		})
	}
}

func TestViaEntryCallerValidationRetainsExactReceiptOwner(t *testing.T) {
	for _, fault := range []string{"cancel", "replacement"} {
		t.Run(fault, func(t *testing.T) {
			a, entry, candidates := viaEntryFixture(t)
			lane := &viaEntryTestLane{entry: entry}
			id := strings.Repeat("8", 32)
			entered, release := make(chan struct{}), make(chan struct{})
			var validating atomic.Bool
			network := func(ctx context.Context) (string, error) {
				if validating.Load() {
					close(entered)
					select {
					case <-ctx.Done():
						return "", ctx.Err()
					case <-release:
					}
				}
				return "captured-physical", ctx.Err()
			}
			measured := runViaEntryTest(a, lane, id, candidates[:1], network)
			if measured.Code != http.StatusOK {
				t.Fatal("original actual candidate receipt failed", measured.Code, measured.Body.String())
			}
			validating.Store(true)
			c := viaEntryControlFor(a)
			c.mu.Lock()
			original := c.owner
			c.mu.Unlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finish := sync.OnceFunc(func() { close(release) })
			defer finish()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				a.viaEntryCandidatesValidate(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates/validate", strings.NewReader(`{"request_id":"`+id+`","entry_id":"entry","exit_id":"`+candidates[0].ID+`"}`)).WithContext(ctx))
				done <- w
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("receipt validation did not enter its original network observer")
			}
			if !c.mu.TryLock() {
				cancel()
				finish()
				<-done
				t.Fatal("network revalidation blocked the candidate-control owner")
			}
			replacement := &viaEntryOwner{id: "replacement", drained: true, receipt: &viaEntryReceipt{RequestID: "replacement"}}
			if fault == "replacement" {
				c.owner = replacement
			}
			c.mu.Unlock()
			if fault == "cancel" {
				cancel()
			} else {
				finish()
			}
			select {
			case w := <-done:
				if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), `"measured":true`) {
					t.Fatalf("foreign caller/receipt borrowed a measured score: %d %s", w.Code, w.Body.String())
				}
			case <-time.After(time.Second):
				t.Fatal("validation did not join its original observer")
			}
			c.mu.Lock()
			current := c.owner
			c.mu.Unlock()
			if fault == "replacement" && current != replacement || fault == "cancel" && current != original {
				t.Fatal("rejected validation changed the current receipt owner")
			}
		})
	}
}
