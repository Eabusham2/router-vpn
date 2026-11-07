package dnsmeasure

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type operationContextKey struct{}
type statusContextKey struct{}

type operationEngine struct {
	*fakeEngine
	observe func(context.Context) (string, error)
	begin   func(context.Context) (context.Context, func(), error)
	legacy  atomic.Int32
}

func (e *operationEngine) Identity() string { e.legacy.Add(1); return e.fakeEngine.Identity() }
func (e *operationEngine) IdentityContext(ctx context.Context) (string, error) {
	if e.observe != nil {
		return e.observe(ctx)
	}
	return e.fakeEngine.Identity(), ctx.Err()
}
func (e *operationEngine) BeginMeasurement(ctx context.Context) (context.Context, func(), error) {
	if e.begin != nil {
		return e.begin(ctx)
	}
	return e.fakeEngine.BeginMeasurement(ctx)
}

func operationService(t *testing.T) (*Service, *operationEngine) {
	t.Helper()
	original := newFake()
	engine := &operationEngine{fakeEngine: original}
	description := Description{NodeID: "captured-exit", SessionID: "captured-session", RouteLabel: "Current external exit", IPv6Enabled: true, Selected: Endpoint{ID: "selected", Kind: "selected", Name: "Selected DNS", Address: "10.77.0.53", Port: 5353, Transport: "udp", Route: "entry-wg", RouteLabel: "Selected DNS via entry-wg"}}
	service, err := NewContext(context.Background(), engine, description)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		original.cancel()
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return service, engine
}

func TestDNSPendingAdmissionKeepsCancellationAndScopeOwner(t *testing.T) {
	for _, phase := range []string{"identity-cancel", "activity-cancel", "recheck-cancel", "late-scope-release", "owner-replaced", "close-admission", "invalidate-admission"} {
		t.Run(phase, func(t *testing.T) {
			s, engine := operationService(t)
			parent, retire := context.WithTimeout(context.WithValue(context.Background(), operationContextKey{}, phase), 10*time.Second)
			defer retire()
			entered, releasing, releaseScope := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			allowRelease := func() { releaseOnce.Do(func() { close(releaseScope) }) }
			defer allowRelease()
			var reads atomic.Int32
			var original context.Context
			engine.observe = func(ctx context.Context) (string, error) {
				if !s.mu.TryLock() {
					return "", errors.New("DNS admission held service lock across native observation")
				}
				s.mu.Unlock()
				if ctx.Value(operationContextKey{}) != phase {
					return "", errors.New("DNS admission detached original caller")
				}
				if original == nil {
					original = ctx
				}
				if ctx != original {
					return "", errors.New("DNS admission replaced its original observation context")
				}
				count := reads.Add(1)
				if count == 1 && (phase == "identity-cancel" || phase == "close-admission" || phase == "invalidate-admission") || count == 2 && phase == "recheck-cancel" {
					close(entered)
					<-ctx.Done()
				}
				return engine.fakeEngine.Identity(), nil
			}
			engine.begin = func(ctx context.Context) (context.Context, func(), error) {
				if ctx != original {
					return nil, nil, errors.New("DNS activity replaced original admission caller")
				}
				if !s.mu.TryLock() {
					return nil, nil, errors.New("DNS admission held service lock across activity capture")
				}
				s.mu.Unlock()
				owned, release, err := engine.fakeEngine.BeginMeasurement(ctx)
				if err != nil {
					return owned, release, err
				}
				if phase == "owner-replaced" {
					engine.mu.Lock()
					engine.identity = "replacement-owner"
					engine.mu.Unlock()
				}
				if phase == "activity-cancel" || phase == "late-scope-release" {
					close(entered)
					<-ctx.Done()
				}
				return owned, func() {
					if phase == "late-scope-release" {
						close(releasing)
						<-releaseScope
					}
					release()
				}, nil
			}
			done := make(chan error, 1)
			go func() { done <- s.StartContext(parent, firstRequest, "tcp") }()
			if phase != "owner-replaced" {
				select {
				case <-entered:
				case err := <-done:
					t.Fatal("DNS admission bypassed the retained callback", err)
				case <-time.After(time.Second):
					retire()
					allowRelease()
					<-done
					t.Fatal("DNS admission did not enter original callback")
				}
				action := make(chan error, 1)
				go func() {
					switch phase {
					case "close-admission":
						action <- s.Close()
					case "invalidate-admission":
						s.Invalidate()
						action <- nil
					default:
						s.Cancel(firstRequest)
						action <- nil
					}
				}()
				select {
				case err := <-action:
					if err != nil {
						t.Fatal("DNS retirement did not join admission", err)
					}
				case <-time.After(time.Second):
					retire()
					allowRelease()
					<-action
					<-done
					t.Fatal("DNS cancellation waited behind a native callback")
				}
				if phase == "late-scope-release" {
					select {
					case <-releasing:
					case <-time.After(time.Second):
						retire()
						allowRelease()
						<-done
						t.Fatal("DNS rejection lost original scope release")
					}
					s.mu.Lock()
					pending := s.pending
					s.mu.Unlock()
					if pending == nil {
						t.Fatal("DNS rejection discarded unjoined admission")
					}
					select {
					case <-pending.done:
						t.Fatal("DNS rejection acknowledged an unjoined scope")
					default:
					}
					if s.StartContext(parent, secondRequest, "tcp") == nil {
						t.Fatal("replacement DNS admission overlapped original release")
					}
					allowRelease()
				}
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(time.Second):
				retire()
				allowRelease()
				<-done
				t.Fatal("DNS admission failed to join cancellation")
			}
			if err == nil {
				t.Fatal("DNS admission published a cancelled or replaced scope")
			}
			if phase != "owner-replaced" && !errors.Is(err, context.Canceled) {
				t.Fatal("DNS admission lost original cancellation", err)
			}
			if phase != "owner-replaced" {
				if err := s.Drain(firstRequest); err != nil {
					t.Fatal("retired DNS admission did not drain", err)
				}
				if s.Start(firstRequest, "tcp") == nil {
					t.Fatal("cancelled DNS nonce reopened")
				}
			}
			wantReleases := 1
			if phase == "identity-cancel" || phase == "close-admission" || phase == "invalidate-admission" {
				wantReleases = 0
			}
			engine.mu.Lock()
			active, releases, dials := engine.active, engine.releases, len(engine.dials)
			engine.mu.Unlock()
			if active || releases != wantReleases || dials != 0 || engine.selected.Load() != 0 || engine.legacy.Load() != 0 || engine.ctx.Err() != nil {
				t.Fatal("DNS admission touched another owner, used legacy identity or started workers", active, releases, dials, engine.legacy.Load())
			}
		})
	}
}

func TestDNSObservationKeepsOperationAndReplacementOwners(t *testing.T) {
	for _, phase := range []string{"successful-queries", "watch-cancel", "stale-status", "cancelled-status"} {
		t.Run(phase, func(t *testing.T) {
			s, engine := operationService(t)
			parent, retire := context.WithTimeout(context.WithValue(context.Background(), operationContextKey{}, phase), 10*time.Second)
			defer retire()
			entered, releaseStatus, workEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var enterOnce, workOnce, releaseOnce sync.Once
			unblockStatus := func() { releaseOnce.Do(func() { close(releaseStatus) }) }
			defer unblockStatus()
			var network atomic.Int32
			var armed atomic.Bool
			var owned context.Context
			engine.begin = func(ctx context.Context) (context.Context, func(), error) {
				if ctx.Value(operationContextKey{}) != phase {
					return nil, nil, errors.New("DNS activity lost original caller")
				}
				current, release, err := engine.fakeEngine.BeginMeasurement(ctx)
				owned = current
				return current, release, err
			}
			engine.observe = func(ctx context.Context) (string, error) {
				if ctx.Value(operationContextKey{}) != phase {
					return "", errors.New("DNS observation detached operation caller")
				}
				if marked, _ := ctx.Value(statusContextKey{}).(bool); marked {
					enterOnce.Do(func() { close(entered) })
					<-releaseStatus
					return "late-old-status-owner", nil
				}
				if phase == "watch-cancel" && armed.Load() && ctx == owned {
					enterOnce.Do(func() { close(entered) })
					<-ctx.Done()
				}
				return engine.fakeEngine.Identity(), ctx.Err()
			}
			work := func(ctx context.Context) error {
				if ctx.Value(operationContextKey{}) != phase {
					return errors.New("DNS query detached operation caller")
				}
				if network.Add(1) == Workers {
					armed.Store(true)
				}
				workOnce.Do(func() { close(workEntered) })
				<-ctx.Done()
				return ctx.Err()
			}
			if phase == "successful-queries" {
				engine.selectFn = func(ctx context.Context) error {
					if ctx.Value(operationContextKey{}) != phase {
						return errors.New("selected DNS lost its operation")
					}
					return fixtureDNSWork(ctx)
				}
				engine.dial = func(ctx context.Context, address string) (net.Conn, error) {
					if ctx.Value(operationContextKey{}) != phase || !AllowedPublicAddress(address) {
						return nil, errors.New("DNS catalog dial lost its route or caller")
					}
					return served(tcpAnswer), nil
				}
			} else {
				engine.selectFn = work
				engine.dial = func(ctx context.Context, _ string) (net.Conn, error) { return nil, work(ctx) }
			}
			var statusDone chan string
			var cancelStatus context.CancelFunc
			if phase == "stale-status" || phase == "cancelled-status" {
				statusCtx, stop := context.WithCancel(context.WithValue(parent, statusContextKey{}, true))
				cancelStatus = stop
				defer stop()
				statusDone = make(chan string, 1)
				go func() { statusDone <- s.statusJSONContext(statusCtx) }()
				select {
				case <-entered:
				case <-time.After(time.Second):
					unblockStatus()
					t.Fatal("status did not retain original observation")
				}
			}
			if err := s.StartContext(parent, firstRequest, "tcp"); err != nil {
				t.Fatal("original DNS operation was not admitted", err)
			}
			if phase == "successful-queries" {
				if err := s.Drain(firstRequest); err != nil {
					t.Fatal(err)
				}
				var result Status
				if json.Unmarshal([]byte(s.statusJSONContext(parent)), &result) != nil || !result.Drained || result.Failure != "" || len(result.Results) != 13 {
					t.Fatal("DNS operation lost selected/catalog results", result)
				}
				for _, row := range result.Results {
					if !row.Ready || row.Samples != Samples || row.Failed != 0 {
						t.Fatal("DNS operation manufactured incomplete results", row)
					}
				}
			} else {
				select {
				case <-workEntered:
				case <-time.After(time.Second):
					retire()
					unblockStatus()
					t.Fatal("DNS operation did not enter captured query")
				}
				if phase == "watch-cancel" {
					select {
					case <-entered:
					case <-time.After(2 * time.Second):
						retire()
						t.Fatal("DNS watcher did not use captured operation context")
					}
				} else {
					if phase == "cancelled-status" {
						cancelStatus()
					}
					unblockStatus()
					var raw string
					select {
					case raw = <-statusDone:
					case <-time.After(time.Second):
						retire()
						t.Fatal("old DNS status did not join")
					}
					var result Status
					if json.Unmarshal([]byte(raw), &result) != nil || result.Request != firstRequest || result.Stage != "measuring" || result.Complete || result.Drained || owned.Err() != nil {
						t.Fatal("old DNS status invalidated the replacement operation", result)
					}
				}
				s.Cancel(firstRequest)
				if err := s.Drain(firstRequest); err != nil {
					t.Fatal(err)
				}
			}
			engine.mu.Lock()
			active, releases := engine.active, engine.releases
			engine.mu.Unlock()
			if active || releases != 1 || engine.legacy.Load() != 0 || engine.ctx.Err() != nil {
				t.Fatal("DNS operation released another owner or used detached identity", active, releases, engine.legacy.Load())
			}
		})
	}
}
