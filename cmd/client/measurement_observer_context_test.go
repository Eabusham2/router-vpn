//go:build go1.25

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func measurementContextResult(t *testing.T, done <-chan error, release func()) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		release()
		<-done // Join even a regressed compatibility callback before failing.
		t.Fatal("measurement observation ignored its original caller behind a held owner")
		return nil
	}
}

func measurementHeldLock(mutex *sync.Mutex) func() {
	mutex.Lock()
	var once sync.Once
	return func() { once.Do(mutex.Unlock) }
}

func TestMeasurementObserverCallerAdmission(t *testing.T) {
	for _, method := range []string{"async", "speed-capture", "speed-validate", "public-ip", "dns"} {
		for _, boundary := range []string{"app", "tracker"} {
			t.Run(method+"/"+boundary, func(t *testing.T) {
				a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
				tracker := sessionTrackerFor(a)
				st := a.state
				identity := speedLabPathIdentity{Tracker: tracker, SessionID: session.ID, RouterID: profile.ID}
				mutex := &a.mu
				if boundary == "tracker" {
					mutex = &tracker.mu
				}
				release := measurementHeldLock(mutex)
				defer release()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					var err error
					switch method {
					case "async":
						_, stop, _, failure := asyncMeasurementPathContext(ctx, a, profile, st, session, asyncMeasurementProfileToken(profile))
						err = failure
						if stop != nil {
							stop()
						}
					case "speed-capture":
						_, _, err = captureSpeedLabIdentityContext(ctx, a)
					case "speed-validate":
						err = validateSpeedLabIdentityContext(ctx, a, identity)
					default:
						response := httptest.NewRecorder()
						request := httptest.NewRequest(http.MethodGet, "/api/public-ip", nil).WithContext(ctx)
						if method == "dns" {
							request.Method = http.MethodPost
							a.retestDNS(response, request)
						} else {
							a.publicIP(response, request)
						}
						if response.Code != http.StatusOK && strings.Contains(response.Body.String(), context.DeadlineExceeded.Error()) {
							err = ctx.Err()
						}
					}
					done <- err
				}()
				if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("original deadline was not retained", err)
				}
				release()
				if !a.state.Connected || a.profiles.Profiles[1].FastestDNSHost != "old-result" {
					t.Fatal("observation expiry changed the healthy VPN or adopted a result")
				}
			})
		}
	}
}

func TestMeasurementObserverJoinsHeldValidation(t *testing.T) {
	for _, boundary := range []string{"app", "tracker"} {
		t.Run(boundary, func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, stop, validate, err := asyncMeasurementPathContext(parent, a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			mutex := &a.mu
			if boundary == "tracker" {
				mutex = &sessionTrackerFor(a).mu
			}
			release := measurementHeldLock(mutex)
			defer release()
			entered, done := make(chan struct{}), make(chan error, 1)
			go func() { close(entered); done <- validate() }()
			<-entered
			cancel()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.Canceled) {
				t.Fatal("terminal observation lost original cancellation", err)
			}
			joined := make(chan error, 1)
			go func() { stop(); joined <- context.Cause(ctx) }()
			if err := measurementContextResult(t, joined, release); !errors.Is(err, context.Canceled) {
				t.Fatal("observer join lost original cancellation", err)
			}
			release()
			if !a.state.Connected {
				t.Fatal("observer cancellation stopped the VPN")
			}
		})
	}
}

func TestMeasurementObserverRejectsIdenticalReplacementTracker(t *testing.T) {
	a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
	tracker := sessionTrackerFor(a)
	ctx, stop, validate, err := asyncMeasurementPathContext(context.Background(), a, profile, a.state, session, asyncMeasurementProfileToken(profile))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	identity := speedLabPathIdentity{Tracker: tracker, SessionID: session.ID, RouterID: profile.ID}
	copy := session
	replacement := &sessionTracker{a: a, session: &copy}
	sessionTrackers.Store(a, replacement)
	if validate() == nil || validateSpeedLabIdentityContext(context.Background(), a, identity) == nil {
		t.Fatal("identical replacement session adopted original measurement")
	}
	if release, err := a.beginAsyncMeasurementAdoption(ctx); err == nil {
		release()
		t.Fatal("replacement tracker admitted old result")
	}
	if current, _ := sessionTrackers.Load(a); current != replacement || !a.state.Connected || copy.ID != session.ID {
		t.Fatal("old observation modified replacement owner")
	}
}

func TestMeasurementAdoptionCancellationJoinsTransaction(t *testing.T) {
	for _, when := range []string{"before", "during"} {
		t.Run(when, func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			observed, stop, _, err := asyncMeasurementPathContext(context.Background(), a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if err != nil {
				t.Fatal(err)
			}
			binding := observed.Value(asyncMeasurementBindingKey{})
			stop()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &measurementAdmissionWaitingContext{Context: context.WithValue(parent, asyncMeasurementBindingKey{}, binding), waiting: make(chan struct{})}
			release := measurementHeldLock(&a.mu)
			defer release()
			if when == "before" {
				cancel()
			}
			done := make(chan error, 1)
			go func() {
				adopt, err := a.beginAsyncMeasurementAdoption(ctx)
				if adopt != nil {
					adopt()
				}
				done <- err
			}()
			if when == "during" {
				select {
				case <-ctx.waiting:
				case <-time.After(time.Second):
					cancel()
					release()
					<-done
					t.Fatal("adoption did not reach its original caller's owner admission")
				}
				if !a.operationMu.TryLock() {
					cancel()
					release()
					<-done
					t.Fatal("unvalidated measurement reserved a connection transaction")
				}
				a.operationMu.Unlock()
				cancel()
			}
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.Canceled) {
				t.Fatal("canceled joined transaction adopted a measurement", err)
			}
			release()
			if !a.operationMu.TryLock() {
				t.Fatal("rejected adoption retained transaction")
			}
			a.operationMu.Unlock()
			if !a.state.Connected || a.profiles.Profiles[1].FastestDNSHost != "old-result" {
				t.Fatal("canceled adoption changed healthy VPN/result")
			}
		})
	}
}

type measurementCallerKey struct{}

func TestMeasurementTorObservationKeepsOriginalCaller(t *testing.T) {
	a, launch, _ := desktopTorRunningFixture(t, "proof")
	bound, err := captureDesktopTorMeasurementBinding(a, a.state)
	if err != nil || bound == nil {
		t.Fatal("original Tor fixture did not capture", err)
	}
	parent := context.WithValue(context.Background(), measurementCallerKey{}, "original")
	ctx, cancel := context.WithTimeout(parent, 20*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	called := false
	legacy, contextual := launch.tor.networkIdentity, launch.tor.networkIdentityContext
	defer func() { launch.tor.networkIdentity, launch.tor.networkIdentityContext = legacy, contextual }()
	launch.tor.networkIdentity = func() string { t.Error("contextless Tor observer was invoked"); return "" }
	launch.tor.networkIdentityContext = func(actual context.Context) (string, error) {
		got, exists := actual.Deadline()
		if actual.Value(measurementCallerKey{}) != "original" || !exists || got != deadline {
			t.Error("Tor observer changed original deadline/value")
		}
		called = true
		<-actual.Done()
		return "", actual.Err()
	}
	a.mu.Lock()
	err = bound.currentLockedContext(ctx, a)
	a.mu.Unlock()
	if !called || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Tor network observation lost original caller", err)
	}
	if launch.command.ProcessState != nil {
		t.Fatal("observation retired Tor child")
	}
}

func TestMeasurementOwnedNodeObservationCallerGates(t *testing.T) {
	for _, boundary := range []string{"app", "workspace", "host"} {
		t.Run(boundary, func(t *testing.T) {
			profile, original := desktopOwnedNodeTestSource(t, "node-A", "198.51.100.8", "wg")
			launch, err := newDesktopOwnedNodeLaunch(profile, original, "wg", t.TempDir(), profile.Endpoint, "original-network", strings.Repeat("1", 32), 0)
			if err != nil {
				t.Fatal(err)
			}
			launch.command = &exec.Cmd{}
			a := &app{cmd: launch.command, profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{profile}}, nodeProtection: &desktopNodeProtectionSlot{}, state: state{RouterID: profile.ID, RuntimeMode: "wg"}}
			launch.ownedNode.slot = a.nodeProtection
			desktopNodeOwners.Store(a, launch)
			defer desktopNodeOwners.Delete(a)
			release := func() {}
			if boundary == "app" {
				release = measurementHeldLock(&a.mu)
			}
			if boundary == "workspace" {
				release = measurementHeldLock(&launch.workspaceMu)
			}
			defer release()
			parent := context.WithValue(context.Background(), measurementCallerKey{}, "original")
			ctx, cancel := context.WithTimeout(parent, 20*time.Millisecond)
			defer cancel()
			if boundary == "host" {
				launch.ownedNode.host = &desktopNodeConnectionOwner{capture: desktopOwnedNodePreparation{packageRoot: t.TempDir(), dataRoot: t.TempDir(), lifetime: context.Background(), current: func() error { t.Error("legacy host called"); return nil }, currentContext: func(actual context.Context) error {
					if actual != ctx || actual.Value(measurementCallerKey{}) != "original" {
						t.Error("host lost original caller")
					}
					<-actual.Done()
					return actual.Err()
				}}, host: desktopNodeConnectionHost{start: func(context.Context, *app, *desktopNodeLaunch, []string, []string, string) (desktopNodeProcess, error) {
					return nil, errors.New("observation cannot start")
				}}}
			}
			done := make(chan error, 1)
			go func() { _, err := a.readDesktopOwnedNodeReadyContext(ctx, launch, false); done <- err }()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("owned Node observation dropped caller", err)
			}
			if launch.ownedNode.retired {
				t.Fatal("observation expiry retired Node owner")
			}
		})
	}
}
