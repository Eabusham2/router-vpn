//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// These tests isolate the post-activation observer and actual app transaction.
// Service authentication/native policy/DNS are exercised by their separate
// service tests; a controlled callback here is not native network acceptance.
type standardMonitorFixture struct {
	a      *app
	o      *linuxStandardServiceLaunch
	m      *linuxStandardServiceMonitor
	op     context.Context
	finish func()
	stops  atomic.Int32
}

func newStandardMonitorFixture(t *testing.T) *standardMonitorFixture {
	t.Helper()
	profile := common.RouterProfile{ID: "control", Name: "Original", DNSMode: "custom", DNSProtocol: "udp", DNSHost: "1.1.1.1", KillSwitchPolicy: "off", IPv6Mode: "on"}
	operation, cancel := context.WithCancel(context.Background())
	a := &app{profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}, connectionContext: operation}
	command := exec.Command("original-unstarted-controller-request")
	prepared := &linuxLegacyStandardExitOwner{app: a, command: command, session: strings.Repeat("1", 32), digest: strings.Repeat("2", 64),
		protectionProfileID: profile.ID, runtimeMode: "standard-socks5", routerID: "standard:provider", base: "external",
		dns: &legacyStandardDNS{profileID: profile.ID, profileToken: asyncMeasurementProfileToken(profile), networkID: "original-physical-network"}}
	request := linuxStandardServiceRequest{Schema: 1, Action: "start", Session: prepared.session, ConfigSHA256: prepared.digest,
		ProfileID: profile.ID, NetworkID: prepared.dns.networkID, RuntimeMode: prepared.runtimeMode, RouterID: prepared.routerID, Base: prepared.base}
	o := &linuxStandardServiceLaunch{app: a, prepared: prepared, request: request, registered: true, attempted: true, dnsProved: true}
	a.cmd = command
	a.state = state{Connected: true, Phase: "connected", Mode: "standard-exit", LogicalMode: "standard-exit", RuntimeMode: prepared.runtimeMode, RouterID: prepared.routerID, Base: prepared.base}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "original-monitor-session", Phase: "connected", Connected: true}}
	linuxStandardServiceOwners.Store(a, o)
	sessionTrackers.Store(a, tracker)
	a.operationMu.Lock()
	var once sync.Once
	f := &standardMonitorFixture{a: a, o: o, op: operation}
	f.finish = func() {
		once.Do(func() {
			cancel()
			a.mu.Lock()
			if a.connectionContext == operation {
				a.connectionContext = nil
			}
			a.mu.Unlock()
			a.operationMu.Unlock()
		})
	}
	t.Cleanup(func() {
		f.finish()
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := o.stopMonitor(ctx); err != nil {
			t.Error("monitor cleanup did not join", err)
		}
		if f.m != nil {
			select {
			case <-f.m.finished:
			case <-ctx.Done():
				t.Error("monitor cleanup outlived its original transaction")
			}
		}
		linuxStandardServiceOwners.Delete(a)
		sessionTrackers.Delete(a)
	})
	return f
}

func (f *standardMonitorFixture) cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.o.stopMonitor(ctx); err != nil {
		return err
	}
	f.o.mu.Lock()
	defer f.o.mu.Unlock()
	f.a.mu.Lock()
	defer f.a.mu.Unlock()
	current, exists := linuxStandardServiceOwners.Load(f.a)
	if !exists || current != f.o || f.a.cmd != f.o.Command() {
		return errors.New("model cleanup refused another original owner")
	}
	f.stops.Add(1)
	f.o.joined = true
	linuxStandardServiceOwners.CompareAndDelete(f.a, f.o)
	f.a.cmd = nil
	f.a.state.Connected, f.a.state.Phase = false, "off"
	return nil
}

func (f *standardMonitorFixture) start(t *testing.T, probe func(context.Context) error, stop func() error) {
	t.Helper()
	if stop == nil {
		stop = f.cleanup
	}
	if err := f.o.activateMonitor(f.op, probe, stop); err != nil {
		t.Fatal("monitor activation", err)
	}
	raw, ok := linuxStandardServiceMonitors.Load(f.o)
	if !ok {
		t.Fatal("monitor was not retained")
	}
	f.m = raw.(*linuxStandardServiceMonitor)
}

func awaitStandardMonitor(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal(message)
	}
}

func TestLinuxStandardServiceMonitorChild(t *testing.T) {
	if os.Getenv("ROUTERVPN_STANDARD_MONITOR_CHILD") != "1" {
		return
	}
	fmt.Println("original-child-ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestLinuxStandardServiceMonitorObservesRealChildAfterRequestEnds(t *testing.T) {
	f := newStandardMonitorFixture(t)
	child := exec.Command(os.Args[0], "-test.run=^TestLinuxStandardServiceMonitorChild$")
	child.Env = append(os.Environ(), "ROUTERVPN_STANDARD_MONITOR_CHILD=1")
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "original-child-ready\n" {
		t.Fatal("actual original child did not start", line, err)
	}
	joined := make(chan struct{})
	go func() { _ = child.Wait(); close(joined) }()
	t.Cleanup(func() { _ = stdin.Close(); _ = child.Process.Kill(); <-joined })
	observed := make(chan struct{})
	var once sync.Once
	f.start(t, func(context.Context) error {
		select {
		case <-joined:
			return errors.New("actual original child joined")
		default:
			once.Do(func() { close(observed) })
			return nil
		}
	}, nil)
	f.finish()
	awaitStandardMonitor(t, observed, "completed Connect cancelled its retained monitor")
	if f.o.Command().Process != nil {
		t.Fatal("controller request fabricated an owned process")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	awaitStandardMonitor(t, joined, "actual original child did not join")
	awaitStandardMonitor(t, f.m.finished, "engine retirement left monitor running")
	if f.stops.Load() != 1 || f.a.state.Connected || f.a.state.Phase != "failed" || f.a.cmd != nil || f.m.observations.Load() == 0 {
		t.Fatal("actual engine exit retained Connected or lost exact cleanup", f.stops.Load(), f.a.state)
	}
}

func TestLinuxStandardServiceMonitorRejectsLateFailureOverReplacement(t *testing.T) {
	f := newStandardMonitorFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.start(t, func(context.Context) error { close(entered); <-release; return errors.New("late original failure") }, nil)
	f.finish()
	awaitStandardMonitor(t, entered, "original observation never entered")
	replacement := exec.Command("new-controller-runtime")
	f.a.mu.Lock()
	f.a.cmd = replacement
	f.a.state.RouterID, f.a.state.RuntimeMode, f.a.state.Phase = "new-router", "new-runtime", "connected"
	want := f.a.state
	f.a.mu.Unlock()
	linuxStandardServiceOwners.Store(f.a, &linuxStandardServiceLaunch{})
	once.Do(func() { close(release) })
	awaitStandardMonitor(t, f.m.finished, "late monitor did not join")
	if f.stops.Load() != 0 || f.a.cmd != replacement || f.a.state != want {
		t.Fatal("late service observation mutated replacement")
	}
}

func TestLinuxStandardServiceMonitorCancellationJoinsEnteredObservation(t *testing.T) {
	f := newStandardMonitorFixture(t)
	entered, release, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.start(t, func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return ctx.Err()
	}, nil)
	f.finish()
	awaitStandardMonitor(t, entered, "owned observation never entered")
	ctx, stop := context.WithTimeout(context.Background(), 40*time.Millisecond)
	err := f.o.stopMonitor(ctx)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Stop claimed join before entered observation returned", err)
	}
	awaitStandardMonitor(t, cancelled, "Stop did not revoke original observation")
	if f.o.copiesClosed || f.stops.Load() != 0 || f.a.cmd != f.o.Command() {
		t.Fatal("unjoined monitor discarded original cleanup authority")
	}
	once.Do(func() { close(release) })
	awaitStandardMonitor(t, f.m.finished, "cancelled observation did not join")
	retry, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	if err := f.o.stopMonitor(retry); err != nil || f.stops.Load() != 0 {
		t.Fatal("original joined cancellation could not be retried", err)
	}
}

func TestLinuxStandardServiceMonitorRechecksUnderOriginalTransaction(t *testing.T) {
	f := newStandardMonitorFixture(t)
	checked := make(chan struct{})
	var calls atomic.Int32
	f.start(t, func(context.Context) error {
		switch calls.Add(1) {
		case 1:
			return errors.New("transient first observation")
		case 2:
			close(checked)
		}
		return nil
	}, nil)
	f.finish()
	awaitStandardMonitor(t, checked, "monitor skipped its serialized final recheck")
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.o.stopMonitor(ctx); err != nil {
		t.Fatal(err)
	}
	awaitStandardMonitor(t, f.m.finished, "healthy final observation failed to join")
	if f.stops.Load() != 0 || !f.a.state.Connected || f.a.cmd != f.o.Command() {
		t.Fatal("healthy repeat observation retired original runtime")
	}
}

func TestLinuxStandardServiceMonitorPreservesOnlyPureObservationExpiry(t *testing.T) {
	for _, outcome := range []string{"pure-expiry", "mixed-runtime-failure"} {
		t.Run(outcome, func(t *testing.T) {
			t.Parallel()
			f := newStandardMonitorFixture(t)
			var calls atomic.Int32
			resumed := make(chan struct{})
			var resumedOnce sync.Once
			fault := errors.New("original runtime proof was independently lost")
			f.start(t, func(ctx context.Context) error {
				attempt := calls.Add(1)
				if attempt <= 2 {
					<-ctx.Done()
					if outcome == "mixed-runtime-failure" {
						return errors.Join(ctx.Err(), fault)
					}
					return fmt.Errorf("original observation: %w", ctx.Err())
				}
				resumedOnce.Do(func() { close(resumed) })
				return nil
			}, nil)
			f.finish()
			// Exercise two actual unchanged four-second observation budgets.
			// A single expired read followed by success would also pass the old
			// double-check-before-Stop code and would miss this regression.
			wait, cancel := context.WithTimeout(context.Background(), 13*time.Second)
			defer cancel()
			if outcome == "pure-expiry" {
				select {
				case <-resumed:
				case <-f.m.finished:
					t.Fatal("two expired reads retired the healthy original activation")
				case <-wait.Done():
					t.Fatal("expired original observation was never retried")
				}
				if err := f.o.stopMonitor(wait); err != nil {
					t.Fatal("explicit monitor cancellation failed", err)
				}
			}
			select {
			case <-f.m.finished:
			case <-wait.Done():
				t.Fatal("original monitor did not finish its owned operation")
			}
			if outcome == "pure-expiry" {
				if f.stops.Load() != 0 || !f.a.state.Connected || f.a.cmd != f.o.Command() || f.m.observations.Load() != 1 {
					t.Fatal("read expiry changed the engine or was counted as successful proof", f.stops.Load(), f.m.observations.Load(), f.a.state)
				}
			} else if f.stops.Load() != 1 || f.a.state.Connected || f.a.state.Phase != "failed" || f.m.observations.Load() != 0 {
				t.Fatal("cancellation hid the independently witnessed runtime failure", f.stops.Load(), f.a.state)
			}
		})
	}
}

func TestLinuxStandardServiceMonitorFailureRetainsRetryOwner(t *testing.T) {
	f := newStandardMonitorFixture(t)
	f.start(t, func(context.Context) error { return errors.New("original native proof lost") }, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.o.stopMonitor(ctx); err != nil {
			return err
		}
		f.stops.Add(1)
		return errors.New("original retirement was not acknowledged")
	})
	f.finish()
	awaitStandardMonitor(t, f.m.finished, "monitor Stop self-joined or failed to terminate")
	owner, exists := linuxStandardServiceOwners.Load(f.a)
	if f.stops.Load() != 1 || !exists || owner != f.o || f.a.cmd != f.o.Command() || f.o.joined || f.o.copiesClosed ||
		f.a.state.Connected || f.a.state.Phase != "failed" || !strings.Contains(f.a.state.LastError, "cleanup remains pending") {
		t.Fatal("failed retirement was erased or retained Connected", f.a.state)
	}
}

func TestLinuxStandardServiceMonitorSourceMutationRetiresOnlyOriginal(t *testing.T) {
	f := newStandardMonitorFixture(t)
	var probes atomic.Int32
	f.start(t, func(context.Context) error { probes.Add(1); return nil }, nil)
	f.finish()
	f.a.mu.Lock()
	f.a.profiles.Profiles[0].DNSHost = "9.9.9.9"
	f.a.mu.Unlock()
	awaitStandardMonitor(t, f.m.finished, "changed saved source retained old activation")
	if f.stops.Load() != 1 || probes.Load() != 0 || f.a.state.Connected {
		t.Fatal("monitor borrowed changed profile or ran ambient proof")
	}
}

func TestLinuxStandardServiceMonitorRejectsUnprovedOrRepeatedActivation(t *testing.T) {
	for _, fault := range []string{"dns", "joined", "unattempted", "wrong-operation", "foreign-runtime", "foreign-tracker"} {
		t.Run(fault, func(t *testing.T) {
			f := newStandardMonitorFixture(t)
			switch fault {
			case "dns":
				f.o.dnsProved = false
			case "joined":
				f.o.joined = true
			case "unattempted":
				f.o.attempted = false
			case "wrong-operation":
				f.a.connectionContext = context.Background()
			case "foreign-runtime":
				f.a.cmd = exec.Command("foreign")
			case "foreign-tracker":
				sessionTrackers.Delete(f.a)
			}
			if err := f.o.activateMonitor(f.op, func(context.Context) error { t.Error("unproved observer ran"); return nil }, f.cleanup); err == nil {
				t.Fatal("unproved or foreign activation acquired a monitor")
			}
		})
	}
	f := newStandardMonitorFixture(t)
	f.start(t, func(context.Context) error { return nil }, nil)
	if err := f.o.activateMonitor(f.op, func(context.Context) error { return nil }, f.cleanup); err == nil {
		t.Fatal("second activation replaced original monitor")
	}
}

// This adapter isolates the real shipping handler's activation ordering. It
// starts no engine and supplies no native proof; those separate service tests
// retain the actual process, peer and kernel requirements.
type standardMonitorRouteOwner struct {
	a        *app
	command  *exec.Cmd
	activate func(context.Context) error
}

func (o *standardMonitorRouteOwner) Command() *exec.Cmd { return o.command }
func (o *standardMonitorRouteOwner) Start(context.Context) error {
	o.a.mu.Lock()
	defer o.a.mu.Unlock()
	o.a.cmd = o.command
	legacyStandardExitOwners.Store(o.a, o)
	return nil
}
func (o *standardMonitorRouteOwner) Current(context.Context) error { return nil }
func (o *standardMonitorRouteOwner) Discard() error                { return nil }
func (o *standardMonitorRouteOwner) ActivateMonitor(ctx context.Context) error {
	return o.activate(ctx)
}

func TestLinuxStandardServiceMonitorShippingActivationOrderAndRefusal(t *testing.T) {
	for _, outcome := range []string{"active", "monitor-refused", "persistence-failed"} {
		t.Run(outcome, func(t *testing.T) {
			f := newLegacyExitFixture(t, "off")
			t.Cleanup(func() { legacyStandardExitOwners.Delete(f.a) })
			proofs, activations := 0, 0
			var original *standardMonitorRouteOwner
			adapter := platformStandardExitRuntime{
				prepareLegacy: func(a *app, command *exec.Cmd, _, _, _ string) (legacyStandardExitLaunch, error) {
					original = &standardMonitorRouteOwner{a: a, command: command}
					original.activate = func(ctx context.Context) error {
						activations++
						a.mu.Lock()
						ready := proofs == 1 && a.cmd == command && command.Process == nil && a.connectionContext == ctx && a.state.Connected && a.state.Phase == "connected"
						a.mu.Unlock()
						if !ready {
							return errors.New("shipping monitor preceded exact proved connection")
						}
						if outcome == "monitor-refused" {
							return errors.New("original activation was refused")
						}
						return nil
					}
					return original, nil
				},
				prove: func(*app, string) error { proofs++; return nil },
				current: func(owner legacyStandardExitLaunch, ctx context.Context) error {
					if outcome == "persistence-failed" {
						// An existing directory cannot be replaced by the profile file.
						f.a.cfg.ProfilesFile = f.root
					}
					return owner.Current(ctx)
				},
			}
			body, _ := json.Marshal(standardExitConnectRequest{StandardExitID: f.exit.ID, Direct: true})
			response := httptest.NewRecorder()
			f.a.platformStandardExitConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(body)), adapter)
			switch outcome {
			case "active":
				if response.Code != http.StatusOK || activations != 1 || !f.a.state.Connected {
					t.Fatal("shipping route omitted or misplaced monitor activation", response.Code, activations, response.Body.String())
				}
			case "monitor-refused":
				retained, exists := legacyStandardExitOwners.Load(f.a)
				if response.Code != http.StatusInternalServerError || activations != 1 || f.a.state.Connected || f.a.state.Phase != "failed" || !exists || retained != original || !strings.Contains(response.Body.String(), "runtime cleanup failed") {
					t.Fatal("refused monitor retained Connected or discarded unjoined cleanup", response.Code, activations, f.a.state, response.Body.String())
				}
			case "persistence-failed":
				if response.Code != http.StatusInternalServerError || activations != 0 {
					t.Fatal("monitor started before final profile persistence", response.Code, activations, response.Body.String())
				}
			}
		})
	}
}
