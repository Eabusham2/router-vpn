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

// Exercise the same serial poll used by run with an explicit short caller.
// This fixture supplies no native acceptance; the retained service and process
// tests separately cover those boundaries.
func standardMonitorPollFixture(t *testing.T) *standardMonitorFixture {
	t.Helper()
	f := newStandardMonitorFixture(t)
	raw, _ := sessionTrackers.Load(f.a)
	ctx, cancel := context.WithCancel(context.Background())
	m := &linuxStandardServiceMonitor{owner: f.o, app: f.a, prepared: f.o.prepared, dns: f.o.prepared.dns, command: f.o.Command(), request: f.o.request, tracker: raw.(*sessionTracker), profileToken: f.o.prepared.dns.profileToken, ctx: ctx, cancel: cancel, watchDone: make(chan struct{}), finished: make(chan struct{}), probe: func(context.Context) error { return nil }, stop: f.cleanup}
	f.m = m
	close(m.finished) // This fixture calls the original serial poll synchronously.
	linuxStandardServiceMonitors.Store(f.o, m)
	t.Cleanup(func() { m.endWatch(); linuxStandardServiceMonitors.CompareAndDelete(f.o, m) })
	f.finish()
	return f
}

func TestLinuxStandardServiceMonitorObservationExpiryKeepsProvedOwner(t *testing.T) {
	for _, scenario := range []string{"owner-lock", "selection-lock", "source-lock", "probe-expiry", "late-success", "final-selection-lock", "transaction-lock"} {
		t.Run(scenario, func(t *testing.T) {
			f := standardMonitorPollFixture(t)
			m := f.m
			var deadline time.Time
			var unlock func()
			entered := make(chan struct{})
			switch scenario {
			case "owner-lock":
				f.o.mu.Lock()
				unlock = f.o.mu.Unlock
			case "selection-lock", "source-lock", "transaction-lock":
				f.a.mu.Lock()
				unlock = f.a.mu.Unlock
			case "probe-expiry", "late-success", "final-selection-lock":
				if scenario == "final-selection-lock" {
					unlock = func() {
						select {
						case <-entered:
							f.a.mu.Unlock()
						default:
						}
					}
				}
				m.probe = func(call context.Context) error {
					got, _ := call.Deadline()
					if !got.Equal(deadline) {
						t.Error("monitor replaced original observer deadline")
					}
					if scenario == "final-selection-lock" {
						f.a.mu.Lock()
						close(entered)
					}
					<-call.Done()
					if scenario == "probe-expiry" {
						return call.Err()
					}
					return nil
				}
			}
			var once sync.Once
			release := func() {
				once.Do(func() {
					if unlock != nil {
						unlock()
					}
				})
			}
			defer release()
			type result struct {
				keep     bool
				err      error
				admitted bool
			}
			done := make(chan result, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				deadline, _ = ctx.Deadline()
				outcome := result{keep: true}
				if scenario == "source-lock" {
					f.o.mu.Lock()
					outcome.err = m.sourceLocked(ctx)
					f.o.mu.Unlock()
				} else if scenario == "transaction-lock" {
					unlock, _, err := m.claimOperation(ctx)
					outcome.err = err
					outcome.admitted = unlock != nil
					if unlock != nil {
						unlock()
					}
				} else {
					outcome.keep = m.poll(ctx)
				}
				done <- outcome
			}()
			var outcome result
			select {
			case outcome = <-done:
			case <-time.After(time.Second):
				release()
				<-done
				t.Fatal("monitor observation waited beyond its original caller on a retained lock")
			}
			release()
			if scenario == "source-lock" || scenario == "transaction-lock" {
				if !errors.Is(outcome.err, context.DeadlineExceeded) || outcome.admitted {
					t.Fatal("monitor lock lost original deadline", outcome.err)
				}
			}
			if !outcome.keep || m.ctx.Err() != nil || m.pendingLoss != nil || f.stops.Load() != 0 || !f.a.state.Connected || f.a.cmd != m.command || m.observations.Load() != 0 {
				t.Fatal("pure observation expiry retired, invalidated or adopted over a proved owner", scenario)
			}
			m.probe = func(context.Context) error { return nil }
			retry, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if !m.poll(retry) || m.observations.Load() != 1 || f.stops.Load() != 0 {
				t.Fatal("healthy original owner could not be observed after expiry")
			}
		})
	}
}

func TestLinuxStandardServiceMonitorMixedExpiryKeepsOriginalRetirement(t *testing.T) {
	for _, scenario := range []string{"mixed-probe", "changed-source", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f := standardMonitorPollFixture(t)
			m := f.m
			calls := 0
			replacement := exec.Command("replacement-monitor-runtime")
			realLoss := errors.New("original native proof failed")
			m.probe = func(ctx context.Context) error {
				calls++
				<-ctx.Done()
				if scenario == "changed-source" {
					m.dns.profileToken = "changed-source"
					return ctx.Err()
				}
				if scenario == "replacement" {
					f.a.mu.Lock()
					f.a.cmd = replacement
					f.a.mu.Unlock()
				}
				return errors.Join(ctx.Err(), realLoss)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if m.poll(ctx) {
				t.Fatal("confirmed original loss did not finish its monitor")
			}
			if calls != 1 {
				t.Fatal("expired native read was retried to erase real loss", calls)
			}
			if scenario == "replacement" {
				if f.stops.Load() != 0 || f.a.cmd != replacement || !f.a.state.Connected {
					t.Fatal("late mixed failure retired replacement")
				}
			} else if f.stops.Load() != 1 || f.a.state.Connected || f.a.state.Phase != "failed" || f.a.cmd != nil {
				t.Fatal("mixed failure lost original cleanup or failure publication", f.stops.Load(), f.a.state)
			}
		})
	}
}

func TestLinuxStandardServiceMonitorActivationKeepsExactIntentAndDeadline(t *testing.T) {
	for _, scenario := range []string{"owner-lock", "app-lock", "derived-intent"} {
		t.Run(scenario, func(t *testing.T) {
			f := newStandardMonitorFixture(t)
			duration := 20 * time.Millisecond
			if scenario == "derived-intent" {
				duration = time.Second
			}
			ctx, cancel := context.WithTimeout(f.op, duration)
			defer cancel()
			if scenario != "derived-intent" {
				f.a.connectionContext = ctx
			}
			var unlock func()
			if scenario == "owner-lock" {
				f.o.mu.Lock()
				unlock = f.o.mu.Unlock
			}
			if scenario == "app-lock" {
				f.a.mu.Lock()
				unlock = f.a.mu.Unlock
			}
			var once sync.Once
			release := func() {
				once.Do(func() {
					if unlock != nil {
						unlock()
					}
				})
			}
			defer release()
			done := make(chan error, 1)
			go func() {
				done <- f.o.activateMonitor(ctx, func(context.Context) error { t.Error("unadmitted monitor observed native runtime"); return nil }, f.cleanup)
			}()
			var err error
			select {
			case err = <-done:
			case <-time.After(time.Second):
				release()
				<-done
				t.Fatal("monitor activation ignored its original caller deadline")
			}
			release()
			f.a.connectionContext = f.op
			if err == nil {
				t.Fatal("expired or derived activation acquired original monitor")
			}
			if scenario != "derived-intent" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("activation lost original caller deadline", err)
			}
			if _, exists := linuxStandardServiceMonitors.Load(f.o); exists {
				t.Fatal("failed activation published monitor")
			}
		})
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

func TestLinuxStandardServiceMonitorBoundsApplicationMetadataLocks(t *testing.T) {
	t.Run("observation", func(t *testing.T) {
		t.Parallel()
		f := newStandardMonitorFixture(t)
		lifetime, cancel := context.WithCancel(context.Background())
		defer cancel()
		tracker, _ := sessionTrackers.Load(f.a)
		var probes atomic.Int32
		m := &linuxStandardServiceMonitor{owner: f.o, app: f.a, prepared: f.o.prepared, dns: f.o.prepared.dns, command: f.o.Command(), request: f.o.request, tracker: tracker.(*sessionTracker), profileToken: f.o.prepared.dns.profileToken, ctx: lifetime, probe: func(context.Context) error { probes.Add(1); return nil }}
		f.a.mu.Lock()
		locked := true
		defer func() {
			if locked {
				f.a.mu.Unlock()
			}
		}()
		type observed struct {
			err      error
			selected bool
		}
		done := make(chan observed, 1)
		observation, stopObservation := context.WithTimeout(lifetime, 4*time.Second)
		defer stopObservation()
		go func() { err, selected := m.observe(observation); done <- observed{err, selected} }()
		select {
		case result := <-done:
			if !errors.Is(result.err, context.DeadlineExceeded) || result.selected {
				t.Fatalf("blocked initial selection lost its original deadline: %+v", result)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("real observation remained queued on application metadata after its four-second budget")
		}
		if probes.Load() != 0 || m.observations.Load() != 0 || f.stops.Load() != 0 || !f.a.state.Connected || f.a.state.LastError != "" {
			t.Fatal("expired metadata read probed, published, disconnected, or claimed success")
		}
		f.a.mu.Unlock()
		locked = false
		retry, stopRetry := context.WithTimeout(lifetime, time.Second)
		defer stopRetry()
		if err, selected := m.observe(retry); err != nil || !selected || m.observations.Load() != 1 {
			t.Fatalf("same original monitor could not retry: %v %v", err, selected)
		}
	})
	t.Run("retained-watch", func(t *testing.T) {
		t.Parallel()
		f := newStandardMonitorFixture(t)
		resumed := make(chan struct{})
		var once sync.Once
		f.start(t, func(context.Context) error { once.Do(func() { close(resumed) }); return nil }, nil)
		f.finish()
		f.a.mu.Lock()
		locked := true
		defer func() {
			if locked {
				f.a.mu.Unlock()
			}
		}()
		// The first real periodic observation must exhaust its unchanged four-second
		// budget while this mutex remains held. Its original watch must survive.
		select {
		case <-f.m.finished:
			t.Fatal("metadata expiry ended the original watch")
		case <-time.After(5 * time.Second):
		}
		if f.stops.Load() != 0 || f.m.observations.Load() != 0 || !f.a.state.Connected || f.a.state.LastError != "" {
			t.Fatal("blocked metadata read changed activation or counted success")
		}
		f.a.mu.Unlock()
		locked = false
		awaitStandardMonitor(t, resumed, "original watch did not retry after metadata lock was released")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.o.stopMonitor(ctx); err != nil {
			t.Fatal(err)
		}
		awaitStandardMonitor(t, f.m.finished, "original watch did not join")
		if f.stops.Load() != 0 || !f.a.state.Connected || f.a.state.LastError != "" {
			t.Fatal("metadata timeout published failure or disconnected original activation")
		}
	})
	t.Run("activation", func(t *testing.T) {
		f := newStandardMonitorFixture(t)
		operation, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		f.a.mu.Lock()
		f.a.connectionContext = operation
		done := make(chan error, 1)
		go func() { done <- f.o.activateMonitor(operation, func(context.Context) error { return nil }, f.cleanup) }()
		var err error
		select {
		case err = <-done:
		case <-time.After(time.Second):
			f.a.mu.Unlock()
			t.Fatal("activation ignored original caller while waiting for metadata")
		}
		f.a.mu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("activation lost deadline: %v", err)
		}
		if _, exists := linuxStandardServiceMonitors.Load(f.o); exists {
			t.Fatal("expired activation published an original monitor")
		}
	})
}
