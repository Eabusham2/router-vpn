//go:build linux && go1.25

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
)

// This models native Current and Stop only. The exact retained captures,
// monitor, app mutex, cancellation and join logic are the shipping code. It
// does not invoke native Activate or manufacture a successful TUN observation;
// the installed-host app-connect gate exercises those separate boundaries.
type linuxNodeMonitorFixture struct {
	a       *app
	p       *desktopLinuxNodeParent
	s       *desktopLinuxNodeSession
	h       *desktopLinuxNodeHost
	m       *desktopLinuxNodeMonitor
	finish  context.CancelFunc
	running bool
	reads   atomic.Uint64
	stops   atomic.Uint64
	broken  atomic.Bool
	stopErr error
}

// synctest's synthetic wall clock carries no monotonic component. Capture a
// real original timestamp before entering any bubble; the production owner
// comparison must keep rejecting serialized/nonmonotonic activation records.
var linuxNodeMonitorFixtureMonotonic = time.Now()

func newLinuxNodeMonitorFixture(t *testing.T) *linuxNodeMonitorFixture {
	t.Helper()
	h, finish := linuxNodeActivationCaptureModel(t)
	h.proof.provedAt = linuxNodeMonitorFixtureMonotonic.Add(-time.Millisecond)
	h.activation.proof = *h.proof
	h.activation.activatedAt = linuxNodeMonitorFixtureMonotonic
	h.monitor = &atomic.Pointer[desktopLinuxNodeMonitor]{}
	h.gate = make(chan struct{}, 1)
	h.gate <- struct{}{}
	h.launch.mode = "wg"
	a := &app{cfg: common.ClientConfig{
		ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
		ModesFile:    filepath.Join(linuxOwnedControllerRoot, "modes.json"),
		ScriptsDir:   filepath.Join(linuxOwnedControllerRoot, "modes"),
		StateFile:    filepath.Join(linuxOwnedControllerRoot, "state.json")},
		cmd: h.launch.command, state: state{Connected: true, Phase: "connected", RouterID: h.launch.profileID, RuntimeMode: h.launch.mode}}
	p := &desktopLinuxNodeParent{gate: make(chan struct{}, 1), ctx: h.parent.lifetime, complete: true,
		dependents: make(map[ownedDesktopNodeParent]struct{})}
	p.gate <- struct{}{}
	controller := &ownedDesktopController{nodeParent: p}
	p.controller, a.localController = controller, controller
	h.parent.app, h.parent.controller, h.parent.parent = a, controller, p
	s := &desktopLinuxNodeSession{gate: make(chan struct{}, 1), parent: h.parent, active: h,
		journal: &desktopLinuxNodeJournal{parent: h.parent}}
	s.gate <- struct{}{}
	p.session, p.dependents[s], p.dependents[h] = s, struct{}{}, struct{}{}
	h.transaction.journal = s.journal
	f := &linuxNodeMonitorFixture{a: a, p: p, s: s, h: h, finish: finish}
	m, err := newDesktopLinuxNodeMonitor(s, h, func(context.Context) error {
		f.reads.Add(1)
		if f.broken.Load() {
			return errors.New("modeled original native proof failed")
		}
		return nil
	}, func() error { return f.stop(t) })
	if err != nil {
		t.Fatal(err)
	}
	f.m = m
	h.monitor.Store(m)
	sessionTrackers.Store(a, &sessionTracker{a: a})
	return f
}

func (f *linuxNodeMonitorFixture) start() { f.running = true; go f.m.run() }

func (f *linuxNodeMonitorFixture) close(t *testing.T) {
	t.Helper()
	f.m.cancel()
	f.finish()
	if f.running {
		select {
		case <-f.m.finished:
		case <-time.After(3 * time.Second):
			t.Error("original Linux monitor goroutine was not joined")
		}
	}
	desktopNodeOwners.Delete(f.a)
	sessionTrackers.Delete(f.a)
}

func (f *linuxNodeMonitorFixture) stop(t *testing.T) error {
	t.Helper()
	f.stops.Add(1)
	select {
	case <-f.m.watchDone:
	default:
		t.Error("monitor entered Stop before joining its observation loop")
		return errors.New("observer not joined before Stop")
	}
	if f.a.operationMu.TryLock() {
		f.a.operationMu.Unlock()
		t.Error("monitor entered Stop without its exact serialized operation")
		return errors.New("missing operation owner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := f.h.stopMonitorBeforeRetirement(ctx); err != nil {
		t.Error("monitor could not join itself before native retirement", err)
		return err
	}
	if f.stopErr != nil {
		return f.stopErr
	}
	// Modeled native retirement retains this exact selected closed predecessor.
	if err := f.s.enter(ctx); err != nil {
		return err
	}
	if err := f.h.enter(ctx); err != nil {
		f.s.gate <- struct{}{}
		return err
	}
	f.s.active, f.s.predecessor = nil, f.h.transaction
	f.h.closed, f.h.released = true, true
	f.h.gate <- struct{}{}
	f.s.gate <- struct{}{}
	f.a.mu.Lock()
	f.a.cmd = nil
	f.a.state.Connected, f.a.state.Phase, f.a.state.RuntimeMode = false, "off", ""
	f.a.mu.Unlock()
	return nil
}

func requireLinuxMonitorAlive(t *testing.T, f *linuxNodeMonitorFixture) {
	t.Helper()
	if f.stops.Load() != 0 || f.m.ctx.Err() != nil || f.h.monitor.Load() != f.m {
		t.Fatal("original active Linux monitor was retired or replaced")
	}
	select {
	case <-f.m.watchDone:
		t.Fatal("original active Linux monitor silently ended observation")
	default:
	}
}

func TestDesktopLinuxNodeMonitorActivationLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		f.start()
		synctest.Wait()
		f.finish()
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		requireLinuxMonitorAlive(t, f)
		if f.h.operation.Err() != context.Canceled || f.m.observations.Load() == 0 || f.reads.Load() == 0 {
			t.Fatal("startup completion cancelled the independent active observation")
		}
	})
}

func TestDesktopLinuxNodeMonitorConfirmedFailure(t *testing.T) {
	for _, scenario := range []string{"native-proof", "original-child-exit", "retirement-error"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newLinuxNodeMonitorFixture(t)
				defer f.close(t)
				if scenario == "original-child-exit" {
					close(f.h.process.joined)
				} else {
					f.broken.Store(true)
				}
				if scenario == "retirement-error" {
					f.stopErr = errors.New("original kernel retirement unavailable")
				}
				f.start()
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				if f.stops.Load() != 1 || f.m.ctx.Err() == nil || !f.h.closing {
					t.Fatal("confirmed original proof loss did not retire the exact monitor")
				}
				select {
				case <-f.m.finished:
				default:
					t.Fatal("confirmed failure retained unfinished monitor work")
				}
				f.a.mu.Lock()
				actual, command := f.a.state, f.a.cmd
				f.a.mu.Unlock()
				if actual.Connected || actual.Phase != "failed" || !strings.Contains(actual.LastError, "lost its proof") {
					t.Fatal("current original failure was not reported", actual)
				}
				if f.stopErr == nil {
					if command != nil || f.s.predecessor != f.h.transaction || !strings.Contains(actual.LastError, "exact protection is held") {
						t.Fatal("monitor lost the modeled exact held predecessor")
					}
				} else if command != f.m.command || !strings.Contains(actual.LastError, f.stopErr.Error()) || strings.Contains(actual.LastError, "exact protection is held") {
					t.Fatal("monitor converted failed retirement into successful protection evidence")
				}
				if !f.a.operationMu.TryLock() {
					t.Fatal("monitor did not release its completed app operation")
				}
				f.a.operationMu.Unlock()
			})
		})
	}
}

func TestDesktopLinuxNodeMonitorTransientObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		f.m.currentLocked = func(context.Context) error {
			if f.reads.Add(1) == 1 {
				return errors.New("first native observation unavailable")
			}
			return nil
		}
		f.start()
		time.Sleep(time.Second)
		synctest.Wait()
		requireLinuxMonitorAlive(t, f)
		if f.reads.Load() < 3 || f.m.observations.Load() < 2 {
			t.Fatal("healthy final read ended or failed to resume the same observer")
		}
	})
}

func TestDesktopLinuxNodeMonitorBusyOperationAndCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		f.broken.Store(true)
		f.a.operationMu.Lock()
		f.start()
		time.Sleep(time.Second)
		synctest.Wait()
		requireLinuxMonitorAlive(t, f)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := f.h.stopMonitorBeforeRetirement(ctx); err != nil {
			t.Fatal("ordinary Stop could not revoke its queued monitor", err)
		}
		f.a.operationMu.Unlock()
		time.Sleep(time.Second)
		synctest.Wait()
		if f.stops.Load() != 0 {
			t.Fatal("cancelled queued monitor later acquired Stop authority")
		}
	})
}

func TestDesktopLinuxNodeMonitorReplacedCapture(t *testing.T) {
	for _, scenario := range []string{"command", "session-host", "parent-session", "controller", "activation", "process", "transaction", "launch", "journal", "host-registration", "parent-stopping", "app-closing", "duplicate-owner"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newLinuxNodeMonitorFixture(t)
				defer f.close(t)
				f.broken.Store(true)
				switch scenario {
				case "command":
					f.a.cmd = &exec.Cmd{}
				case "session-host":
					f.s.active = &desktopLinuxNodeHost{}
				case "parent-session":
					f.p.session = &desktopLinuxNodeSession{}
				case "controller":
					f.a.localController = &ownedDesktopController{}
				case "activation":
					f.h.activation = &desktopLinuxNodeActivation{}
				case "process":
					f.h.process = &desktopLinuxNodeProcess{}
				case "transaction":
					f.h.transaction = &desktopLinuxNodeTransaction{}
				case "launch":
					f.h.launch = &desktopNodeLaunch{}
				case "journal":
					f.s.journal = &desktopLinuxNodeJournal{}
				case "host-registration":
					delete(f.p.dependents, f.h)
				case "parent-stopping":
					f.p.stopping = true
				case "app-closing":
					f.a.closing = true
				case "duplicate-owner":
					desktopNodeOwners.Store(f.a, &desktopNodeLaunch{})
				}
				f.a.state.LastError = "replacement state"
				f.start()
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				if f.stops.Load() != 0 || f.a.state.LastError != "replacement state" || !f.a.state.Connected {
					t.Fatal("stale observer stopped or overwrote a replacement")
				}
				select {
				case <-f.m.finished:
				default:
					t.Fatal("stale observer retained a foreign capture")
				}
			})
		})
	}
}

func TestDesktopLinuxNodeMonitorRevalidatesObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		f.m.currentLocked = func(context.Context) error {
			f.a.mu.Lock()
			f.a.cmd = &exec.Cmd{}
			f.a.state.LastError = "replacement during native read"
			f.a.mu.Unlock()
			return errors.New("old native failure")
		}
		f.start()
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if f.stops.Load() != 0 || f.m.observations.Load() != 0 || f.a.state.LastError != "replacement during native read" {
			t.Fatal("old native completion obtained replacement Stop or observation authority")
		}
	})
}

func TestDesktopLinuxNodeMonitorPreservesReplacementAfterStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		f.broken.Store(true)
		replacement := &exec.Cmd{}
		f.m.stop = func() error {
			f.stops.Add(1)
			f.a.mu.Lock()
			f.a.cmd = replacement
			f.a.state.LastError = "replacement after old Stop"
			f.a.mu.Unlock()
			return errors.New("old Stop failed")
		}
		f.start()
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if f.stops.Load() != 1 || f.a.cmd != replacement || f.a.state.LastError != "replacement after old Stop" || !f.a.state.Connected {
			t.Fatal("old Stop completion overwrote the replacement presentation")
		}
	})
}

func TestDesktopLinuxNodeMonitorJoinsBlockedObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		entered, left := make(chan struct{}), make(chan struct{})
		f.m.currentLocked = func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			select {
			case <-f.h.gate:
				t.Error("entered native observation did not retain its host gate")
				f.h.gate <- struct{}{}
			default:
			}
			close(left)
			return ctx.Err()
		}
		f.start()
		time.Sleep(500 * time.Millisecond)
		<-entered
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := f.h.stopMonitorBeforeRetirement(ctx); err != nil {
			t.Fatal("retirement failed to cancel and join the original observation", err)
		}
		select {
		case <-left:
		default:
			t.Fatal("retirement passed the original observer before its cleanup joined")
		}
		synctest.Wait()
		if f.stops.Load() != 0 || f.m.observations.Load() != 0 {
			t.Fatal("cancelled observation became native success or a second Stop")
		}
	})
}

func TestDesktopLinuxNodeMonitorRetirementRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		entered, release := make(chan struct{}), make(chan struct{})
		f.m.currentLocked = func(ctx context.Context) error { close(entered); <-release; return ctx.Err() }
		f.start()
		time.Sleep(500 * time.Millisecond)
		<-entered
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := f.h.stopMonitorBeforeRetirement(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || f.h.monitor.Load() != f.m || f.m.ctx.Err() == nil {
			t.Fatal("unjoined observation was discarded or falsely reported complete", err)
		}
		select {
		case <-f.m.watchDone:
			t.Fatal("retirement fabricated a joined blocked observation")
		default:
		}
		close(release)
		synctest.Wait()
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.h.stopMonitorBeforeRetirement(ctx); err != nil || f.stops.Load() != 0 || !f.h.closing {
			t.Fatal("original-owner retirement retry did not join the same observer", err)
		}
	})
}

func TestDesktopLinuxNodeMonitorGateContention(t *testing.T) {
	for _, name := range []string{"session", "host", "parent"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newLinuxNodeMonitorFixture(t)
				defer f.close(t)
				gate := f.s.gate
				if name == "host" {
					gate = f.h.gate
				} else if name == "parent" {
					gate = f.p.gate
				}
				<-gate
				held := true
				defer func() {
					if held {
						gate <- struct{}{}
					}
				}()
				f.start()
				time.Sleep(5 * time.Second) // Longer than the unchanged four-second observation bound.
				synctest.Wait()
				requireLinuxMonitorAlive(t, f)
				if f.reads.Load() != 0 || f.m.observations.Load() != 0 {
					t.Fatal("gate contention became an entered native observation")
				}
				gate <- struct{}{}
				held = false
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				requireLinuxMonitorAlive(t, f)
				if f.m.observations.Load() == 0 {
					t.Fatal("legitimate gate contention silently ended the retained observer")
				}
			})
		})
	}
}

func TestDesktopLinuxNodeMonitorCancelGateWait(t *testing.T) {
	for _, name := range []string{"session", "host", "parent"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newLinuxNodeMonitorFixture(t)
				defer f.close(t)
				gate := f.s.gate
				if name == "host" {
					gate = f.h.gate
				} else if name == "parent" {
					gate = f.p.gate
				}
				<-gate
				defer func() { gate <- struct{}{} }()
				f.start()
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				f.m.cancel()
				synctest.Wait()
				select {
				case <-f.m.finished:
				default:
					t.Fatal("cancelled gate wait retained monitor work")
				}
				if f.stops.Load() != 0 || f.m.observations.Load() != 0 {
					t.Fatal("cancelled gate wait obtained native evidence or Stop authority")
				}
			})
		})
	}
}

func TestDesktopLinuxNodeMonitorEnteredProofTimeout(t *testing.T) {
	for _, name := range []string{"explicit-error", "late-nil"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newLinuxNodeMonitorFixture(t)
				defer f.close(t)
				f.m.currentLocked = func(ctx context.Context) error {
					f.reads.Add(1)
					<-ctx.Done()
					if name == "late-nil" {
						return nil
					}
					return ctx.Err()
				}
				f.start()
				time.Sleep(9 * time.Second)
				synctest.Wait()
				if f.stops.Load() != 1 || f.reads.Load() != 2 || f.m.observations.Load() != 0 || f.a.state.Connected {
					t.Fatal("entered native proof timeout retained Connected or fabricated successful observation")
				}
			})
		})
	}
}

func TestDesktopLinuxNodeMonitorJoinReleasesHostGate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		// Model a retained observer's final cleanup needing the host gate. The
		// shipping retirement hook must cancel, release that gate, then join.
		f.running = true
		go func() {
			defer close(f.m.finished)
			defer close(f.m.watchDone)
			<-f.m.ctx.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := f.h.enter(ctx); err != nil {
				t.Error("observer cleanup blocked behind retirement's host gate", err)
				return
			}
			f.h.gate <- struct{}{}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := f.h.stopMonitorBeforeRetirement(ctx); err != nil {
			t.Fatal("retirement held the observer's gate while waiting for its join", err)
		}
	})
}

func TestDesktopLinuxNodeMonitorForeignRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newLinuxNodeMonitorFixture(t)
		defer f.close(t)
		f.start()
		synctest.Wait()
		foreign := *f.h // Intentional foreign host, including the original immutable holder.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := foreign.stopMonitorBeforeRetirement(ctx); err == nil {
			t.Fatal("copied foreign host acquired original monitor cancellation")
		}
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		requireLinuxMonitorAlive(t, f)
		if f.m.observations.Load() == 0 || f.h.closing {
			t.Fatal("foreign retirement changed the original active host")
		}
	})
}

func TestDesktopLinuxNodeMonitorRejectsStartupReplay(t *testing.T) {
	for _, name := range []string{"readiness", "proof", "activation"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newLinuxNodeMonitorFixture(t)
				defer f.close(t)
				proof, active, ready := f.h.proof, f.h.activation, f.h.ready
				proofValue, readyValue := *proof, *ready
				f.start()
				f.finish()
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				before := f.m.observations.Load()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				var err error
				switch name {
				case "readiness":
					_, err = f.h.WaitReady(ctx)
				case "proof":
					_, err = f.h.Prove(ctx)
				case "activation":
					err = f.h.Activate(ctx)
				}
				if err == nil {
					t.Fatal("replayed startup acquired an already active host")
				}
				if f.h.proof != proof || f.h.ready != ready || f.h.activation != active ||
					*proof != proofValue || *ready != readyValue || active.matches(f.h) != nil ||
					f.h.closing || f.h.closed || f.m.ctx.Err() != nil {
					t.Fatal("replayed startup mutated active proof or observer")
				}
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				requireLinuxMonitorAlive(t, f)
				if before == 0 || f.m.observations.Load() <= before || f.a.cmd != f.m.command || !f.a.state.Connected {
					t.Fatal("rejected startup replay stopped the original monitored connection")
				}
			})
		})
	}
}
