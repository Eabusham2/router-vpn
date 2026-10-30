package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The compiler, captured private files, monitor, and Stop transaction are real.
// This fixture models only the child/Job and kernel boundaries; it cannot prove
// Windows execution. Its wait remains blocked until that same child exits.
type desktopOwnedNodeMonitorProcess struct {
	*desktopOwnedNodeTestProcess
	exited chan struct{}
	once   sync.Once
}

func (p *desktopOwnedNodeMonitorProcess) signalExit() { p.once.Do(func() { close(p.exited) }) }
func (p *desktopOwnedNodeMonitorProcess) Wait(ctx context.Context) (uint32, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-p.exited:
		return 0, nil
	}
}
func (p *desktopOwnedNodeMonitorProcess) Close(ctx context.Context) error {
	if err := p.desktopOwnedNodeTestProcess.Close(ctx); err != nil {
		return err
	}
	p.signalExit()
	return nil
}

func newDesktopOwnedNodeMonitorFixture(t *testing.T) (*desktopOwnedNodeTestFixture, *desktopOwnedNodeMonitorProcess) {
	t.Helper()
	profile, files := desktopNodeFixture(t, "198.51.100.8")
	profile.KillSwitch, profile.KillSwitchPolicy = true, "always"
	// Fixed policy keeps a Stop-release from starting an unrelated automatic
	// measurement. The live lease records below still exercise real MTU parsing.
	profile.MTUPolicy, profile.ManualMTU = "manual", 1420
	original, _, err := compileDesktopNode(context.Background(), profile, "wg", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := desktopOwnedNodeTestCapture(t, nil, &desktopNodeProtectionFixture{}, profile, original, "wg", "1", 0)
	if err := f.start(t, context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	// Add blocking observation to the same modeled child before any watcher or
	// process waiter starts; no executable or captured runtime is replaced.
	process := &desktopOwnedNodeMonitorProcess{desktopOwnedNodeTestProcess: f.process, exited: make(chan struct{})}
	f.launch.workspaceMu.Lock()
	f.launch.ownedNode.process = process
	f.launch.workspaceMu.Unlock()
	f.a.mu.Lock()
	f.a.state.Connected, f.a.state.Phase = true, "connected"
	f.a.mu.Unlock()
	// The application normally creates its tracker before connecting. Keep its
	// real state methods without starting an unrelated permanent observer loop
	// inside this watcher-lifetime test's synctest bubble.
	sessionTrackers.Store(f.a, &sessionTracker{a: f.a})
	return f, process
}

func desktopOwnedNodeMonitorDone(launch *desktopNodeLaunch) <-chan struct{} {
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	return launch.ownedNode.monitorDone
}

func desktopOwnedNodeMonitorCleanup(t *testing.T, f *desktopOwnedNodeTestFixture, process *desktopOwnedNodeMonitorProcess) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := stopDesktopOwnedNodeMonitor(ctx, f.launch); err != nil {
		t.Error("fixture watcher did not join", err)
	}
	if err := process.Close(context.Background()); err != nil {
		t.Error("fixture child did not join", err)
	}
	mtuSuspensions.Delete(f.a)
	sessionTrackers.Delete(f.a)
}

func desktopOwnedNodeMonitorAssertLive(t *testing.T, f *desktopOwnedNodeTestFixture) {
	t.Helper()
	f.a.mu.Lock()
	current := f.a.cmd == f.launch.command && f.a.state.Connected && f.a.state.Phase == "connected"
	f.a.mu.Unlock()
	if !current || f.process.closed || f.process.closes != 0 {
		t.Fatal("healthy captured runtime was stopped by its watcher")
	}
	select {
	case <-desktopOwnedNodeMonitorDone(f.launch):
		t.Fatal("healthy captured runtime lost its watcher")
	default:
	}
}

func TestDesktopOwnedNodeMonitorAllowsActiveMTUAndProvedExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, process := newDesktopOwnedNodeMonitorFixture(t)
		defer desktopOwnedNodeMonitorCleanup(t, f, process)
		live, err := readDesktopNodeMTU(f.launch)
		if err != nil {
			t.Fatal(err)
		}
		replaced := live
		replaced.Reader = 2
		desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", replaced)
		if _, err := f.a.readDesktopOwnedNodeReady(f.launch, true); err == nil {
			t.Fatal("startup accepted a replacement reader before initial TUN proof")
		}
		desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
		f.a.monitorDesktopOwnedNodeRuntime(f.launch)
		synctest.Wait()
		live.Active, live.MTU, live.Reader = true, 1360, 2
		// The native MTU operation may replace the reader and interface index;
		// it preserves the owned interface name and publishes the next reader.
		live.Index++
		live.Generation, live.Request, live.Lease = 1, strings.Repeat("2", 32), strings.Repeat("3", 32)
		desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
		if _, err := f.a.readDesktopOwnedNodeReady(f.launch, true); err == nil {
			t.Fatal("startup accepted an active temporary MTU lease")
		}
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		desktopOwnedNodeMonitorAssertLive(t, f)

		live.Active, live.Expired, live.Restored = false, true, true
		live.MTU, live.Reader, live.Heartbeat = 1420, 3, time.Now().UnixMilli()
		live.Index++
		live.Failure = "captured MTU lease expired; original MTU restored"
		desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
		if _, err := f.a.readDesktopOwnedNodeReady(f.launch, true); err == nil {
			t.Fatal("startup accepted a historical expired MTU lease")
		}
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		desktopOwnedNodeMonitorAssertLive(t, f)
	})
}

func TestDesktopOwnedNodeMonitorRejectsUnrelatedOrReplacedTUNReadback(t *testing.T) {
	for name, alter := range map[string]func(*desktopNodeMTURecord){
		"later-operation-failure": func(r *desktopNodeMTURecord) {
			r.Expired, r.Restored = true, true
			r.Failure = "captured TUN operation rejected"
		},
		"unproved-rollback": func(r *desktopNodeMTURecord) {
			r.Expired = true
			r.Failure = "captured MTU lease expired; original MTU restored"
		},
		"still-active-expiry": func(r *desktopNodeMTURecord) {
			r.Expired, r.Restored, r.Active = true, true, true
			r.Failure = "captured MTU lease expired; original MTU restored"
		},
		"different-interface": func(r *desktopNodeMTURecord) { r.Interface = "replacement-vpn" },
		"different-index":     func(r *desktopNodeMTURecord) { r.Index++ },
		"stale-heartbeat":     func(r *desktopNodeMTURecord) { r.Heartbeat = time.Now().Add(-3 * time.Second).UnixMilli() },
	} {
		t.Run(name, func(t *testing.T) {
			f, process := newDesktopOwnedNodeMonitorFixture(t)
			defer desktopOwnedNodeMonitorCleanup(t, f, process)
			live, err := readDesktopNodeMTU(f.launch)
			if err != nil {
				t.Fatal(err)
			}
			alter(&live)
			desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
			if _, err := f.a.readDesktopOwnedNodeReady(f.launch, false); err == nil {
				t.Fatal("runtime watcher accepted an unrelated failure or replaced TUN owner", name)
			}
		})
	}
}

func TestDesktopOwnedNodeMonitorRetiresFailureAfterJoiningWatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, process := newDesktopOwnedNodeMonitorFixture(t)
		defer desktopOwnedNodeMonitorCleanup(t, f, process)
		f.retirement(t)
		want := copyDesktopNodeProtectionTarget(f.kernel.target)
		joinedBeforeChild := false
		originalJoin := f.process.join
		f.process.join = func() {
			select {
			case <-desktopOwnedNodeMonitorDone(f.launch):
				joinedBeforeChild = true
			default:
			}
			originalJoin()
		}
		if err := f.launch.directoryRoot.Remove("node-ready.json"); err != nil {
			t.Fatal(err)
		}
		f.a.monitorDesktopOwnedNodeRuntime(f.launch)
		synctest.Wait()
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if !joinedBeforeChild || !f.process.closed || !f.launch.ownedNode.retired || f.kernel.locked {
			t.Fatal("failed watcher did not join itself before exact child and Job retirement")
		}
		if f.launch.ownedNode.slot.active != nil || !reflect.DeepEqual(f.launch.ownedNode.slot.target, want) || !reflect.DeepEqual(f.kernel.target, want) {
			t.Fatal("watcher retirement did not retain the independently proved exact deny")
		}
		f.a.mu.Lock()
		stopped := f.a.cmd == nil && !f.a.state.Connected && f.a.state.Phase == "failed" && strings.Contains(f.a.state.LastError, "exact protection is held")
		f.a.mu.Unlock()
		if !stopped || !f.a.operationMu.TryLock() {
			t.Fatal("watcher failed to finish its serialized Stop transaction")
		}
		f.a.operationMu.Unlock()
		if _, exists := desktopNodeOwners.Load(f.a); exists {
			t.Fatal("joined watcher retained a completed runtime workspace owner")
		}
		if _, err := os.Lstat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("joined watcher did not remove its owned private workspace", err)
		}
	})
}

func TestDesktopOwnedNodeMonitorCannotStopReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, process := newDesktopOwnedNodeMonitorFixture(t)
		defer desktopOwnedNodeMonitorCleanup(t, f, process)
		f.a.monitorDesktopOwnedNodeRuntime(f.launch)
		synctest.Wait()
		replacement := &exec.Cmd{Path: "different-retained-runtime"}
		replacementOwner := &desktopNodeLaunch{command: replacement}
		replacementSlot := &desktopNodeProtectionSlot{}
		f.a.mu.Lock()
		f.a.cmd, f.a.nodeProtection = replacement, replacementSlot
		f.a.state.RouterID, f.a.state.LastError = "replacement-node", "replacement-state"
		f.a.mu.Unlock()
		desktopNodeOwners.Store(f.a, replacementOwner)
		defer desktopNodeOwners.CompareAndDelete(f.a, replacementOwner)
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		select {
		case <-desktopOwnedNodeMonitorDone(f.launch):
		default:
			t.Fatal("old watcher did not leave a replacement connection")
		}
		f.a.mu.Lock()
		unchanged := f.a.cmd == replacement && f.a.nodeProtection == replacementSlot && f.a.state.Connected && f.a.state.Phase == "connected" && f.a.state.RouterID == "replacement-node" && f.a.state.LastError == "replacement-state"
		f.a.mu.Unlock()
		currentOwner, _ := desktopNodeOwners.Load(f.a)
		if !unchanged || currentOwner != replacementOwner || f.process.closes != 0 || f.launch.ownedNode.retired {
			t.Fatal("old watcher stopped or rewrote a replacement owner")
		}
	})
}

func TestDesktopOwnedNodeMonitorDefersToForegroundOperation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, process := newDesktopOwnedNodeMonitorFixture(t)
		defer desktopOwnedNodeMonitorCleanup(t, f, process)
		captured := *f.launch.ownedNode.ready
		if err := f.launch.directoryRoot.Remove("node-ready.json"); err != nil {
			t.Fatal(err)
		}
		f.a.operationMu.Lock()
		locked := true
		defer func() {
			if locked {
				f.a.operationMu.Unlock()
			}
		}()
		f.a.monitorDesktopOwnedNodeRuntime(f.launch)
		synctest.Wait()
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		desktopOwnedNodeMonitorAssertLive(t, f)
		desktopOwnedNodeTestWrite(t, f.launch, "node-ready.json", captured)
		f.a.operationMu.Unlock()
		locked = false
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		desktopOwnedNodeMonitorAssertLive(t, f)
		if !f.a.operationMu.TryLock() {
			t.Fatal("watcher retained the foreground operation lock after healthy recheck")
		}
		f.a.operationMu.Unlock()
	})
}

func TestDesktopOwnedNodeMonitorCancellationJoinsWithoutStopping(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, process := newDesktopOwnedNodeMonitorFixture(t)
		defer desktopOwnedNodeMonitorCleanup(t, f, process)
		f.a.monitorDesktopOwnedNodeRuntime(f.launch)
		synctest.Wait()
		done := desktopOwnedNodeMonitorDone(f.launch)
		f.a.monitorDesktopOwnedNodeRuntime(f.launch)
		if desktopOwnedNodeMonitorDone(f.launch) != done {
			t.Fatal("duplicate watcher replaced the captured cancellation owner")
		}
		if err := stopDesktopOwnedNodeMonitor(context.Background(), f.launch); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("watcher cancellation acknowledged before its actual loop joined")
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		f.a.mu.Lock()
		unchanged := f.a.cmd == f.launch.command && f.a.state.Connected && f.a.state.Phase == "connected"
		f.a.mu.Unlock()
		if !unchanged || f.process.closes != 0 || f.launch.ownedNode.retired {
			t.Fatal("cancelled watcher later stopped its runtime on stale heartbeat")
		}
	})
}

func TestDesktopOwnedNodeMonitorForegroundRetirementAndOldRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, process := newDesktopOwnedNodeMonitorFixture(t)
		defer desktopOwnedNodeMonitorCleanup(t, f, process)
		f.retirement(t)
		joinedBeforeChild := false
		originalJoin := f.process.join
		f.process.join = func() {
			select {
			case <-desktopOwnedNodeMonitorDone(f.launch):
				joinedBeforeChild = true
			default:
			}
			originalJoin()
		}
		f.a.monitorDesktopOwnedNodeRuntime(f.launch)
		synctest.Wait()
		f.a.operationMu.Lock()
		err := f.a.retireDesktopOwnedNode(context.Background(), f.launch)
		f.a.operationMu.Unlock()
		if err != nil || !joinedBeforeChild || !f.process.closed || !f.launch.ownedNode.retired {
			t.Fatal("foreground retirement did not join its watcher before the captured child", err)
		}
		synctest.Wait()
		closes := f.process.closes
		replacement := &desktopNodeProtectionSlot{}
		f.a.mu.Lock()
		f.a.nodeProtection = replacement
		f.a.mu.Unlock()
		if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err != nil {
			t.Fatal("already joined old runtime could not finish an idempotent retry after slot replacement", err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if f.process.closes != closes || f.a.nodeProtection != replacement || f.a.cmd != f.launch.command || f.a.state.Phase != "connected" {
			t.Fatal("old retirement retry changed the replacement slot or published a late watcher failure")
		}
	})
}

func TestDesktopOwnedNodeMonitorMTUDrainJoinsDirectChildWithoutExecProcess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, process := newDesktopOwnedNodeMonitorFixture(t)
		defer desktopOwnedNodeMonitorCleanup(t, f, process)
		f.retirement(t)
		// The main child has exited, but its captured Job and native baseline
		// are still unjoined. Explicit Stop must discharge that exact owner.
		process.signalExit()
		<-desktopNodeProcessDone(f.launch)
		if f.launch.command.Process != nil || f.process.closed || !f.kernel.locked {
			t.Fatal("direct-process fixture did not retain its unjoined native owner")
		}
		calls := 0
		release, command, err := f.a.holdMTUForStopWith(func(ctx context.Context) (func(), error) {
			calls++
			if calls == 1 {
				return nil, errors.New("captured MTU lease has not drained")
			}
			if !f.process.closed || f.kernel.locked || !f.launch.ownedNode.retired || f.launch.ownedNode.slot.active != nil {
				t.Error("MTU drain retried before exact child/Job join and independent target read")
			}
			return f.a.holdCapturedMTU(ctx)
		})
		if err != nil || release == nil || command != f.launch.command || calls != 2 {
			t.Fatal("direct captured child was skipped because its immutable exec descriptor has no Process", err, calls)
		}
		release()
		if f.a.cmd != command {
			t.Fatal("MTU fallback stole the ordinary Stop transaction's command owner")
		}
	})
}
