//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"

	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/common"
	"syscall"
	"testing"
	"time"
)

func legacyStopBoundaryFiles(t *testing.T, root string) string {
	t.Helper()
	modes := filepath.Join(root, "modes")
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{modes, bin} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"native-standard-exit-linux.sh", "cleanup-private-runtime.py", "native-wrapper-owner.py", "runtime-pids.py", "select-standard-engine.sh", "run-multihop.sh", "multihop.py", "profile_id.py", "private_profile_store.py", "dns-policy.py"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "modes", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(modes, name), raw, 0700); err != nil {
			t.Fatal(err)
		}
	}
	firewall := `import pathlib,sys,os
p=pathlib.Path(os.environ['HOMEVPN_ROOT'])/'firewall-observed'
with p.open('a') as f:f.write(sys.argv[1]+'\n')
`
	if err := os.WriteFile(filepath.Join(modes, "kill-switch-platform.py"), []byte(firewall), 0700); err != nil {
		t.Fatal(err)
	}
	engine := `#!/usr/bin/env python3
import os,sys,signal,time,pathlib
if sys.argv[1]=='check':sys.exit(0)
root=pathlib.Path(os.environ['HOMEVPN_ROOT'])
(root/'engine-started').write_text(str(os.getpid()))
def done(*_):
 (root/'engine-stopped').write_text('closed')
 sys.exit(0)
signal.signal(signal.SIGINT,done);signal.signal(signal.SIGTERM,done)
while True:time.sleep(.02)
`
	if err := os.WriteFile(filepath.Join(bin, "sing-box"), []byte(engine), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	return modes
}

func legacyStopShippingCatalog(t *testing.T) []common.Mode {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var modes []common.Mode
	if err = json.Unmarshal(raw, &modes); err != nil || len(modes) < 20 {
		t.Fatal("shipping mode catalog unavailable", err)
	}
	for _, mode := range modes {
		if mode.ID == "multihop" || mode.ID == "standard-exit" {
			t.Fatal("reproduction catalog assumptions changed")
		}
	}
	return modes
}

type legacyExitFixture struct {
	a    *app
	root string
	exit standardExit
	mux  *http.ServeMux
}

func newLegacyExitFixture(t *testing.T, policy string) *legacyExitFixture {
	t.Helper()
	root := t.TempDir()
	modes := legacyStopBoundaryFiles(t, root)
	control := common.RouterProfile{ID: "control", Name: "Control", KillSwitch: true, KillSwitchPolicy: policy, DNSMode: "custom", DNSProtocol: "udp", DNSHost: "1.1.1.1"}
	a := &app{modes: legacyStopShippingCatalog(t), cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ScriptsDir: modes}, profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: control.ID, Profiles: []common.RouterProfile{control}}, state: state{Mode: "off", Phase: "off"}}
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	exit := validTestStandardExit("socks5")
	if err := persistStandardExitStore(standardExitStore{SchemaVersion: standardExitStoreVersion, Exits: []standardExit{exit}}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDesktopMultihopRoutes(mux, a)
	f := &legacyExitFixture{a: a, root: root, exit: exit, mux: mux}
	t.Cleanup(func() {
		if value, ok := legacyStandardExitOwners.Load(a); ok {
			owner := value.(*linuxLegacyStandardExitOwner)
			if owner.command.Process != nil {
				owner.command.Process.Kill()
				if owner.done != nil {
					<-owner.done
				}
			}
			legacyStandardExitOwners.Delete(a)
			for _, file := range []*os.File{owner.image, owner.config, owner.sourceImage, owner.sourceConfig, owner.directory, owner.namespace, owner.pidFile} {
				if file != nil {
					file.Close()
				}
			}
			if owner.launch.directoryRoot != nil {
				owner.launch.directoryRoot.Close()
			}
		}
		sessionTrackers.Delete(a)
		mtuSuspensions.Delete(a)
		strategyLocks.Delete(a)
	})
	return f
}

// This test runs the production retained process/Stop adapters. Only the native nft/TUN
// absence queries are modeled: this host cannot create a privileged network/TUN
// namespace. The shared flock and persisted-state check remain real.
func (f *legacyExitFixture) prepareOff(t *testing.T) (*linuxLegacyStandardExitOwner, context.Context) {
	t.Helper()
	operation, finish, err := f.a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(finish)
	command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := prepareLegacyStandardExitOwnerWithObservers(f.a, command, "standard-socks5", "external", "standard:"+f.exit.ID, func() error { return nil }, func() string { return "captured-test-network" })
	if err != nil || captured == nil {
		t.Fatal("shipping retained Off adapter unavailable", err)
	}
	owner := captured.(*linuxLegacyStandardExitOwner)
	owner.offProtectionCheck = func(ctx context.Context) error {
		lease, err := acquireLegacyExitMutationLease(ctx, f.root)
		if err != nil {
			return err
		}
		defer lease.Close()
		return legacyExitStateAbsent(lease)
	}
	t.Cleanup(func() { _ = owner.Discard() })
	return owner, operation
}
func waitLegacyOffEngine(t *testing.T, f *legacyExitFixture) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(f.root, "engine-started")); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("original real child did not initialize")
}
func assertLegacyOffJoined(t *testing.T, owner *linuxLegacyStandardExitOwner) {
	t.Helper()
	for _, done := range []<-chan struct{}{owner.done, owner.creatorDone} {
		select {
		case <-done:
		default:
			t.Fatal("Stop returned before original child/creator joined")
		}
	}
	if owner.command.ProcessState == nil {
		t.Fatal("original Wait did not join")
	}
}
func TestLegacyStandardOffStopJoinsOriginalWithoutCatalogOrGlobalRelease(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disconnect", true: "cancel"}[cancelled], func(t *testing.T) {
			f := newLegacyExitFixture(t, "off")
			owner, operation := f.prepareOff(t)
			if err := owner.Start(operation); err != nil {
				t.Fatal(err)
			}
			waitLegacyOffEngine(t, f)
			if err := owner.Current(operation); err != nil {
				t.Fatal(err)
			}
			if cancelled {
				f.a.cancelConnectionOperation()
				if owner.Current(operation) == nil {
					t.Fatal("cancelled request remained admissible")
				}
			}
			// A concurrent policy belongs to its own helper. Off Stop cannot erase it.
			foreign := []byte(`{"policy":"always","owner":"another-session"}`)
			statePath := filepath.Join(f.root, "run", "kill-switch.json")
			if err := os.WriteFile(statePath, foreign, 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.a.stopMode(); err != nil {
				t.Fatal("actual Stop fell back to missing standard-exit catalog entry", err)
			}
			assertLegacyOffJoined(t, owner)
			if _, ok := legacyStandardExitOwners.Load(f.a); ok || f.a.cmd != nil || f.a.state.Mode != "off" {
				t.Fatal("joined Stop did not commit exact owner")
			}
			if raw, err := os.ReadFile(statePath); err != nil || string(raw) != string(foreign) {
				t.Fatal("Off Stop mutated another session's policy", err)
			}
			if _, err := os.Stat(filepath.Join(f.root, "firewall-observed")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("retained Off unexpectedly called generic apply/release", err)
			}
			if _, err := os.Stat(owner.launch.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("original private runtime was not retired", err)
			}
		})
	}
}
func TestLegacyStandardOffRejectsActualForeignRetiredPIDFD(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	owner, operation := f.prepareOff(t)
	if err := owner.Start(operation); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	foreignFD := -1
	foreign := exec.Command("sh", "-c", "exit 0")
	foreign.SysProcAttr = &syscall.SysProcAttr{PidFD: &foreignFD}
	if err := foreign.Run(); err != nil || foreignFD < 0 {
		t.Fatal("real foreign pidfd fixture unavailable", err)
	}
	file := os.NewFile(uintptr(foreignFD), "foreign-retired-child")
	defer file.Close()
	if err := legacyExitPIDFDRetired(file); err != nil {
		t.Fatal("foreign fixture is not a real retired process", err)
	}
	original := owner.originalPIDFD
	owner.pidFile = file
	if err := f.a.stopMode(); err == nil || !strings.Contains(err.Error(), "descriptor was replaced") {
		t.Fatal("real foreign pidfd authorized retirement", err)
	}
	assertLegacyOffJoined(t, owner)
	if current, ok := legacyStandardExitOwners.Load(f.a); !ok || current != owner || f.a.cmd != owner.command {
		t.Fatal("rejected descriptor lost original retry owner")
	}
	if _, err := os.Stat(owner.launch.directory); err != nil {
		t.Fatal("unproved retirement deleted workspace", err)
	}
	owner.pidFile = original
	if err := f.a.stopMode(); err != nil {
		t.Fatal("original pidfd retry failed", err)
	}
}
func TestLegacyStandardOffAdmissionPreservesExistingPolicy(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	owner, operation := f.prepareOff(t)
	if err := os.MkdirAll(filepath.Join(f.root, "run"), 0700); err != nil {
		t.Fatal(err)
	}
	saved := []byte(`{"policy":"always"}`)
	path := filepath.Join(f.root, "run", "kill-switch.json")
	if err := os.WriteFile(path, saved, 0600); err != nil {
		t.Fatal(err)
	}
	if err := owner.Start(operation); err == nil {
		t.Fatal("Off adopted preexisting Always policy")
	}
	if owner.started || owner.command.Process != nil {
		t.Fatal("engine started without proved absence")
	}
	if err := f.a.stopMode(); err != nil {
		t.Fatal("unstarted original owner could not clean itself", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(saved) {
		t.Fatal("admission failure changed Always policy", err)
	}
}
func TestLegacyStandardOffMutationLeaseRejectsReplacementAndStateSymlink(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	lease, err := acquireLegacyExitMutationLease(context.Background(), f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := legacyExitStateAbsent(lease); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(f.root, "run", "kill-switch.json")
	if err := os.Symlink(filepath.Join(f.root, "missing"), statePath); err != nil {
		t.Fatal(err)
	}
	if err := legacyExitStateAbsent(lease); err == nil {
		t.Fatal("dangling state symlink became absence")
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "run", "kill-switch.lock")
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Current(); err == nil {
		t.Fatal("replaced helper flock inode remained current")
	}
}

func TestLegacyStandardOffCapturedLegacyPolicy(t *testing.T) {
	for _, p := range []common.RouterProfile{{KillSwitch: true}, {KillSwitchPolicy: "always"}, {KillSwitchPolicy: "on-connect"}, {KillSwitchPolicy: "unknown"}} {
		if legacyStandardExitOffPolicy(p) {
			t.Fatal("protected/unknown policy became Off", p)
		}
	}
	for _, p := range []common.RouterProfile{{}, {KillSwitchPolicy: " OFF ", KillSwitch: true}} {
		if !legacyStandardExitOffPolicy(p) {
			t.Fatal("explicit Off was not retained", p)
		}
	}
}
func TestLegacyStandardOffWorkspaceReplacementCannotAdopt(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	owner, operation := f.prepareOff(t)
	if err := owner.Start(operation); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	path := owner.launch.directory
	if err := os.Rename(path, path+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "foreign")
	if err := os.WriteFile(marker, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := owner.Current(operation); err == nil {
		t.Fatal("replacement workspace authorized Connected")
	}
	if err := f.a.stopMode(); err == nil {
		t.Fatal("replacement workspace authorized retirement")
	}
	if body, err := os.ReadFile(marker); err != nil || string(body) != "preserve" {
		t.Fatal("replacement workspace was changed", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+"-original", path); err != nil {
		t.Fatal(err)
	}
	if err := f.a.stopMode(); err != nil {
		t.Fatal("restored original workspace could not retry", err)
	}
}
func TestLegacyStandardOffRetainedStopUsesOriginalDeadline(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	body := `#!/usr/bin/env python3
import sys,os,signal,pathlib,time
if sys.argv[1]=='check':sys.exit(0)
signal.signal(signal.SIGINT,signal.SIG_IGN)
pathlib.Path(os.environ['HOMEVPN_ROOT'],'engine-started').write_text('ready')
while True:time.sleep(.01)
`
	if err := os.WriteFile(filepath.Join(f.root, "bin", "sing-box"), []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	owner, operation := f.prepareOff(t)
	if err := owner.Start(operation); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	captured, err := captureLegacyStandardExitStop(f.a)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := captured.Retire(ctx, owner.command, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Stop ignored captured deadline", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("Stop waited on a replacement budget")
	}
	if current, ok := legacyStandardExitOwners.Load(f.a); !ok || current != owner {
		t.Fatal("bounded Stop lost retry ownership")
	}
	if err := owner.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := f.a.stopMode(); err != nil {
		t.Fatal("bounded retry could not join original", err)
	}
}
func TestLegacyStandardOffLeaseSharesPythonHelperTransaction(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	lease, err := acquireLegacyExitMutationLease(context.Background(), f.root)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
	script := `import fcntl,os,sys
f=open(sys.argv[1],'r+')
fcntl.flock(f,fcntl.LOCK_EX)
print('owned',flush=True)
sys.stdin.buffer.read(1)
`
	child := exec.Command("python3", "-c", script, filepath.Join(f.root, "run", "kill-switch.lock"))
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); _ = child.Wait() })
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "owned\n" {
		t.Fatal("actual Python lease not acquired", line, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if borrowed, err := acquireLegacyExitMutationLease(ctx, f.root); err == nil {
		borrowed.Close()
		t.Fatal("Go Off admission bypassed same Python lock inode")
	}
	input.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	lease, err = acquireLegacyExitMutationLease(context.Background(), f.root)
	if err != nil {
		t.Fatal("joined Python release did not permit admission", err)
	}
	lease.Close()
}
func TestLegacyStandardOffHandlerLateIntentAndReplacementCannotAdopt(t *testing.T) {
	for _, replacementPolicy := range []string{"", "always", "on-connect"} {
		replacement := replacementPolicy != ""
		t.Run("late-intent-or-replacement-"+replacementPolicy, func(t *testing.T) {
			f := newLegacyExitFixture(t, "off")
			var owner *linuxLegacyStandardExitOwner
			var replacementCommand *exec.Cmd
			var replacementTracker *sessionTracker
			adapter := platformStandardExitRuntime{
				prepareLegacy: func(a *app, cmd *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
					captured, err := prepareLegacyStandardExitOwnerWithObservers(a, cmd, mode, base, id, func() error { return nil }, func() string { return "captured-test-network" })
					if err != nil || captured == nil {
						return captured, err
					}
					owner = captured.(*linuxLegacyStandardExitOwner)
					owner.offProtectionCheck = func(ctx context.Context) error {
						lease, err := acquireLegacyExitMutationLease(ctx, f.root)
						if err != nil {
							return err
						}
						defer lease.Close()
						return legacyExitStateAbsent(lease)
					}
					return owner, nil
				},
				prove: func(*app, string) error { return nil },
				current: func(captured legacyStandardExitLaunch, ctx context.Context) error {
					if err := captured.Current(ctx); err != nil {
						return err
					}
					// The original exact owner check just succeeded. Race cancellation intent
					// (before cancel() fires) or a replacement before final Connected adoption.
					f.a.mu.Lock()
					if replacement {
						replacementCommand = exec.Command("python3", "-c", "import time;time.sleep(60)")
						if err := replacementCommand.Start(); err != nil {
							f.a.mu.Unlock()
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = replacementCommand.Process.Kill(); _ = replacementCommand.Wait() })
						f.a.profiles.Profiles[0].KillSwitchPolicy = replacementPolicy
						if err := os.WriteFile(filepath.Join(f.root, "run", "kill-switch.json"), []byte(`{"policy":"`+replacementPolicy+`","owner":"replacement"}`), 0600); err != nil {
							f.a.mu.Unlock()
							t.Fatal(err)
						}
						f.a.cmd = replacementCommand
						f.a.state = state{Mode: "replacement", Phase: "replacement", Connected: true, LastError: "preserve"}
						replacementTracker = &sessionTracker{a: f.a, requestedMode: "replacement", requestedBase: "preserve"}
						sessionTrackers.Store(f.a, replacementTracker)
					} else {
						f.a.connectionCancelIntent = ctx
					}
					f.a.mu.Unlock()
					return nil
				},
			}
			body, _ := json.Marshal(standardExitConnectRequest{StandardExitID: f.exit.ID, Direct: true})
			response := httptest.NewRecorder()
			f.a.platformStandardExitConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(body)), adapter)
			if response.Code != http.StatusConflict {
				t.Fatal("late old request was not rejected", response.Code, response.Body.String())
			}
			if owner == nil {
				t.Fatal("handler did not execute retained production creator")
			}
			if _, err := os.Stat(filepath.Join(f.root, "firewall-observed")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old handler invoked generic policy mutation", err)
			}
			if !replacement {
				if f.a.state.Connected || f.a.cmd != nil {
					t.Fatal("cancelled handler adopted Connected")
				}
				assertLegacyOffJoined(t, owner)
			} else {
				if f.a.cmd != replacementCommand || f.a.state.Mode != "replacement" || !f.a.state.Connected || f.a.state.LastError != "preserve" {
					t.Fatal("late completion changed replacement state")
				}
				if tracker, _ := sessionTrackers.Load(f.a); tracker != replacementTracker || replacementTracker.requestedMode != "replacement" || replacementTracker.requestedBase != "preserve" {
					t.Fatal("late completion changed replacement history")
				}
				if current, ok := legacyStandardExitOwners.Load(f.a); !ok || current != owner {
					t.Fatal("old source lost retained cleanup capability")
				}
				if err := replacementCommand.Process.Signal(syscall.Signal(0)); err != nil {
					t.Fatal("stale cancellation stopped newer protected process", err)
				}
				if body, err := os.ReadFile(filepath.Join(f.root, "run", "kill-switch.json")); err != nil || string(body) != `{"policy":"`+replacementPolicy+`","owner":"replacement"}` {
					t.Fatal("stale cancellation released newer protected state", err)
				}
			}
		})
	}
}

func TestLegacyStandardOffTUNReadUsesCapturedNamespace(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	owner, _ := f.prepareOff(t)
	expected := owner.namespaceInfo
	foreign, err := os.Stat(filepath.Join(f.root, "routers.json"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	owner.tunAbsent = func() error { called = true; return nil }
	owner.namespaceInfo = foreign
	if err := owner.tunAbsentInNamespace(); err == nil || called {
		t.Fatal("TUN result borrowed a different namespace", err, called)
	}
	owner.namespaceInfo = expected
	if err := owner.tunAbsentInNamespace(); err != nil || !called {
		t.Fatal("original namespace could not supply readback", err, called)
	}
	// The real nft query must also reject the wrong captured namespace before
	// invoking the unavailable native binary in this unprivileged test host.
	if err := legacyExitVerifyOffProtection(context.Background(), f.root, foreign); err == nil || !strings.Contains(err.Error(), "captured network namespace") {
		t.Fatal("Off nft readback ignored captured namespace", err)
	}
}
