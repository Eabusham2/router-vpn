//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func smartLegacyChild(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "120")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

type smartLegacyFixture struct {
	a         *app
	profile   common.RouterProfile
	first     common.Mode
	original  *exec.Cmd
	operation context.Context
	cancel    context.CancelFunc
	starts    []string
}

func newSmartLegacyFixture(t *testing.T, mode string, candidates ...string) *smartLegacyFixture {
	t.Helper()
	operation, cancel := context.WithCancel(context.Background())
	p := common.RouterProfile{ID: "home", Endpoint: "198.51.100.7", NodeKind: "router-vpn", KillSwitch: true, KillSwitchPolicy: "always"}
	first := common.Mode{ID: mode, AutoEligible: true, SmartSimplify: candidates}
	cmd := smartLegacyChild(t)
	scripts := t.TempDir()
	if err := os.WriteFile(filepath.Join(scripts, "kill-switch-platform.py"), []byte("from pathlib import Path\nPath('released').touch()\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &app{
		cmd: cmd, connectionContext: operation, connectionCancel: cancel, modes: []common.Mode{first},
		state:    state{Connected: true, Mode: mode, RuntimeMode: mode, RouterID: p.ID, Phase: "connected", Base: "auto"},
		profiles: common.RouterProfileStore{SelectedID: p.ID, Profiles: []common.RouterProfile{p}},
	}
	a.cfg.ScriptsDir = scripts
	for _, id := range candidates {
		a.modes = append(a.modes, common.Mode{ID: id, AutoEligible: true})
	}
	sessionTrackers.Store(a, &sessionTracker{a: a})
	t.Cleanup(func() {
		cancel()
		sessionTrackers.Delete(a)
		strategyLocks.Delete(a)
		if _, err := os.Stat(filepath.Join(scripts, "released")); !errors.Is(err, os.ErrNotExist) {
			t.Error("SMART invoked global protection release", err)
		}
	})
	return &smartLegacyFixture{a: a, profile: p, first: first, original: cmd, operation: operation, cancel: cancel}
}

// Seed firstWorking's previously proved connection. Every simplification runs
// the production startModeAttempt path up to the missing authenticated Linux
// controller. No privileged controller, rules, or user network is needed.
func (f *smartLegacyFixture) runtime(t *testing.T, afterRefusal func()) smartStrategyRuntime {
	t.Helper()
	return smartStrategyRuntime{
		first: func(a *app, p common.RouterProfile, r *strategyResult) (common.Mode, error) {
			if a != f.a || p.ID != f.profile.ID {
				t.Fatal("SMART changed the source of its first connection")
			}
			r.Attempts = append(r.Attempts, strategyAttempt{Mode: f.first.ID, Action: "candidate", Success: true})
			return f.first, nil
		},
		start: func(a *app, id string, hold bool, transition *modeAttemptTransition) error {
			if id == f.first.ID || !hold || transition == nil {
				t.Fatalf("unexpected legacy restart or transition: %s", id)
			}
			f.starts = append(f.starts, id)
			err := a.startModeAttempt(id, hold, transition)
			if err == nil || !strings.Contains(err.Error(), "Linux Node parent requires its authenticated installed controller") || transition.StopBegun {
				t.Fatalf("%s did not refuse the real Linux preflight before Stop: %v %+v", id, err, transition)
			}
			if afterRefusal != nil {
				afterRefusal()
			}
			return err
		},
		restore: func(*app, speedLabRestorePlan) error {
			t.Fatal("refused Linux preflight attempted native restore")
			return nil
		},
	}
}

func (f *smartLegacyFixture) run(r smartStrategyRuntime) (strategyResult, error) {
	f.a.operationMu.Lock()
	defer f.a.operationMu.Unlock()
	return f.a.runSmartStrategyWith(r)
}

func TestDesktopSmartLegacyLinuxRealPreflightsRetainOriginal(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		candidates []string
	}{
		{"wg-pq", []string{"wg"}}, {"naive-h3", []string{"hysteria2", "naive-h2"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newSmartLegacyFixture(t, tc.mode, tc.candidates...)
			want := f.a.state
			want.LogicalMode = "smart-auto"
			result, err := f.run(f.runtime(t, nil))
			if err != nil || !result.OK || result.RuntimeMode != tc.mode || result.RestoredMode != "" || !slices.Equal(f.starts, tc.candidates) || len(result.Attempts) != 1+2*len(tc.candidates) {
				t.Fatal(result, err, f.starts)
			}
			for i, candidate := range tc.candidates {
				trial, retain := result.Attempts[1+2*i], result.Attempts[2+2*i]
				if trial.Mode != candidate || trial.Action != "simplify" || trial.Success || retain.Mode != tc.mode || retain.Action != "retain" || !retain.Success {
					t.Fatal(trial, retain)
				}
			}
			if f.a.cmd != f.original || f.a.state != want || f.original.Process.Signal(syscall.Signal(0)) != nil {
				t.Fatal("SMART changed the proved helper or state", f.a.state)
			}
		})
	}
}

// Wait for kernel exit without reaping the original child. Signal(0) still
// succeeds in this state. The production witness must reject this pidfd.
func smartLegacyZombie(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	stat := filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "stat")
	deadline := time.Now().Add(3 * time.Second)
	for {
		body, err := os.ReadFile(stat)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(") Z ")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child never entered zombie state")
		}
		time.Sleep(time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("child was reaped before test", err)
	}
}

func TestDesktopSmartLegacyLinuxUnreapedExit(t *testing.T) {
	for _, timing := range []string{"before-capture", "during-preflight"} {
		t.Run(timing, func(t *testing.T) {
			f := newSmartLegacyFixture(t, "wg-pq", "wg")
			var kill func()
			if timing == "before-capture" {
				smartLegacyZombie(t, f.original)
			} else {
				kill = func() { smartLegacyZombie(t, f.original) }
			}
			result, err := f.run(f.runtime(t, kill))
			if !errors.Is(err, os.ErrProcessDone) || result.OK || result.RestoredMode != "" || f.a.cmd != f.original || f.a.state.Connected || f.a.state.Phase != "failed" || f.a.state.LogicalMode != "" {
				t.Fatal("unreaped helper was adopted or restarted", result, err, f.a.state)
			}
			if timing == "before-capture" && len(f.starts) != 0 || timing == "during-preflight" && len(f.starts) != 1 {
				t.Fatal(f.starts)
			}
		})
	}
}

func TestDesktopSmartLegacyLinuxRejectedPreflightCannotReplaceOwner(t *testing.T) {
	for _, fault := range []string{"cancel", "source", "source-aba", "mode", "command", "between-candidates"} {
		t.Run(fault, func(t *testing.T) {
			f := newSmartLegacyFixture(t, "naive-h3", "hysteria2", "naive-h2")
			replacement := smartLegacyChild(t)
			var want state
			wantCmd := f.original
			mutate := func() {
				f.a.mu.Lock()
				defer f.a.mu.Unlock()
				switch fault {
				case "cancel":
					f.a.connectionCancelIntent = f.operation
					f.cancel()
				case "source":
					f.a.profiles.Profiles[0].APIToken = "new-private-source"
				case "source-aba":
					f.a.profiles.Profiles[0].APIToken = "transient"
					if _, err := f.a.candidateCatalogRevisionLocked(); err != nil {
						t.Fatal(err)
					}
					f.a.profiles.Profiles[0].APIToken = f.profile.APIToken
				case "mode":
					f.a.state.Mode, f.a.state.RuntimeMode = "different", "different"
				case "command", "between-candidates":
					f.a.cmd = replacement
					wantCmd = replacement
				}
				want = f.a.state
			}
			var r smartStrategyRuntime
			if fault == "between-candidates" {
				r = f.runtime(t, nil)
				r.check = func(a *app, mode common.Mode) (bool, string) {
					if mode.ID == "naive-h2" {
						mutate()
					}
					return true, ""
				}
			} else {
				r = f.runtime(t, mutate)
			}
			result, err := f.run(r)
			if err == nil || result.OK || result.RestoredMode != "" || !slices.Equal(f.starts, []string{"hysteria2"}) || f.a.state != want || f.a.cmd != wantCmd {
				t.Fatal("preflight replaced or adopted another owner", result, err, f.starts, f.a.state, want)
			}
			for _, child := range []*exec.Cmd{f.original, replacement} {
				if err := child.Process.Signal(syscall.Signal(0)); err != nil {
					t.Fatal("SMART stopped a child", err)
				}
			}
		})
	}
}

func TestDesktopSmartLegacyLinuxWinnerCannotRetireNativeReplacement(t *testing.T) {
	f := newSmartLegacyFixture(t, "naive-h3", "hysteria2")
	a := f.a
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	saved, err := a.captureSmartLegacyPredecessor(f.operation, f.profile, f.first.ID)
	if err != nil || saved == nil {
		t.Fatal("could not capture original legacy helper", err)
	}
	// The new native owner has a real live child, the same operation and
	// mode, and an original slot. It has not published its ready record.
	// Only that owner's own Stop may retire it.
	replacement := smartLegacyChild(t)
	slot := &desktopNodeProtectionSlot{}
	native := &desktopNodeLaunch{mode: f.first.ID, command: replacement, ownedNode: &desktopOwnedNodeRuntime{operation: f.operation, slot: slot}}
	a.cmd, a.nodeProtection = replacement, slot
	desktopNodeOwners.Store(a, native)
	t.Cleanup(func() { desktopNodeOwners.Delete(a) })
	want := a.state
	if _, err := a.readDesktopOwnedNodeReady(native, false); err == nil {
		t.Fatal("fixture requires a native replacement whose readiness check would fail")
	}
	err = a.setStrategyWinnerFor("smart-auto", f.first, f.operation, saved)
	owner, present := desktopNodeOwners.Load(a)
	if err == nil || !strings.Contains(err.Error(), "SMART legacy predecessor changed") || !present || owner != native || a.cmd != replacement || a.nodeProtection != slot || a.state != want {
		t.Fatal("legacy winner publication bypassed its witness or touched the native replacement", err, a.state)
	}
}
