//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobiletor"
)

var linuxNodeFallbackCases = []string{"held-on-connect", "strategy-failure", "cancelled-active", "older-active", "active-release",
	"temporary-deferred", "duplicate-owner", "partial-journal", "empty-legacy", "always"}

// These are actual installed controller/process/guardian/nft/journal owners.
// The established transaction child models graph readiness; no TUN, selected
// DNS traffic or successful Connected claim is supplied by this fixture.
func linuxNodeFallbackFixture(controller *ownedDesktopController, scenario string) error {
	policy := "on-connect"
	if scenario == "always" {
		policy = "always"
	}
	profile, _, err := linuxTransactionProfile(policy)
	if err != nil {
		return err
	}
	operation, cancelOperation := context.WithCancel(context.Background())
	defer cancelOperation()
	a := &app{localController: controller, connectionContext: operation, connectionCancel: cancelOperation,
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
			ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
			StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")},
		profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}}
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "fallback-rendezvous")
	defer gate.Close()
	if err := linuxprocess.SetCloseOnExec(gate); err != nil {
		return err
	}
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != 1 {
		return errors.Join(err, errors.New("Linux fallback lost its original rendezvous"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := linuxNodeLauncherPackage(); err != nil {
		return err
	}
	if err := linuxHostStartAssets(profile); err != nil {
		return err
	}
	// This fixture boundary only records legacy dispatch. It never changes a
	// native rule or reports Node protection absent. Actual nft/journal reads
	// below independently require the original Node retirement/release.
	legacy := filepath.Join(linuxOwnedControllerRoot, "fallback-legacy-release")
	if err := os.WriteFile(filepath.Join(a.cfg.ScriptsDir, "kill-switch-platform.py"),
		[]byte(fmt.Sprintf("from pathlib import Path\nPath(%q).write_text('legacy release entered')\n", legacy)), 0600); err != nil {
		return err
	}
	session, err := captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return err
	}
	if scenario == "empty-legacy" {
		if err := linuxNodeFallbackLegacy(ctx, a, session, legacy); err != nil {
			return err
		}
		if err := parent.parent.Close(ctx); err != nil {
			return err
		}
		controller.close()
		_, err := fmt.Fprintln(os.Stdout, "captured-parent-retired")
		return err
	}
	verify := func(context.Context, string) (string, error) {
		return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
	}
	host, err := prepareDesktopLinuxNodeHostWith(operation, a, profile, "shadowsocks", 0, verify, nil)
	if err != nil {
		return err
	}
	if err := host.Stage(ctx); err != nil {
		return err
	}
	environment := []string{linuxNodeTransactionMarker + "=1", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0"}
	partial := ""
	if scenario == "partial-journal" {
		path := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
		partial = filepath.Join(path, "unowned-record")
		if err := os.WriteFile(partial, []byte("original foreign journal"), 0600); err != nil {
			return err
		}
	}
	startErr := session.startWithVerifier(ctx, host, environment, verify)
	if scenario == "partial-journal" {
		if startErr == nil || session.journalErr != startErr || session.active != host || host.process != nil {
			return errors.New("Linux fallback did not retain its original partial constructor")
		}
		if err := a.stopMode(); err != startErr || session.active != nil || !host.closed {
			return errors.New("Linux fallback partial host cleanup lost its original constructor error")
		}
		if err := a.releaseFallbackKillSwitch(operation); err != startErr || session.journalErr != startErr {
			return errors.New("Linux fallback converted its unresolved original journal into a release")
		}
		actual, err := os.ReadFile(partial)
		if err != nil || string(actual) != "original foreign journal" {
			return errors.Join(err, errors.New("Linux fallback changed another journal's bytes"))
		}
	} else {
		if startErr != nil {
			return startErr
		}
		command := a.cmd
		journal := session.journal
		if command == nil || command != host.process.command || session.active != host || a.state.Connected {
			return errors.New("Linux fallback lost its actual source or fabricated connection proof")
		}
		if scenario == "older-active" {
			later, cancelLater := context.WithCancel(context.Background())
			cancelLater()
			a.mu.Lock()
			a.connectionContext, a.connectionCancel = later, cancelLater
			before := a.state
			a.mu.Unlock()
			failure := a.finalizeCancelledFallbackFor("later Linux attempt", later)
			if !errors.Is(failure, errDesktopNodeOperationReplaced) || a.cmd != command || session.active != host ||
				host.process.Alive() != nil || host.transaction.control.Current(ctx) != nil || a.state != before {
				return errors.New("Linux fallback cancellation adopted an older request's active host")
			}
			a.mu.Lock()
			a.connectionContext, a.connectionCancel = operation, cancelOperation
			a.mu.Unlock()
		}
		if scenario == "active-release" {
			if err := a.releaseTransitionKillSwitch(); err == nil || a.cmd != command || session.active != host ||
				host.process.Alive() != nil || host.transaction.control.Current(ctx) != nil {
				return errors.New("Linux fallback release adopted an active native host")
			}
		}
		if scenario == "cancelled-active" {
			cancelOperation()
			failure := a.finalizeCancelledFallbackFor("original Linux attempt", operation)
			if !errors.Is(failure, errConnectionOperationCancelled) || errors.Is(failure, errDesktopNodeOperationReplaced) || a.state.Phase != "off" ||
				a.cmd != nil || session.active != nil || session.predecessor != nil || !host.closed || command.ProcessState == nil {
				return errors.Join(failure, errors.New("Linux cancelled fallback did not join and release its original request"))
			}
		} else {
			if err := a.stopModeWithIntent(true); err != nil || session.active != nil || session.predecessor != host.transaction ||
				host.transaction.baseline.ObserveClosed(ctx) != nil || command.ProcessState == nil || a.cmd != nil {
				return errors.Join(err, errors.New("Linux fallback did not retain its actual joined closed predecessor"))
			}
			if scenario == "temporary-deferred" {
				intent, stopIntent := context.WithCancel(context.Background())
				defer stopIntent()
				temporary := &speedLabTemporaryOwner{intent: intent, cancelIntent: stopIntent, test: operation, current: operation,
					runtime: command, mutated: true}
				if _, exists := speedLabTemporaryOwners.LoadOrStore(a, temporary); exists {
					return errors.New("Linux fallback fixture replaced another temporary test")
				}
				failure := a.releaseFallbackKillSwitch(operation)
				if !speedLabTemporaryOwners.CompareAndDelete(a, temporary) {
					return errors.New("Linux fallback fixture lost its own temporary test registration")
				}
				if failure != nil || session.predecessor != host.transaction || host.transaction.baseline.ObserveClosed(ctx) != nil {
					return errors.New("Linux fallback released the captured temporary test's restore protection")
				}
			}
			if scenario == "duplicate-owner" {
				desktopNodeOwners.Store(a, host.launch)
				failure := a.releaseTransitionKillSwitch()
				if !desktopNodeOwners.CompareAndDelete(a, host.launch) {
					return errors.New("Linux fallback fixture lost its duplicate legacy registration")
				}
				if failure == nil || session.predecessor != host.transaction || host.transaction.baseline.ObserveClosed(ctx) != nil {
					return errors.New("Linux fallback shared original protection with a duplicate legacy owner")
				}
			}
			if scenario == "strategy-failure" {
				if err := a.failStrategy("auto", []string{"captured candidate failed"}); err == nil || a.state.Phase != "failed" {
					return errors.New("Linux AUTO fallback lost the original strategy failure")
				}
			} else if err := a.releaseFallbackKillSwitch(operation); err != nil {
				return err
			}
		}
		if session.journal != journal || session.active != nil || a.cmd != nil || a.state.Connected || !host.closed || !host.released ||
			!host.transaction.engineJoined || !host.transaction.retired || command.ProcessState == nil {
			return errors.New("Linux fallback release preceded original joined durable retirement")
		}
		if scenario == "always" {
			if session.predecessor != host.transaction || host.transaction.baseline.ObserveClosed(ctx) != nil {
				return errors.New("Linux fallback released Always protection without its original successor")
			}
		} else if session.predecessor != nil || mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
			return errors.New("Linux fallback reported release without its original Node-family absence")
		}
	}
	if _, err := os.Lstat(legacy); !errors.Is(err, os.ErrNotExist) {
		return errors.New("Linux fallback entered legacy release for retained Node protection")
	}
	var table string
	var retained []byte
	if scenario == "always" {
		table = session.predecessor.head.Record.Committed.Target.Native.TableName
		retained, err = exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", table).Output()
		if err != nil || len(retained) == 0 {
			return errors.Join(err, errors.New("Linux Always fallback lost its independently readable native guard"))
		}
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	if !session.closed || !session.released || a.cmd != nil {
		return errors.New("Linux fallback left its original terminal owner unjoined")
	}
	if table != "" {
		actual, err := exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", table).Output()
		if err != nil || !bytes.Equal(actual, retained) {
			return errors.Join(err, errors.New("Linux terminal fallback changed its exact retained Always table"))
		}
	} else if mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
		return errors.New("Linux terminal fallback lost its original native absence")
	}
	controller.close()
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func linuxNodeFallbackLegacy(ctx context.Context, a *app, session *desktopLinuxNodeSession, marker string) error {
	command := exec.CommandContext(ctx, "nft", "-f", "-")
	command.Stdin = strings.NewReader("add table inet router_vpn_killswitch\nadd chain inet router_vpn_killswitch output { type filter hook output priority -310; policy drop; }\n")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("Linux fallback fixed guard fixture: %w: %s", err, output)
	}
	before, err := exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", "router_vpn_killswitch").Output()
	if err != nil {
		return err
	}
	if err := a.releaseTransitionKillSwitch(); err != nil || session.journal != nil || session.active != nil || session.predecessor != nil {
		return errors.Join(err, errors.New("Linux empty fallback swallowed its actual legacy release dispatcher"))
	}
	if _, err := os.Stat(marker); err != nil {
		return errors.New("Linux empty fallback did not defer to its legacy release dispatcher")
	}
	actual, err := exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", "router_vpn_killswitch").Output()
	if err != nil || !bytes.Equal(actual, before) {
		return errors.Join(err, errors.New("Linux empty fallback adopted or changed the fixed legacy guard"))
	}
	// The marker dispatcher does not model native release. Only this fixture
	// removes its own unchanged test guard in the private network namespace.
	return exec.CommandContext(ctx, "nft", "delete", "table", "inet", "router_vpn_killswitch").Run()
}

func TestDesktopLinuxGuardianKernelNodeFallback(t *testing.T) {
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node fallback requires its actual isolated guardian namespace", err)
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
	for _, scenario := range linuxNodeFallbackCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			child := startLinuxNodeParentProcess(t, installed, "fallback/"+scenario)
			child.retire(t, "")
		})
	}
}
