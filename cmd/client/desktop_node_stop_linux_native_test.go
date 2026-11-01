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
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobiletor"
)

var linuxNodeStopCases = []string{"on-connect", "hold-on-connect", "request-ended", "mtu-drain", "cancelled-retirement", "retirement-retry",
	"replaced-command", "replaced-operation", "replaced-session", "duplicate-legacy-owner", "partial-journal", "unused-session",
	"released-legacy", "released-legacy-closing", "released-node-guard", "released-journal-change", "closing-active", "always"}

// The production app Stop owns an actual installed controller, original
// engine/guardian, authenticated source and native nft table. The established
// transaction child models graph readiness; this is not a TUN/DNS traffic test.
func linuxNodeStopFixture(controller *ownedDesktopController, scenario string) error {
	policy := "on-connect"
	if scenario == "always" {
		policy = "always"
	}
	profile, _, err := linuxTransactionProfile(policy)
	if err != nil {
		return err
	}
	operation, stopOperation := context.WithCancel(context.Background())
	defer stopOperation()
	legacyMarker := filepath.Join(linuxOwnedControllerRoot, "legacy-stop-was-entered")
	a := &app{localController: controller, connectionContext: operation, connectionCancel: stopOperation,
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
			ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
			StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")},
		modes:    []common.Mode{{ID: "shadowsocks", StopCommand: []string{"/usr/bin/touch", legacyMarker}}},
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
	gate := os.NewFile(3, "app-stop-rendezvous")
	defer gate.Close()
	if err := linuxprocess.SetCloseOnExec(gate); err != nil {
		return err
	}
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != 1 {
		return errors.Join(err, errors.New("Linux app Stop lost its original rendezvous"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := linuxNodeLauncherPackage(); err != nil {
		return err
	}
	if err := linuxHostStartAssets(profile); err != nil {
		return err
	}
	session, err := captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return err
	}
	var alwaysTable string
	var alwaysBefore []byte
	verify := func(context.Context, string) (string, error) {
		return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
	}
	if scenario == "unused-session" {
		capture, err := a.captureDesktopNodeStop()
		if err != nil || capture != nil || session.journal != nil || session.active != nil || session.predecessor != nil {
			return errors.Join(err, errors.New("Linux Stop created or adopted an unused session"))
		}
	} else {
		host, err := prepareDesktopLinuxNodeHostWith(operation, a, profile, "shadowsocks", 0, verify, nil)
		if err != nil {
			return err
		}
		if err := host.Stage(ctx); err != nil {
			return err
		}
		environment := []string{linuxNodeTransactionMarker + "=1", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0"}
		if scenario == "retirement-retry" {
			environment = append(environment, "ROUTERVPN_LINUX_TRANSACTION_CASE=engine-join")
		}
		if scenario == "partial-journal" {
			path := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
			if err := os.Mkdir(path, 0700); err != nil {
				return err
			}
			marker := filepath.Join(path, "unowned-record")
			if err := os.WriteFile(marker, []byte("original foreign journal"), 0600); err != nil {
				return err
			}
			initial := session.startWithVerifier(ctx, host, environment, verify)
			if initial == nil || host.process != nil || session.active != host || session.journalErr != initial {
				return errors.New("Linux Stop fixture failed to retain partial journal creation")
			}
			if err := a.stopMode(); err != initial || session.active != nil || !host.closed || a.cmd != nil {
				return errors.New("Linux Stop lost its original partial creation error or host")
			}
			body, err := os.ReadFile(marker)
			if err != nil || string(body) != "original foreign journal" || session.journalErr != initial {
				return errors.Join(err, errors.New("Linux Stop changed another journal or forgot its uncertain original result"))
			}
		} else {
			if err := session.startWithVerifier(ctx, host, environment, verify); err != nil {
				return err
			}
			if session.active != host || host.transaction == nil || host.process == nil || a.cmd != host.process.command || a.state.Connected {
				return errors.New("Linux Stop fixture lost its actual admitted source or fabricated graph readiness")
			}
			command := a.cmd
			journal := session.journal
			capture, err := a.captureDesktopNodeStop()
			if err != nil || capture == nil || capture.host != host || capture.session != session || capture.command != command {
				return errors.Join(err, errors.New("Linux app Stop did not capture its original session and command"))
			}
			if scenario == "closing-active" {
				return linuxNodeStopClosingFixture(ctx, a, parent, session, host, capture, legacyMarker)
			}
			if scenario == "request-ended" {
				stopOperation()
			}
			if scenario == "cancelled-retirement" {
				ended, stop := context.WithCancel(ctx)
				stop()
				if err := capture.Retire(ended, command, true); err == nil || session.active != host || a.cmd != command || host.process.Alive() != nil {
					return errors.New("cancelled Linux Stop changed its retained original engine")
				}
			}
			if scenario == "replaced-operation" {
				a.mu.Lock()
				a.connectionContext = context.Background()
				a.mu.Unlock()
				if err := capture.Retire(ctx, command, true); err == nil || session.active != host || a.cmd != command || host.process.Alive() != nil {
					return errors.New("Linux Stop adopted a replacement operation")
				}
				a.mu.Lock()
				a.connectionContext = operation
				a.mu.Unlock()
			}
			if scenario == "duplicate-legacy-owner" {
				desktopNodeOwners.Store(a, host.launch)
				duplicate, failure := a.captureDesktopNodeStop()
				retireErr := capture.Retire(ctx, command, true)
				actual, retained := desktopNodeOwners.Load(a)
				if !desktopNodeOwners.CompareAndDelete(a, host.launch) {
					return errors.New("Linux duplicate-owner fixture lost its exact registry insertion")
				}
				if duplicate != nil || failure == nil || retireErr == nil || !retained || actual != host.launch ||
					session.active != host || a.cmd != command || host.process.Alive() != nil || host.transaction.control.Current(ctx) != nil {
					return errors.New("Linux Stop accepted duplicate legacy process ownership")
				}
			}
			if scenario == "replaced-session" {
				p := parent.parent
				<-p.gate
				p.session = &desktopLinuxNodeSession{}
				p.gate <- struct{}{}
				failure := capture.Retire(ctx, command, true)
				<-p.gate
				p.session = session
				p.gate <- struct{}{}
				if failure == nil || session.active != host || a.cmd != command || host.process.Alive() != nil {
					return errors.New("Linux Stop adopted a replacement session")
				}
			}
			if scenario == "replaced-command" {
				replacement := exec.Command("/bin/sleep", "20")
				if err := replacement.Start(); err != nil {
					return err
				}
				defer func() { _ = replacement.Process.Kill(); _ = replacement.Wait() }()
				a.mu.Lock()
				a.cmd = replacement
				a.mu.Unlock()
				failure := capture.Retire(ctx, command, true)
				if failure == nil || session.active != host || a.cmd != replacement || replacement.ProcessState != nil ||
					host.process.Alive() != nil || host.transaction.control.Current(ctx) != nil {
					return errors.New("Linux Stop changed its replacement command or original live source")
				}
				a.mu.Lock()
				a.cmd = command
				a.mu.Unlock()
			}
			if scenario == "retirement-retry" {
				short, stop := context.WithCancel(ctx)
				pending := make(chan error, 1)
				go func() { pending <- capture.Retire(short, command, true) }()
				if err := linuxTransactionWait(ctx, host.launch.directory, "eof"); err != nil {
					stop()
					return err
				}
				stop()
				failure := <-pending
				if failure == nil || session.active != host || a.cmd != command || host.transaction.engineJoined ||
					host.transaction.retired || host.transaction.head.Record.Committed.Engine == nil || a.state.Phase != "failed" {
					return errors.New("Linux Stop discarded its original unfinished retirement")
				}
				if err := host.transaction.baseline.ObserveClosed(ctx); err != nil {
					return err
				}
				if err := linuxTransactionMarker(host.launch.directory, "finish"); err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-host.process.joined:
				}
				// These two files belong only to this fixture's post-EOF join
				// rendezvous. Preserve the production workspace allowlist: remove
				// them through the retained root only after original Cmd.Wait.
				for _, name := range []string{"eof", "finish"} {
					body, err := readDesktopRuntimeFile(host.launch, name, 128)
					if err != nil || string(body) != "original fixture rendezvous\n" {
						return errors.Join(err, errors.New("Linux Stop fixture lost its owned join rendezvous"))
					}
					if err := host.launch.directoryRoot.Remove(name); err != nil {
						return err
					}
				}
			}
			var stopErr error
			if scenario == "mtu-drain" {
				lock := mtuRetestLockFor(a)
				lock.Lock()
				pending := make(chan error, 1)
				go func() { pending <- a.stopMode() }()
				deferred := true
				defer func() {
					if deferred {
						lock.Unlock()
					}
				}()
				deadline := time.NewTimer(2 * time.Second)
				defer deadline.Stop()
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					suspension := mtuSuspensionFor(a)
					suspension.mu.Lock()
					waiting := suspension.users > 0
					suspension.mu.Unlock()
					if waiting {
						break
					}
					select {
					case failure := <-pending:
						return errors.Join(failure, errors.New("Linux Stop bypassed the captured MTU drain"))
					case <-deadline.C:
						return errors.New("Linux Stop did not enter its actual MTU drain")
					case <-ticker.C:
					}
				}
				if session.active != host || a.cmd != command || host.process.Alive() != nil || host.transaction.control.Current(ctx) != nil {
					return errors.New("Linux Stop retired its source before owned MTU drained")
				}
				lock.Unlock()
				deferred = false
				stopErr = <-pending
			} else {
				stopErr = a.stopModeWithIntent(scenario == "hold-on-connect")
			}
			if _, err := os.Lstat(legacyMarker); !errors.Is(err, os.ErrNotExist) {
				return errors.New("Linux Stop entered legacy teardown for its authenticated native source")
			}
			if stopErr != nil {
				return stopErr
			}
			if session.active != nil || !host.closed || !host.released || !host.transaction.engineJoined || !host.transaction.retired ||
				host.process.command.ProcessState == nil || a.cmd != nil || a.state.Connected || a.state.Phase != "off" ||
				a.state.Mode != "off" || a.state.LogicalMode != "" || a.state.RuntimeMode != "" || a.state.Base != "" || session.journal != journal {
				return errors.New("Linux app Stop returned before original joined retirement and durable settlement")
			}
			if scenario == "always" || scenario == "hold-on-connect" {
				if session.predecessor != host.transaction || host.transaction.baseline.ObserveClosed(ctx) != nil {
					return errors.New("Linux Stop released the exact protection held for its successor")
				}
				if scenario == "hold-on-connect" {
					if err := a.stopMode(); err != nil || session.predecessor != nil || mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
						return errors.Join(err, errors.New("Linux Disconnect did not release its original held On-connect source"))
					}
				} else {
					alwaysTable = host.transaction.head.Record.Committed.Target.Native.TableName
					alwaysBefore, err = exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", alwaysTable).Output()
					if err != nil || len(alwaysBefore) == 0 {
						return errors.Join(err, errors.New("Linux Always Stop lost its independently readable closed table"))
					}
				}
			} else if session.predecessor != nil || mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
				return errors.New("Linux Stop retained an On-connect source after successful explicit Disconnect")
			}
			if strings.HasPrefix(scenario, "released-") {
				if err := linuxNodeStopLegacyFixture(ctx, a, session, scenario, legacyMarker); err != nil {
					return err
				}
			}
		}
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	if !session.closed || !session.released || a.cmd != nil || a.state.Connected {
		return errors.New("Linux app Stop left its original terminal owner unjoined")
	}
	if scenario != "always" && mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
		return errors.New("Linux app Stop lost its actual native absence after terminal closure")
	}
	if scenario == "always" {
		actual, err := exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", alwaysTable).Output()
		if err != nil || !bytes.Equal(actual, alwaysBefore) {
			return errors.Join(err, errors.New("Linux terminal closure changed the exact Always table retained by app Stop"))
		}
	}
	controller.close()
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

// An actual later legacy process owns its own Stop and fixed Tor/global deny
// table. The fixture proves dispatch and original process joining, not Tor
// traffic. Only the isolated fixture removes its exact unchanged test table;
// held production protection is never inferred to be released by that cleanup.
func linuxNodeStopLegacyFixture(ctx context.Context, a *app, session *desktopLinuxNodeSession, scenario, marker string) error {
	journal := session.journal
	if journal == nil || session.active != nil || session.predecessor != nil {
		return errors.New("Linux legacy Stop fixture requires its released original Node session")
	}
	checkpoint := append([]byte(nil), journal.currentBytes...)
	table := "router_vpn_killswitch"
	if scenario == "released-node-guard" {
		table = "router_vpn_node_" + strings.Repeat("f", 32)
	}
	install := exec.CommandContext(ctx, "nft", "-f", "-")
	install.Stdin = strings.NewReader("add table inet " + table + "\nadd chain inet " + table + " output { type filter hook output priority -310; policy drop; }\n")
	if output, err := install.CombinedOutput(); err != nil {
		return fmt.Errorf("Linux legacy guard fixture failed: %w: %s", err, output)
	}
	before, err := exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", table).Output()
	if err != nil || len(before) == 0 {
		return errors.Join(err, errors.New("Linux legacy guard fixture lost its native table"))
	}
	legacy := exec.Command("/bin/sleep", "20")
	if err := legacy.Start(); err != nil {
		return err
	}
	defer func() {
		if legacy.ProcessState == nil {
			_ = legacy.Process.Kill()
			_ = legacy.Wait()
		}
	}()
	a.mu.Lock()
	a.modes = append(a.modes, common.Mode{ID: "tor", StopCommand: []string{"/usr/bin/touch", marker}})
	a.cmd = legacy
	a.state.Mode, a.state.RuntimeMode, a.state.Phase, a.state.Connected = "tor", "tor", "connected", true
	if scenario == "released-legacy-closing" {
		a.closing = true
	}
	a.mu.Unlock()
	if scenario == "released-journal-change" {
		body := append(append([]byte(nil), checkpoint...), byte('!'))
		file := journal.slots[journal.current.Slot].file
		if n, err := file.WriteAt(body, 0); err != nil || n != len(body) {
			return errors.Join(err, errors.New("Linux journal fixture could not alter its owned selected slot"))
		}
	}
	if scenario == "released-node-guard" || scenario == "released-journal-change" {
		capture, captureErr := a.captureDesktopNodeStop()
		stopErr := a.stopModeWithIntent(true)
		if capture != nil || captureErr == nil || stopErr == nil || a.cmd != legacy || legacy.ProcessState != nil ||
			legacy.Process.Signal(syscall.Signal(0)) != nil || !a.state.Connected {
			return errors.New("Linux empty Stop dispatch accepted unresolved Node protection or changed storage")
		}
		if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
			return errors.New("Linux empty Stop dispatch entered legacy cleanup before original absence")
		}
		if scenario == "released-journal-change" {
			file := journal.slots[journal.current.Slot].file
			if n, err := file.WriteAt(checkpoint, 0); err != nil || n != len(checkpoint) {
				return errors.Join(err, errors.New("Linux journal fixture lost its original selected slot"))
			}
			if err := file.Truncate(int64(len(checkpoint))); err != nil {
				return err
			}
		}
	}
	checkGuard := func() error {
		actual, err := exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", "inet", table).Output()
		if err != nil || !bytes.Equal(actual, before) {
			return errors.Join(err, errors.New("Linux Node Stop changed a later connection's exact native guard"))
		}
		return nil
	}
	if err := checkGuard(); err != nil {
		return err
	}
	if scenario == "released-node-guard" {
		// This unknown Node-family table is fixture-owned. Production Stop must
		// refuse it; only this test removes it before exercising legacy Stop.
		if output, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", table).CombinedOutput(); err != nil {
			return fmt.Errorf("Linux fixture Node guard cleanup failed: %w: %s", err, output)
		}
	}
	capture, err := a.captureDesktopNodeStop()
	if err != nil || capture != nil {
		return errors.Join(err, errors.New("Linux released Node session blocked its later legacy Stop"))
	}
	if err := a.stopModeWithIntent(true); err != nil || a.cmd != nil || a.state.Connected || a.state.Phase != "off" || legacy.ProcessState == nil {
		return errors.Join(err, errors.New("Linux released Node session did not join its later legacy Stop"))
	}
	if _, err := os.Stat(marker); err != nil || session.journal != journal || !bytes.Equal(journal.currentBytes, checkpoint) ||
		session.active != nil || session.predecessor != nil {
		return errors.Join(err, errors.New("Linux legacy Stop lost its own callback or changed the original empty session"))
	}
	if scenario != "released-node-guard" {
		if err := checkGuard(); err != nil {
			return err
		}
		if output, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", table).CombinedOutput(); err != nil {
			return fmt.Errorf("Linux fixture fixed guard cleanup failed: %w: %s", err, output)
		}
	}
	return nil
}

func linuxNodeStopClosingFixture(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture, session *desktopLinuxNodeSession,
	host *desktopLinuxNodeHost, capture *desktopNodeStopCapture, marker string) error {
	command := a.cmd
	bootstrap, err := host.process.Bootstrap(ctx)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	fresh, freshErr := a.captureDesktopNodeStop()
	stopErr := a.stopMode()
	retireErr := capture.Retire(ctx, command, true)
	// The ordinary process accessor deliberately rejects new admission after
	// closing. Observe the already retained native channel/process instead.
	nativeErr, controlErr := bootstrap.Current(ctx), host.transaction.control.Current(ctx)
	if fresh != nil || freshErr == nil || stopErr == nil || retireErr == nil || a.cmd != command || session.active != host ||
		nativeErr != nil || controlErr != nil {
		return errors.Join(nativeErr, controlErr, errors.New("Linux closing Stop bypassed its active original retirement owner"))
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		return errors.New("Linux closing Stop entered legacy cleanup for an active native source")
	}
	if err := a.retireNativeNodeForShutdownContext(ctx); err != nil {
		return err
	}
	if a.cmd != nil || a.state.Connected || !host.transaction.engineJoined || !host.transaction.retired || command.ProcessState == nil {
		return errors.New("Linux ordered shutdown did not join the retained closing source")
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	if !session.closed || !session.released || !host.closed || !host.released || mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
		return errors.New("Linux closing Stop lost its original settled terminal cleanup")
	}
	parent.controller.close()
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func TestDesktopLinuxGuardianKernelNodeStop(t *testing.T) {
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node Stop requires its actual isolated guardian namespace", err)
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
	for _, scenario := range linuxNodeStopCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			child := startLinuxNodeParentProcess(t, installed, "stop/"+scenario)
			child.retire(t, "")
		})
	}
}
