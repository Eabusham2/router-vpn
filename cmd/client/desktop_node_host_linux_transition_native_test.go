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

var linuxNodeTransitionCases = []string{"empty", "fixed-active", "fixed-wrong-family", "unrelated-table", "node-predecessor",
	"command-replaced", "operation-replaced", "cancelled", "entered-host"}

// The original installed controller, processes, guards and session below are
// real. Legacy presentation and the established Node transaction's graph
// readiness are modeled. This proves refusal before Stop, not legacy tunnel
// traffic, supported cross-owner succession or public Connect admission.
func linuxNodeTransitionFixture(controller *ownedDesktopController, scenario string) error {
	profile, _, err := linuxTransactionProfile("on-connect")
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
	gate := os.NewFile(3, "transition-rendezvous")
	defer gate.Close()
	if err := linuxprocess.SetCloseOnExec(gate); err != nil {
		return err
	}
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != 1 {
		return errors.Join(err, errors.New("Linux transition lost its original rendezvous"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := linuxNodeLauncherPackage(); err != nil {
		return err
	}
	if err := linuxHostStartAssets(profile); err != nil {
		return err
	}
	verify := func(context.Context, string) (string, error) {
		return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
	}
	session, err := captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return err
	}
	var previous *desktopLinuxNodeHost
	var legacy, replacement *exec.Cmd
	startLegacy := func() (*exec.Cmd, error) {
		command := exec.Command("/bin/sleep", "35")
		return command, command.Start()
	}
	defer func() {
		// Only the fixture-created legacy commands have these wait owners.
		// The real Node predecessor is joined by its original retained session.
		for _, command := range []*exec.Cmd{legacy, replacement} {
			if command != nil && command.Process != nil && command.ProcessState == nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
		}
	}()
	if scenario == "node-predecessor" {
		previous, err = prepareDesktopLinuxNodeHostWith(operation, a, profile, "shadowsocks", 0, verify, nil)
		if err != nil {
			return err
		}
		if err := previous.Stage(ctx); err != nil {
			return err
		}
		environment := []string{linuxNodeTransactionMarker + "=1", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0"}
		if err := session.startWithVerifier(ctx, previous, environment, verify); err != nil {
			return err
		}
	} else if scenario != "empty" {
		legacy, err = startLegacy()
		if err != nil {
			return err
		}
		a.cmd = legacy
		a.state = state{Connected: true, Phase: "connected", Mode: "fixture-legacy", RuntimeMode: "fixture-legacy", RouterID: profile.ID}
	}
	host, err := prepareDesktopLinuxNodeHostWith(operation, a, profile, "shadowsocks", 0, verify, nil)
	if err != nil {
		return err
	}
	if scenario == "entered-host" {
		if err := host.Stage(ctx); err != nil {
			return err
		}
	}
	family, table := "", ""
	if scenario == "fixed-active" || scenario == "fixed-wrong-family" {
		family, table = "inet", "router_vpn_killswitch"
		if scenario == "fixed-wrong-family" {
			family = "ip"
		}
	} else if scenario == "unrelated-table" {
		family, table = "inet", "fixture_other_owner"
	}
	var nativeBefore []byte
	if table != "" {
		command := exec.CommandContext(ctx, "nft", "-f", "-")
		input := "add table " + family + " " + table + "\n"
		if strings.HasPrefix(scenario, "fixed-") {
			input += "add chain " + family + " " + table + " output { type filter hook output priority -310; policy drop; }\n"
		}
		command.Stdin = strings.NewReader(input)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("Linux transition fixture guard: %w: %s", err, output)
		}
		nativeBefore, err = exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", family, table).Output()
		if err != nil {
			return err
		}
	}
	originalCommand, originalState := a.cmd, a.state
	observer := mobiletor.ReadDesktopLinuxLegacyTransitionAbsence
	if scenario == "command-replaced" || scenario == "operation-replaced" {
		observer = func(ctx context.Context) error {
			if err := mobiletor.ReadDesktopLinuxLegacyTransitionAbsence(ctx); err != nil {
				return err
			}
			if scenario == "command-replaced" {
				replacement, err = startLegacy()
				if err != nil {
					return err
				}
				a.mu.Lock()
				a.cmd = replacement
				a.mu.Unlock()
			} else {
				later, cancelLater := context.WithCancel(context.Background())
				defer cancelLater()
				a.mu.Lock()
				a.connectionContext = later
				a.mu.Unlock()
			}
			return nil
		}
	}
	probe := ctx
	if scenario == "cancelled" {
		cancelled, stop := context.WithCancel(ctx)
		stop()
		probe = cancelled
	}
	var failure error
	if scenario == "command-replaced" || scenario == "operation-replaced" {
		failure = host.checkLegacyTransition(probe, observer)
	} else {
		failure = host.CheckLegacyTransition(probe)
	}
	refuse := strings.HasPrefix(scenario, "fixed-") || scenario == "command-replaced" || scenario == "operation-replaced" || scenario == "cancelled" || scenario == "entered-host"
	if refuse && failure == nil {
		return errors.New("Linux transition accepted its unsupported or replaced original boundary: " + scenario)
	}
	if !refuse && failure != nil {
		return failure
	}
	wantedCommand := originalCommand
	if replacement != nil {
		wantedCommand = replacement
	}
	if a.cmd != wantedCommand || a.state != originalState || session.active != previous || host.startEntered || host.process != nil || host.transaction != nil {
		return errors.New("Linux transition changed a previous connection before its caller entered Stop")
	}
	for _, command := range []*exec.Cmd{legacy, replacement} {
		if command != nil && (command.ProcessState != nil || command.Process.Signal(syscall.Signal(0)) != nil) {
			return errors.New("Linux transition retired a fixture's actual original legacy command")
		}
	}
	if previous != nil && (previous.process.Alive() != nil || previous.transaction.control.Current(ctx) != nil) {
		return errors.New("Linux fixed-guard preflight changed the actual original Node predecessor")
	}
	if table != "" {
		actual, err := exec.CommandContext(ctx, "nft", "-j", "-a", "list", "table", family, table).Output()
		if err != nil || !bytes.Equal(actual, nativeBefore) {
			return errors.Join(err, errors.New("Linux transition changed or adopted another owner's native guard"))
		}
		// This read-only preflight never removes a guard. The fixture disposes
		// only its own unchanged table in the private test network namespace.
		if err := exec.CommandContext(ctx, "nft", "delete", "table", family, table).Run(); err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.connectionContext = operation
	a.mu.Unlock()
	if err := host.Close(ctx); err != nil {
		return err
	}
	if previous != nil {
		if err := session.Retire(ctx, previous, true); err != nil {
			return err
		}
	} else {
		for _, command := range []*exec.Cmd{legacy, replacement} {
			if command != nil {
				_ = command.Process.Kill()
				_ = command.Wait()
				if command.ProcessState == nil {
					return errors.New("Linux transition fixture did not join its own original command")
				}
			}
		}
		a.mu.Lock()
		a.cmd, a.state = nil, state{}
		a.mu.Unlock()
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return err
	}
	controller.close()
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func TestDesktopLinuxGuardianKernelNodeTransition(t *testing.T) {
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node transition requires its actual isolated guardian namespace", err)
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
	for _, scenario := range linuxNodeTransitionCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			child := startLinuxNodeParentProcess(t, installed, "transition/"+scenario)
			child.retire(t, "")
		})
	}
}
