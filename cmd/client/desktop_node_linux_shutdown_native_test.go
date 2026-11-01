//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

func linuxShutdownTable(ctx context.Context, session string) ([]byte, error) {
	return exec.CommandContext(ctx, "nft", "-j", "-s", "-n", "list", "table", "inet", "router_vpn_node_"+session).CombinedOutput()
}

func linuxShutdownSelection(ctx context.Context, journal *desktopLinuxNodeJournal) (linuxprotection.JournalSelection, error) {
	if err := journal.enter(ctx); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	defer func() { journal.gate <- struct{}{} }()
	selected, _, err := journal.readSelection()
	return selected, err
}

func linuxShutdownRefusesAdmission(ctx context.Context, transaction *desktopLinuxNodeTransaction, journal *desktopLinuxNodeJournal) error {
	parent := transaction.parent
	if parent.Current(ctx) == nil || parent.parent.Current(ctx) == nil || parent.parent.ctx.Err() != nil {
		return errors.New("Linux shutdown lost permanent admission refusal or prematurely cancelled its original parent")
	}
	if parent.retirementCurrent(ctx) != nil {
		return errors.New("Linux shutdown lost the exact native parent before joined durable settlement")
	}
	if parent.parent.image == nil || parent.parent.processWitness == nil || journal.closed || journal.root == nil {
		return errors.New("Linux shutdown closed original witnesses before all owned transactions settled")
	}
	before, err := linuxShutdownSelection(ctx, journal)
	if err != nil {
		return err
	}
	// The ordinary storage API cannot acquire the retirement exception, even
	// with a structurally valid next record and the original journal pointer.
	next := linuxJournalCheckpoint(before)
	if _, err := journal.Append(ctx, before.SHA256, next); err == nil {
		return errors.New("terminal shutdown journal reopened ordinary native admission")
	}
	// A caller cannot borrow the joined transaction to prepare a new target.
	if _, err := journal.append(ctx, before.SHA256, next, transaction); err == nil {
		return errors.New("retirement-only journal accepted a fresh successor")
	}
	after, err := linuxShutdownSelection(ctx, journal)
	if err != nil || !reflect.DeepEqual(before, after) || journal.pending != nil {
		return errors.Join(err, errors.New("rejected terminal journal mutation changed its actual durable bytes"))
	}
	if captured, err := captureDesktopLinuxNodeParent(parent.app); err == nil || captured != nil {
		return errors.New("terminal shutdown recaptured an admission-capable native parent")
	}
	return nil
}

func linuxShutdownCancelJoin(ctx context.Context, a *app, transaction *desktopLinuxNodeTransaction, directory string) error {
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	short, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- a.retireNativeNodeForShutdownContext(short) }()
	if err := linuxTransactionWait(ctx, directory, "eof"); err != nil {
		return err
	}
	cancel()
	err := <-result
	if err == nil || transaction.engineJoined || transaction.retired || transaction.retirement == nil ||
		transaction.head.Record.Committed.Engine == nil || transaction.parent.lifetime.Err() != nil || transaction.parent.parent.closed ||
		transaction.journal.closed || transaction.process.command.ProcessState != nil || a.cmd != transaction.process.command {
		return errors.Join(err, errors.New("cancelled shutdown lost its unjoined original source receipt or parent authority"))
	}
	if err := transaction.baseline.ObserveClosed(ctx); err != nil {
		return err
	}
	selected, err := linuxShutdownSelection(ctx, transaction.journal)
	if err != nil || selected.Record.Committed.Engine == nil {
		return errors.Join(err, errors.New("cancelled shutdown falsely settled its durable engine before Cmd.Wait"))
	}
	return linuxTransactionMarker(directory, "finish")
}

func linuxShutdownRefusesFreshRetirementWrite(ctx context.Context, a *app, transaction *desktopLinuxNodeTransaction) error {
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	journal := transaction.journal
	before, err := journal.snapshot(ctx, transaction)
	if err != nil {
		return errors.Join(err, errors.New("fixture lost its valid joined retirement storage owner"))
	}
	next := linuxJournalCheckpoint(before)
	if err := linuxprotection.CheckJournalTransition(before.Record, next); err != nil {
		return errors.Join(err, errors.New("fixture did not construct a structurally valid fresh successor"))
	}
	if _, err := journal.append(ctx, before.SHA256, next, transaction); err == nil {
		return errors.New("retirement-only journal accepted a fresh successor while its original joined owner was valid")
	}
	after, err := journal.snapshot(ctx, transaction)
	if err != nil || !reflect.DeepEqual(before, after) || journal.pending != nil {
		return errors.Join(err, errors.New("fresh retirement-write refusal changed the original durable checkpoint"))
	}
	return nil
}

func linuxShutdownRejectReplacement(ctx context.Context, a *app, transaction *desktopLinuxNodeTransaction) error {
	replacement := exec.Command("/bin/sleep", "30")
	if err := replacement.Start(); err != nil {
		return err
	}
	defer func() { _ = replacement.Process.Kill(); _ = replacement.Wait() }()
	a.mu.Lock()
	original, phase, mode := a.cmd, a.state.Phase, a.state.RuntimeMode
	a.cmd, a.closing = replacement, true
	a.mu.Unlock()
	err := a.drainControllerOwner()
	if err == nil || a.cmd != replacement || a.state.Phase != phase || a.state.RuntimeMode != mode || transaction.stopRequested.Load() ||
		transaction.engineJoined || transaction.retired || transaction.journal.closed || transaction.head.Record.Committed.Engine == nil ||
		replacement.Process.Signal(syscall.Signal(0)) != nil {
		return errors.Join(err, errors.New("old shutdown touched or cleared the replacement app command"))
	}
	if transaction.bootstrap.Current(ctx) != nil {
		return errors.New("rejected replacement shutdown prematurely tore down the original authenticated engine")
	}
	if err := replacement.Process.Kill(); err != nil {
		return err
	}
	_ = replacement.Wait()
	a.mu.Lock()
	a.cmd = original
	a.mu.Unlock()
	return nil
}

func linuxTransactionShutdownFixture(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture, journal *desktopLinuxNodeJournal,
	transaction *desktopLinuxNodeTransaction, scenario, directory string, stopOperation context.CancelFunc) error {
	var preparation <-chan error
	if scenario == "shutdown-before-admission" {
		done := make(chan error, 1)
		go func() { done <- transaction.ServePreparation(ctx) }()
		preparation = done
		if err := linuxTransactionWait(ctx, directory, "prepared"); err != nil {
			return err
		}
	} else if scenario != "shutdown-before-prepare" {
		if err := linuxTransactionPrepare(ctx, transaction, scenario, directory, stopOperation); err != nil {
			return fmt.Errorf("shutdown original preparation: %w", err)
		}
	}
	var original *desktopLinuxNodeTransaction
	var closedAlways []byte
	if scenario == "shutdown-always" || scenario == "shutdown-successor-first" {
		if err := linuxTransactionRetire(ctx, transaction, scenario, directory); err != nil {
			return fmt.Errorf("shutdown predecessor retirement: %w", err)
		}
		if scenario == "shutdown-always" {
			var err error
			closedAlways, err = linuxShutdownTable(ctx, transaction.selection.SessionID)
			if err != nil {
				return fmt.Errorf("shutdown original successor construction: %w", err)
			}
		} else {
			original = transaction
			var err error
			transaction, stopOperation, directory, err = linuxTransactionStart(ctx, a, parent, journal, original,
				strings.Repeat("2", 32), "on-connect", "successor")
			if err != nil {
				return err
			}
			defer stopOperation()
			defer transaction.Close(context.Background())
			if err := linuxTransactionPrepare(ctx, transaction, "successor", directory, stopOperation); err != nil {
				return fmt.Errorf("shutdown original successor preparation: %w", err)
			}
		}
	}
	if scenario == "shutdown-request-ended" || scenario == "shutdown-always" {
		stopOperation()
		a.mu.Lock()
		a.connectionContext, a.connectionCancel = nil, nil
		a.mu.Unlock()
	}
	if scenario == "shutdown-always" {
		if err := linuxShutdownRefusesFreshRetirementWrite(ctx, a, transaction); err != nil {
			return err
		}
	}
	if scenario == "shutdown-retry" {
		if err := linuxShutdownCancelJoin(ctx, a, transaction, directory); err != nil {
			return err
		}
	}
	joinedReceipt := transaction.retirement
	if scenario == "shutdown-replacement" {
		if err := linuxShutdownRejectReplacement(ctx, a, transaction); err != nil {
			return err
		}
	}
	shutdown := newControllerShutdown(a, testControllerOwner)
	shutdown.retryDelay = 10 * time.Millisecond
	shutdown.begin()
	if scenario == "shutdown-before-admission" {
		if err := linuxTransactionMarker(directory, "continue"); err != nil {
			return err
		}
	}
	select {
	case <-shutdown.done:
	case <-parent.lifetime.Done():
		return errors.New("parent lifetime cancelled before authenticated retirement and durable settlement")
	case <-ctx.Done():
		return errors.Join(ctx.Err(), errors.New("actual controller shutdown did not settle its original Linux transaction"))
	}
	if preparation != nil {
		select {
		case err := <-preparation:
			if !errors.Is(err, linuxprotection.ErrNodeControlRefused) {
				return errors.Join(err, errors.New("shutdown admitted its cancelled prepared source"))
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !a.closing || a.cmd != nil || a.state.Connected || a.state.RuntimeMode != "" || a.state.Phase != "off" ||
		!transaction.retired || !transaction.engineJoined || !transaction.closed || !transaction.released ||
		transaction.process.command.ProcessState == nil || !transaction.process.closed || !transaction.process.released ||
		transaction.pending != nil || transaction.journal.pending != nil {
		return errors.New("actual terminal drain preceded original source/engine/journal retirement")
	}
	if scenario == "shutdown-retry" && (joinedReceipt == nil || transaction.retirement != joinedReceipt) {
		return errors.New("shutdown retry replaced its exact original source-join receipt")
	}
	if original != nil && (!original.closed || !original.released || !original.superseded || original.successor != nil) {
		return errors.New("terminal shutdown relied on dependent map order instead of original successor-first retirement")
	}
	if err := linuxShutdownRefusesAdmission(ctx, transaction, journal); err != nil {
		return err
	}
	selected, err := linuxShutdownSelection(ctx, journal)
	if err != nil || selected.Record.Phase != "settled" || selected.Record.Committed.Engine != nil || selected.Incomplete {
		return errors.Join(err, errors.New("shutdown did not flush its complete original joined checkpoint"))
	}
	if scenario == "shutdown-always" {
		after, err := linuxShutdownTable(ctx, transaction.selection.SessionID)
		if err != nil || !bytes.Equal(closedAlways, after) || selected.Record.Committed.Target == nil ||
			selected.Record.Committed.Target.Native != transaction.prepared.Protection || selected.Record.Committed.Target.Policy != "always" {
			return errors.Join(err, errors.New("shutdown removed or replaced the original closed Always table"))
		}
	} else if selected.Record.Committed.Target != nil || mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
		return errors.New("On-connect shutdown did not release only after original joined durable settlement")
	}
	parent.controller.close()
	if !parent.parent.closed || parent.lifetime.Err() == nil || !journal.closed || !journal.released ||
		parent.parent.image != nil || parent.parent.processWitness != nil || parent.parent.root != nil {
		return errors.New("terminal controller exit retained an unjoined original native owner")
	}
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func TestDesktopLinuxGuardianKernelNodeShutdown(t *testing.T) {
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node shutdown requires its actual isolated guardian namespace", err)
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
	// Always is last: its real closed table intentionally survives controller
	// exit until this private network namespace itself is destroyed.
	for _, scenario := range []string{"shutdown-on-connect", "shutdown-request-ended", "shutdown-before-prepare", "shutdown-before-admission",
		"shutdown-retry", "shutdown-successor-first", "shutdown-replacement", "shutdown-always"} {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			child := startLinuxNodeParentProcess(t, installed, "transaction/"+scenario)
			child.retire(t, "")
		})
	}
}
