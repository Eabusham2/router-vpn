//go:build windows && routervpn_windows_protection_native

package windowsprotection

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

// The subprocess waits for its actual parent to close a test-owned stdin
// rendezvous. Production recovery never signals a PID from a journal record.
func TestWindowsProtectionJournalRecoveryFixture(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 1 || arguments[0] != "retained-process" {
		t.Fatal("unknown native retirement fixture role")
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 16))
	if err != nil || string(input) != "finish\n" {
		t.Fatal("native retirement fixture lost its actual parent rendezvous", err)
	}
}

type journalRecoveryFixtureProcess struct {
	process *windowscontroller.Process
	capture Controller
	finish  func()
}

func journalRecoveryStartProcess(t *testing.T) *journalRecoveryFixtureProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	command := exec.CommandContext(ctx, executable, "-test.run=^TestWindowsProtectionJournalRecoveryFixture$", "-test.count=1", "-test.timeout=40s", "--", "retained-process")
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		cancel()
		_ = input.Close()
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { joined <- command.Wait() }()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			_, writeErr := io.WriteString(input, "finish\n")
			closeErr := input.Close()
			waitErr := <-joined
			cancel()
			if err := errors.Join(writeErr, closeErr, waitErr); err != nil {
				t.Error("actual retirement fixture did not join its own child", err, output.String())
			}
		})
	}
	t.Cleanup(finish)
	process, err := windowscontroller.OpenProcess(uint32(command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Close() })
	capture, _, err := journalProcessCapture(process)
	if err != nil {
		t.Fatal(err)
	}
	return &journalRecoveryFixtureProcess{process: process, capture: capture, finish: finish}
}

type journalNativeRecoveryObservation struct {
	callback func(context.Context, int) error
	matched  int
	reads    int
	closed   bool
	entered  chan struct{}
	release  chan struct{}
	after    func() error
}

func (observation *journalNativeRecoveryObservation) Run(ctx context.Context) error {
	observation.reads++
	if observation.entered != nil {
		close(observation.entered)
		<-observation.release
	}
	if err := observation.callback(ctx, observation.matched); err != nil {
		return err
	}
	if observation.after != nil {
		return observation.after()
	}
	return nil
}

func (observation *journalNativeRecoveryObservation) Close(context.Context) error {
	observation.closed = true
	return nil
}

func journalNativeRecoveryBegin(t *testing.T, store *ProtectionJournal, matched int) (*JournalRecovery, *journalNativeRecoveryObservation) {
	t.Helper()
	observation := &journalNativeRecoveryObservation{matched: matched}
	owner, err := store.beginRecovery(context.Background(), func(targets []*mobiletor.DesktopWindowsProtectionTarget, callback func(context.Context, int) error) (journalRecoveryObservation, error) {
		if len(targets) < 1 || matched < 0 || matched >= len(targets) {
			t.Fatal("native storage fixture lost its exact BFE candidate")
		}
		observation.callback = callback
		return observation, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return owner, observation
}

// Only BFE is modeled in this suite. The protected ACLs, immutable file/Data
// identities, exclusive lock, process snapshot, creation/token queries, exit
// waits, writes, flushes and readback use actual Windows operations. The real
// BFE observation transaction has separate scoped native tests in mobiletor.
func journalNativeRecoveryReopen(t *testing.T, fixture *journalNativeFixture, previous, current JournalRecord) *ProtectionJournal {
	t.Helper()
	store := fixture.store
	if previous.JournalID != store.header.JournalID || current.JournalID != store.header.JournalID || CheckJournalTransition(previous, current) != nil {
		t.Fatal("native recovery fixture must preserve an exact historical comparison chain")
	}
	var bodies [2][]byte
	bodies[(previous.Sequence-1)%2] = journalTestBody(t, previous)
	bodies[(current.Sequence-1)%2] = journalTestBody(t, current)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for index, body := range bodies {
		journalNativeOverwrite(t, store.api, store.slots[index].path, body)
	}
	opened, err := journalNativeOpen(t, fixture)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store = opened
	return opened
}

func journalNativeRecoveryInitial(fixture *journalNativeFixture, controller Controller) JournalRecord {
	initial := journalTestInitial()
	initial.JournalID, initial.Controller = fixture.store.header.JournalID, controller
	return initial
}

func journalNativeRecoveryLive(t *testing.T, fixture *journalNativeFixture, controller, engine Controller, live bool) (JournalRecord, JournalRecord) {
	t.Helper()
	initial := journalNativeRecoveryInitial(fixture, controller)
	intent := journalTestNext(t, initial)
	intent.Phase = "intent"
	candidate := journalTestState("b", false)
	candidate.Engine = &engine
	intent.Intent = &JournalIntent{Action: "successor", RequestID: strings.Repeat("b", 32), ProfileID: candidate.ProfileID,
		ProfileRevision: candidate.ProfileRevision, ResultProfileRevision: candidate.ProfileRevision, Candidate: candidate}
	state := cloneJournalState(intent.Intent.Candidate)
	if !live {
		state.Engine = nil
	}
	settled := journalTestSettled(t, intent, state)
	return intent, settled
}

func journalNativeRecoveryOff(t *testing.T, fixture *journalNativeFixture, controller Controller) (JournalRecord, JournalRecord) {
	t.Helper()
	retained := journalTestRetained(t)
	retained.JournalID, retained.Controller = fixture.store.header.JournalID, controller
	off := journalTestNext(t, retained)
	off.Phase = "intent"
	off.Intent = &JournalIntent{Action: "off", RequestID: strings.Repeat("c", 32), ProfileID: retained.Committed.ProfileID,
		ProfileRevision: strings.Repeat("8", 64), ResultProfileRevision: strings.Repeat("d", 64)}
	return retained, off
}

func TestWindowsProtectionJournalRecoveryNativeControllerRetirement(t *testing.T) {
	fixture := journalNativeCreate(t)
	old := journalRecoveryStartProcess(t)
	previous := journalNativeRecoveryInitial(fixture, old.capture)
	current := journalTestNext(t, previous)
	store := journalNativeRecoveryReopen(t, fixture, previous, current)
	owner, observation := journalNativeRecoveryBegin(t, store, 0)
	if _, err := owner.Run(context.Background()); err == nil || observation.reads != 0 || store.pending != nil {
		t.Fatal("a live old controller reached native observation or journal adoption")
	}
	if err := old.process.Alive(); err != nil {
		t.Fatal("recovery signalled a recorded live controller", err)
	}
	if _, err := store.Snapshot(context.Background()); err == nil {
		t.Fatal("unresolved recovery acquired ordinary snapshot admission")
	}
	if _, err := store.Append(context.Background(), store.current.SHA256, journalTestNext(t, store.current.Record)); err == nil {
		t.Fatal("ordinary append replaced the entered recovery owner")
	}
	old.finish()
	result, err := owner.Run(context.Background())
	if err != nil || result.Selection.Record.Controller != store.controller || result.Observed.Target != nil || store.recovery != nil || !observation.closed {
		t.Fatal("actual old-controller exit did not permit its exact durable handover", err)
	}
	if _, err := store.Snapshot(context.Background()); err != nil {
		t.Fatal("joined recovery did not release the native journal snapshot", err)
	}
	if _, err := store.Append(context.Background(), result.Selection.SHA256, journalTestNext(t, result.Selection.Record)); err != nil {
		t.Fatal("new controller could not append while preserving adopted provenance", err)
	}
}

func TestWindowsProtectionJournalRecoveryNativeEngineRetirement(t *testing.T) {
	for _, phase := range []string{"settled-live", "pending-successor"} {
		t.Run(phase, func(t *testing.T) {
			fixture := journalNativeCreate(t)
			old := journalRecoveryStartProcess(t)
			engine := journalRecoveryStartProcess(t)
			intent, settled := journalNativeRecoveryLive(t, fixture, old.capture, engine.capture, true)
			previous, current, matched := intent, settled, 0
			if phase == "pending-successor" {
				previous, current, matched = journalNativeRecoveryInitial(fixture, old.capture), intent, 1
			}
			old.finish()
			store := journalNativeRecoveryReopen(t, fixture, previous, current)
			owner, observation := journalNativeRecoveryBegin(t, store, matched)
			if _, err := owner.Run(context.Background()); err == nil || observation.reads != 0 || store.pending != nil {
				t.Fatal("a live recorded source reached controller adoption")
			}
			if err := engine.process.Alive(); err != nil {
				t.Fatal("recovery signalled the recorded native engine", err)
			}
			engine.finish()
			result, err := owner.Run(context.Background())
			if err != nil || result.Observed.Target == nil || result.Observed.Engine != nil || result.Observed.ProfileRevision != settled.Committed.ProfileRevision ||
				*result.Observed.Target != *settled.Committed.Target || result.Selection.Record.Intent != nil {
				t.Fatal("actual source exit lost its captured Always/source binding", err)
			}
		})
	}
}

func TestWindowsProtectionJournalRecoveryNativePendingOff(t *testing.T) {
	for _, matched := range []int{0, 1} {
		t.Run(map[int]string{0: "retained", 1: "absence-unsaved"}[matched], func(t *testing.T) {
			fixture := journalNativeCreate(t)
			old := journalRecoveryStartProcess(t)
			previous, current := journalNativeRecoveryOff(t, fixture, old.capture)
			old.finish()
			store := journalNativeRecoveryReopen(t, fixture, previous, current)
			owner, _ := journalNativeRecoveryBegin(t, store, matched)
			result, err := owner.Run(context.Background())
			if err != nil || result.Selection.Record.Phase != "intent" || result.Selection.Record.Intent == nil ||
				result.Selection.Record.Intent.RequestID != current.Intent.RequestID ||
				result.Selection.Record.Intent.ProfileRevision != current.Intent.ProfileRevision ||
				result.Selection.Record.Intent.ResultProfileRevision != current.Intent.ResultProfileRevision ||
				result.Selection.Record.Committed.ProfileRevision != current.Committed.ProfileRevision ||
				(result.Observed.Target == nil) != (matched == 1) {
				t.Fatal("native recovery cleared or rebound an accepted Off before saved-profile acknowledgment", err)
			}
		})
	}
}

func TestWindowsProtectionJournalRecoveryNativePIDReuseAndToken(t *testing.T) {
	for _, change := range []string{"reused-creation", "wrong-token"} {
		t.Run(change, func(t *testing.T) {
			fixture := journalNativeCreate(t)
			original := fixture.store.controller
			recorded := original
			if change == "reused-creation" {
				recorded.StartTimeUTCTicks--
			} else {
				recorded.AuthenticationID++
			}
			previous := journalNativeRecoveryInitial(fixture, recorded)
			current := journalTestNext(t, previous)
			store := journalNativeRecoveryReopen(t, fixture, previous, current)
			owner, observation := journalNativeRecoveryBegin(t, store, 0)
			result, err := owner.Run(context.Background())
			if change == "reused-creation" {
				if err != nil || result.Selection.Record.Controller != original || observation.reads != 1 {
					t.Fatal("recorded prior creation was confused with the live replacement process", err)
				}
			} else if err == nil || observation.reads != 0 || store.pending != nil {
				t.Fatal("matching creation with the wrong primary token gained recovery authority")
			}
			actual, _, err := journalProcessCapture(store.self)
			if err != nil || actual != original {
				t.Fatal("recovery touched a live replacement or mismatching token owner", err)
			}
		})
	}
}

func TestWindowsProtectionJournalRecoveryNativeExactAppendRetry(t *testing.T) {
	fixture := journalNativeCreate(t)
	old := journalRecoveryStartProcess(t)
	previous, current := journalNativeRecoveryOff(t, fixture, old.capture)
	old.finish()
	store := journalNativeRecoveryReopen(t, fixture, previous, current)
	owner, observation := journalNativeRecoveryBegin(t, store, 1)
	file := store.slots[1-store.current.Slot]
	original := file.handle
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var limited syscall.Handle
	if err := syscall.DuplicateHandle(self, original, self, &limited, 0x00120089 /* FILE_GENERIC_READ */, false, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		file.handle = original
		if limited != 0 {
			_ = syscall.CloseHandle(limited)
		}
	}()
	file.handle = limited
	if result, err := owner.Run(context.Background()); err == nil || result.Selection.Record.Sequence != 0 || store.pending == nil {
		t.Fatal("denied native adoption write was acknowledged or lost its pending owner")
	}
	pending, body := store.pending, append([]byte(nil), store.pending.body...)
	file.handle = original
	if err := syscall.CloseHandle(limited); err != nil {
		t.Fatal(err)
	}
	limited = 0
	observation.matched = 0
	if _, err := owner.Run(context.Background()); err == nil || store.pending != pending || !bytes.Equal(store.pending.body, body) {
		t.Fatal("recovery replaced its exact pending native adoption with another outcome")
	}
	observation.matched = 1
	result, err := owner.Run(context.Background())
	if err != nil || result.Selection.SHA256 != pending.digest || store.pending != nil || store.recovery != nil || !bytes.Equal(journalTestBody(t, result.Selection.Record), body) {
		t.Fatal("same native adoption could not retry its original retained slot and bytes", err)
	}
}

func TestWindowsProtectionJournalRecoveryNativeLegacyAndTornState(t *testing.T) {
	for _, fault := range []string{"legacy-unbound", "torn-peer", "retired-desktop"} {
		t.Run(fault, func(t *testing.T) {
			fixture := journalNativeCreate(t)
			old := journalRecoveryStartProcess(t)
			previous, current := journalNativeRecoveryOff(t, fixture, old.capture)
			if fault == "legacy-unbound" {
				previous.Committed.ProfileRevision = ""
				current = journalTestNext(t, previous)
				current.Phase = "intent"
				current.Intent = &JournalIntent{Action: "off", RequestID: strings.Repeat("c", 32), ProfileID: previous.Committed.ProfileID,
					ProfileRevision: strings.Repeat("8", 64), ResultProfileRevision: strings.Repeat("d", 64)}
			}
			old.finish()
			store := journalNativeRecoveryReopen(t, fixture, previous, current)
			if fault == "torn-peer" {
				peer := store.slots[1-store.current.Slot].path
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				journalNativeOverwrite(t, store.api, peer, []byte("{\"torn\":"))
				var err error
				store, err = journalNativeOpen(t, fixture)
				if err != nil {
					t.Fatal(err)
				}
			}
			var before [2][]byte
			for index, file := range store.slots {
				var err error
				before[index], err = journalReadRetained(file, JournalRecordLimit)
				if err != nil {
					t.Fatal(err)
				}
			}
			if fault == "retired-desktop" {
				owner, observation := journalNativeRecoveryBegin(t, store, 1)
				if err := store.desktop.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Run(context.Background()); err == nil || observation.reads != 0 {
					t.Fatal("retired original desktop granted restart recovery authority")
				}
			} else {
				called := false
				owner, err := store.beginRecovery(context.Background(), func([]*mobiletor.DesktopWindowsProtectionTarget, func(context.Context, int) error) (journalRecoveryObservation, error) {
					called = true
					return nil, errors.New("unexpected observation")
				})
				if err == nil || owner != nil || called || store.pending != nil {
					t.Fatal("unbound or torn journal acquired checked adoption authority")
				}
			}
			for index, file := range store.slots {
				actual, err := journalReadRetained(file, JournalRecordLimit)
				if err != nil || !bytes.Equal(actual, before[index]) {
					t.Fatal("rejected restart changed unknown or unbound journal evidence", err)
				}
			}
		})
	}
}

func TestWindowsProtectionJournalRecoveryNativeSnapshotAndExit(t *testing.T) {
	protectionRequireNative(t)
	snapshot, err := captureJournalProcessSnapshot(context.Background())
	if snapshot != nil {
		defer snapshot.close()
	}
	if err != nil || !snapshot.complete || !snapshot.pids[uint32(os.Getpid())] {
		t.Fatal("actual native process snapshot did not prove its complete process list", err)
	}
	child := journalRecoveryStartProcess(t)
	witness := &journalRetirementWitness{recorded: child.capture, process: child.process}
	if err := witness.prove(context.Background()); err == nil || witness.retired {
		t.Fatal("retained live process was treated as a joined old owner")
	}
	child.finish()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wrong := &journalRetirementWitness{recorded: child.capture, process: child.process}
	wrong.recorded.AuthenticationID++
	if err := wrong.prove(ctx); err == nil || wrong.retired {
		t.Fatal("exited process with a different recorded primary token was accepted")
	}
	if err := witness.prove(ctx); err != nil || !witness.retired {
		t.Fatal("actual signalled retained process did not prove its recorded exit", err)
	}
	if err := child.process.Close(); err != nil {
		t.Fatal(err)
	}
	witness.retired = false
	if err := witness.prove(ctx); err == nil || witness.retired {
		t.Fatal("closed retained handle was mistaken for process exit")
	}
}

func TestWindowsProtectionJournalRecoveryNativeCloseJoinsObservation(t *testing.T) {
	fixture := journalNativeCreate(t)
	old := journalRecoveryStartProcess(t)
	previous := journalNativeRecoveryInitial(fixture, old.capture)
	current := journalTestNext(t, previous)
	old.finish()
	store := journalNativeRecoveryReopen(t, fixture, previous, current)
	owner, observation := journalNativeRecoveryBegin(t, store, 0)
	observation.entered, observation.release = make(chan struct{}), make(chan struct{})
	ran := make(chan error, 1)
	go func() { _, err := owner.Run(context.Background()); ran <- err }()
	<-observation.entered
	closed := make(chan error, 1)
	go func() { closed <- store.Close() }()
	<-owner.lifetime.Done()
	select {
	case <-closed:
		t.Fatal("journal file handles closed while recovery observation was still entered")
	default:
	}
	close(observation.release)
	if err := <-ran; err == nil {
		t.Fatal("closing journal admitted a cancelled controller handover")
	}
	if err := <-closed; err != nil || !observation.closed || store.lock.handle != 0 || store.slots[0].handle != 0 || store.slots[1].handle != 0 {
		t.Fatal("native journal close did not join recovery before its exact files", err)
	}
}

func TestWindowsProtectionJournalRecoveryNativeStickyClose(t *testing.T) {
	fixture := journalNativeCreate(t)
	old := journalRecoveryStartProcess(t)
	previous := journalNativeRecoveryInitial(fixture, old.capture)
	current := journalTestNext(t, previous)
	old.finish()
	initial := fixture.store
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	for _, record := range []JournalRecord{previous, current} {
		journalNativeOverwrite(t, initial.api, initial.slots[(record.Sequence-1)%2].path, journalTestBody(t, record))
	}
	store, err := openProtectionJournal(context.Background(), fixture.machine, fixture.desktop, fixture.data)
	if store != nil {
		// This fixture substitutes the reserved invalid value for one retained
		// Toolhelp close operation. The actual original handle stays owned by
		// the fixture, so no recycled handle can be closed accidentally. Every
		// other actual file/process handle must still join on Close.
		t.Cleanup(func() { _ = store.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	owner, observation := journalNativeRecoveryBegin(t, store, 0)
	native := owner.backend.(*journalRecoveryNative)
	var retainedSnapshot syscall.Handle
	t.Cleanup(func() {
		if retainedSnapshot != 0 {
			if err := syscall.CloseHandle(retainedSnapshot); err != nil {
				t.Error("fixture failed to join its separately retained native snapshot", err)
			}
		}
	})
	observation.after = func() error {
		if native.snapshot == nil || native.snapshot.handle == 0 {
			return errors.New("fixture lost its actual retained process snapshot")
		}
		retainedSnapshot, native.snapshot.handle = native.snapshot.handle, syscall.InvalidHandle
		return nil
	}
	partial, err := owner.Run(context.Background())
	if err == nil || partial.Selection.Record.Sequence == 0 || native.closeErr == nil || store.recovery != owner {
		t.Fatal("native retained-handle close failure admitted controller recovery")
	}
	for range 2 {
		result, err := owner.Run(context.Background())
		if err == nil || result.Selection.SHA256 != partial.Selection.SHA256 || store.recovery != owner {
			t.Fatal("sticky native close ambiguity became an eventual recovery success")
		}
	}
	if err := store.Close(); err == nil || store.lock.handle != 0 || store.slots[0].handle != 0 || store.slots[1].handle != 0 {
		t.Fatal("ambiguous recovery close lost its sticky result or failed to join remaining native files")
	}
}
